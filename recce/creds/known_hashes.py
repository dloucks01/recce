"""Cross-service "hashes known to this engagement" reader.

Every enumeration path that produces a crackable secret — SAM/NTDS dump,
kerberoast, AS-REP roast, MSSQL logins, MySQL user table, MongoDB SCRAM,
IPMI RAKP, VNC challenge/response — lands the raw hash in one of two
places today:

  * `Credential(kind="nthash", secret=…)` in the cred store — for NTLM/NT
    hashes that spray-with-`-H` (PtH) can already consume.
  * `loot/<category>.hash` on disk — for everything else, formatted for
    hashcat: Kerberos blobs, MSSQL 1731, MongoDB SCRAM 24100, IPMI 7300,
    VNC 11600. Written by `hashloot.write_hashcat_file()`.

Consumers today reach into whichever half they care about ad-hoc. This
module unions them: `known_hashes(creds, loot_dir)` returns the full
inventory of what recce is holding for cracking, indexed both by user
(for "does recce hold any hash for alice?") and by hash (for potfile
matching — same shape the old private `_known_hashes` had).

The immediate consumer is the CLI `creds --plan` / `--run` summary: it
now prints "12 hash(es) captured across 8 user(s): nthash×5, krb5tgs×3,
mssql×2, ipmi×2 — run `recce creds --potfile <pot>` after cracking".
The by-user view is also what a future SMB PtH targeter would consume
("for every user with an NT hash, spray it via `-H`") — that path is
already implicit in `nthashes.txt` today, but the reader is the surface
future capabilities read from.
"""
from __future__ import annotations

import os
import re

from ..core.models import Credential


# Kerberos blob prefixes carry the user + realm inline, so we can bucket
# them from loot files without parsing every hashcat category.
_KRB_TGS = re.compile(r"^\$krb5tgs\$(\d+)\$\*([^$]+)\$([^$]+)\$")
_KRB_ASREP = re.compile(r"^\$krb5asrep\$(?:(\d+)\$)?([^@$\s]+)@(\S+?)[:$]")


# category -> (filename, hashcat mode). Mirrors hashloot.CATEGORIES but
# without the description column (this module never writes, only reads).
_LOOT_FILES: dict[str, tuple[str, int]] = {
    "kerberoast":     ("kerberoast.hash", 13100),
    "asrep":          ("asrep.hash",      18200),
    "mssql":          ("mssql.hash",       1731),
    "mysql":          ("mysql.hash",        300),
    "mongo-scram":    ("mongo-scram.hash",24100),
    "mongo-scram256": ("mongo-scram256.hash", 24200),
    "ipmi":           ("ipmi.hash",        7300),
    "ipmi-sha256":    ("ipmi-sha256.hash", 7302),
    "vnc":            ("vnc.hash",        11600),
}


def _user_from_loot_line(category: str, line: str) -> tuple[str, str]:
    """(username, domain) parsed out of a loot line, or ("", "") if the
    format doesn't self-identify. Non-identifying formats (MSSQL,
    MongoDB SCRAM, IPMI, VNC) still get counted in totals but their
    per-user attribution comes from the finding that generated them
    (out of scope for the pure-file reader)."""
    if category == "kerberoast":
        m = _KRB_TGS.match(line)
        if m:
            return m.group(2), m.group(3)
    elif category == "asrep":
        m = _KRB_ASREP.match(line)
        if m:
            return m.group(2), m.group(3)
    return "", ""


def _read_loot(loot_dir: str) -> dict[str, list[str]]:
    """Return {category: [line, ...]} for every category file present."""
    if not loot_dir or not os.path.isdir(loot_dir):
        return {}
    out: dict[str, list[str]] = {}
    for category, (fname, _mode) in _LOOT_FILES.items():
        path = os.path.join(loot_dir, fname)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
        except OSError:
            continue
        if lines:
            out[category] = lines
    return out


def known_hashes(creds: list[Credential], loot_dir: str = "") -> dict:
    """Inventory every hash recce is holding for cracking.

    Returns:
      {"by_user":   {name_lower: [{"kind", "value", "source", "hashcat_mode"}]},
       "by_hash":   {hash_lower_or_full: (user, domain)},
       "by_mode":   {int: count},        # -m N -> total lines
       "categories":{category: count},   # loot-file category -> lines
       "total":     int}                 # sum across creds + loot files

    `by_hash` is the same shape the (private) _known_hashes reader in
    credentials.py builds today — refactor callers to use this one.
    """
    by_user: dict[str, list[dict]] = {}
    by_hash: dict[str, tuple[str, str]] = {}
    by_mode: dict[int, int] = {}
    categories: dict[str, int] = {}

    def _add_user(name: str, entry: dict) -> None:
        if not name:
            return
        by_user.setdefault(name.lower(), []).append(entry)

    # (1) NT hashes from the credential store — mode 1000 (NTLM) or 5500
    #     (NetNTLMv1) / 5600 (NetNTLMv2). The kind attr distinguishes.
    for c in creds:
        if c.kind == "nthash" and c.secret:
            h = c.secret.strip()
            by_hash[h.lower()] = (c.username, c.domain)
            mode = 1000  # NTLM; SAM/NTDS dumps are always this mode
            by_mode[mode] = by_mode.get(mode, 0) + 1
            _add_user(c.username, {"kind": "nthash", "value": h,
                                   "source": c.source or "cred_store",
                                   "hashcat_mode": mode,
                                   "domain": c.domain or ""})

    # (2) Loot files on disk.
    loot = _read_loot(loot_dir)
    for category, lines in loot.items():
        _fname, mode = _LOOT_FILES[category]
        categories[category] = len(lines)
        by_mode[mode] = by_mode.get(mode, 0) + len(lines)
        for line in lines:
            user, domain = _user_from_loot_line(category, line)
            # Kerberos blobs keep case; hex digests get lowercased for match
            key = line if line.startswith("$") else line.lower()
            if user:
                by_hash[key] = (user, domain)
            _add_user(user, {"kind": category, "value": line,
                             "source": f"loot/{_LOOT_FILES[category][0]}",
                             "hashcat_mode": mode, "domain": domain})

    total = sum(by_mode.values())
    return {"by_user": by_user, "by_hash": by_hash,
            "by_mode": by_mode, "categories": categories, "total": total}


# --- hashcat potfile auto-discovery -----------------------------------------

# Hashcat's default per-user potfile locations, in the order it itself
# checks them (documented in the hashcat FAQ). We scan every one that
# exists so a cracked hash from any past hashcat run auto-feeds back
# into the next spray, without the operator having to remember
# `--potfile /path`.
_HASHCAT_DEFAULT_POTFILES = (
    "~/.hashcat/hashcat.potfile",
    "~/.local/share/hashcat/hashcat.potfile",
    "~/hashcat.potfile",
)


def default_potfile_paths(out_dir: str = "") -> list[str]:
    """Every potfile path recce will opportunistically read at spray time.

    Order: hashcat's own defaults, then anything named `*.pot` or
    `cracked.txt` inside the engagement out_dir (a common convention when
    operators keep per-engagement pot files alongside recce output).
    """
    paths: list[str] = []
    for p in _HASHCAT_DEFAULT_POTFILES:
        real = os.path.expanduser(p)
        if os.path.isfile(real):
            paths.append(real)
    if out_dir and os.path.isdir(out_dir):
        for name in sorted(os.listdir(out_dir)):
            if name.endswith(".pot") or name == "cracked.txt":
                paths.append(os.path.join(out_dir, name))
    # De-dupe while preserving order.
    seen: set[str] = set()
    uniq: list[str] = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq
