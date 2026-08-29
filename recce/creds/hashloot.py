"""Write captured password hashes to `loot/<category>.hash` in the exact format
hashcat consumes.

recce's DB modules already extract hashes and put the hashcat mode number in
the finding text ("hashcat -m 1731 mssql_hashes.txt wordlist.txt"). What was
missing was the FILE hashcat wants next to that command — the operator ended
up grepping the report to reconstruct it by hand, and then any cracks landed
in a potfile with no way back into recce (which is why the `--potfile`
importer was added first). Writing the file here closes the collection half of
the same loop.

Each category maps to one hashcat mode + one filename. Categories are stable
strings so `recce creds --potfile` can look them up after the operator runs
hashcat.

Design:
  * append-only, deduped by full-line, so re-running a scan does not shrink or
    duplicate the file — the tester can crack incrementally over several days.
  * 0o600 on write, because the file carries crackable secrets.
  * every write returns the number of NEW lines so the caller can print
    "captured N new hash(es) → loot/mssql.hash".
"""
from __future__ import annotations

import os

from ..core.models import Credential


# category -> (filename, hashcat mode, one-line description). Kept flat rather
# than a dict-of-dicts because the per-DB analyzers add exactly one line each,
# and a table beats an ad-hoc constant per module.
CATEGORIES: dict[str, tuple[str, int, str]] = {
    "mssql":       ("mssql.hash",       1731,  "MSSQL 2012+ (sys.sql_logins password_hash)"),
    "mysql":       ("mysql.hash",       300,   "MySQL 4.1+ (mysql.user Password)"),
    "mongo-scram": ("mongo-scram.hash", 24100, "MongoDB SCRAM-SHA-1 (usersInfo showCredentials)"),
    "mongo-scram256": ("mongo-scram256.hash", 24200, "MongoDB SCRAM-SHA-256"),
    "ipmi":        ("ipmi.hash",        7300,  "IPMI 2.0 RAKP HMAC-SHA1"),
    "ipmi-sha256": ("ipmi-sha256.hash", 7302,  "IPMI 2.0 RAKP HMAC-SHA256"),
    "vnc":         ("vnc.hash",         11600, "VNC challenge/response (8-byte DES)"),
    # Kerberos hashes are already written by cli/_service_helpers.py; listed
    # here so `recce creds --potfile` recognises them as loot too.
    "kerberoast":  ("kerberoast.hash",  13100, "Kerberos TGS-REP (kerberoast)"),
    "asrep":       ("asrep.hash",       18200, "Kerberos AS-REP (AS-REP roast)"),
}


def _category_path(out_dir: str, category: str) -> str:
    if category not in CATEGORIES:
        raise ValueError(f"unknown hashloot category {category!r}; "
                         f"expected one of {sorted(CATEGORIES)}")
    return os.path.join(out_dir, CATEGORIES[category][0])


def write_hashcat_file(out_dir: str, category: str, hashes: list[str]) -> int:
    """Append `hashes` to loot/<category>.hash, deduping against what is already
    on disk. Returns the number of NEW lines written.

    A hash we already recorded is not re-written, which matters when the same
    scan is re-run mid-engagement — the file grows, never shrinks or dupes.
    """
    if not hashes:
        return 0
    os.makedirs(out_dir, exist_ok=True)
    path = _category_path(out_dir, category)
    existing: set[str] = set()
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                existing = {ln.strip() for ln in fh if ln.strip()}
        except OSError:
            existing = set()
    fresh = [h for h in (str(x).strip() for x in hashes) if h and h not in existing]
    if not fresh:
        return 0
    # Open new / append and immediately chmod 0o600. The file carries crackable
    # secrets and _relax_perms only sweeps the tree at CLI exit; a scan started
    # from `recce serve` skips that path entirely (SIGTERM does not fire the
    # finally-block), so set the mode directly here.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, ("\n".join(fresh) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return len(fresh)


def collect_from_db_probe(probe: dict, service: str) -> list[tuple[str, str]]:
    """Turn a DB module's probe dict into [(category, hash_line), ...].

    Each DB stores hashes differently:
      * mssql: probe["hashes"] = list of ("user|0xDEADBEEF...",) tuples from the
        SELECT sys.sql_logins query — the second half after the '|' is the
        hex hash hashcat wants for -m 1731.
      * mysql: probe["hashes"] = [{"user", "host", "hash", "plugin"}] — hashcat
        wants "user:*HASH" for mode 300.
      * mongodb: probe["hashes"] = [{"user", "mechanism", "hashcat"}] — the
        "hashcat" field is already the finished line; mode 24100 or 24200
        depending on mechanism.

    Returns pairs so the caller can group by category and call
    write_hashcat_file once per category — a single scan can populate more
    than one file (mongo SCRAM-SHA-1 + SCRAM-SHA-256, etc.).
    """
    out: list[tuple[str, str]] = []
    hashes = probe.get("hashes") if isinstance(probe, dict) else None
    if not hashes:
        return out

    if service == "mssql":
        for h in hashes:
            # Two shapes: (str,) tuple from the fetchone loop, or bare string.
            line = h[0] if isinstance(h, (tuple, list)) and h else h
            if not isinstance(line, str) or "|" not in line:
                continue
            # mode 1731 expects the hex blob (0x0200...) alone or with user, but
            # the "user|hex" line is a stable form recce writes for the tester.
            out.append(("mssql", line.strip()))

    elif service == "mysql":
        for h in hashes:
            if not isinstance(h, dict):
                continue
            user, digest = h.get("user"), h.get("hash")
            if not (user and digest):
                continue
            # mode 300 wants the *HASH string (already 40-hex prefixed with *).
            digest = digest if digest.startswith("*") else f"*{digest}"
            out.append(("mysql", f"{user}:{digest}"))

    elif service == "mongodb":
        for h in hashes:
            if not isinstance(h, dict) or not h.get("hashcat"):
                continue
            mech = (h.get("mechanism") or "").upper()
            cat = "mongo-scram256" if "SHA-256" in mech or "SHA256" in mech else "mongo-scram"
            out.append((cat, h["hashcat"]))

    return out


def collect_from_probe(probe: dict, service: str) -> list[tuple[str, str]]:
    """Category + line collector for every service that produces a hash.

    Superset of collect_from_db_probe — includes IPMI (probe["rakp"] populated
    by services/ipmi.rakp_hash) alongside the DB engines. Extending in-place
    kept the existing DB call sites unchanged; this is the unified entry point
    for anything new.
    """
    if service == "ipmi":
        out: list[tuple[str, str]] = []
        # Multi-user + multi-alg sweep produces a list of {category, line}.
        sweep = probe.get("rakp_sweep") if isinstance(probe, dict) else None
        if isinstance(sweep, dict):
            for h in sweep.get("hashes") or []:
                cat = h.get("category")
                line = h.get("hashcat_line")
                if cat and line:
                    out.append((cat, line))
        # Legacy single-hash shape from the earlier iteration — kept so a
        # future caller passing the old-format probe still gets the loot line.
        legacy = probe.get("rakp") if isinstance(probe, dict) else None
        if isinstance(legacy, dict) and legacy.get("hashcat_line") and not out:
            out.append(("ipmi", legacy["hashcat_line"]))
        return out
    return collect_from_db_probe(probe, service)


def creds_to_hashcat_lines(creds: list[Credential]) -> list[str]:
    """NT hashes from the credential store, formatted as `user:hash` for mode
    1000. Complements the existing `nthashes.txt` (bare hash lines) with a
    labeled form so the potfile matcher after cracking can attribute the crack.
    """
    return [f"{c.username}:{c.secret}"
            for c in creds
            if c.kind == "nthash" and c.username and c.secret]
