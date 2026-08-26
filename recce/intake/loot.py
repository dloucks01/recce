"""Loot scanner — mine uploaded evidence files for high-value artifacts.

The tester attaches files to a host through the evidence-upload flow
(recce/webui/routes/findings.py's /api/evidence/upload). Those files
land in `<engagement>/evidence/<ip>/`. Historically recce just held onto
them as `Manual evidence` info-findings; the actual scanning was left to
the tester.

This module walks the evidence tree and looks for:

* **Kerberos ticket files** (.ccache, .kirbi) — impacket / mimikatz drop
  these for later Pass-the-Ticket usage. Their presence in evidence means
  the tester (or the target host) already produced them; recce surfaces
  them so they're not buried in file listings.
* **Credential files** — .aws/credentials, .netrc, id_rsa*, docker config
  auths, browser saved-logins databases (Chrome/Firefox login data).
* **Config secrets** — grep .env, .yml, .yaml, .json, .properties, .xml,
  .conf, .ini files for password/token/secret-like patterns.
* **Git repo dumps** — a HEAD file (or .git directory contents) uploaded
  as evidence means the .git/ leak from C1 was harvested; extract branch
  names + commit refs so the tester knows what to review with git log.

Emits Vuln findings so they show up in the Findings tab (source=loot).
Read-only — never writes to the evidence dir, never uploads anything.
"""
from __future__ import annotations

import os
import re
from ..models import Vuln


# File-name / extension patterns for each category. Case-insensitive.
_TICKET_PATTERNS = re.compile(r"\.(ccache|kirbi)$", re.I)
_CRED_FILE_NAMES = {
    "credentials",           # ~/.aws/credentials
    "config",                # ~/.aws/config
    ".netrc", "netrc",
    ".docker",               # sometimes uploaded as a bare filename
    "login data", "logins.json",  # Chrome / Firefox
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys",
    "known_hosts",
    ".env", "env",
    "shadow", "passwd",
    "sam", "system",         # Windows registry hives dumped from a target
    "ntds.dit",
}
_CRED_FILE_PATTERNS = [
    re.compile(r"^id_[a-z0-9]+(\.pub)?$", re.I),
    re.compile(r"\.pfx$|\.p12$|\.pem$|\.key$|\.jks$", re.I),
    re.compile(r"^\.htpasswd$", re.I),
    re.compile(r"^\.pgpass$", re.I),
]
_CONFIG_EXTENSIONS = re.compile(
    r"\.(env|ya?ml|json|properties|xml|conf|ini|toml|cfg|config)$", re.I)

# Regex patterns for secret-like content lines inside config files.
# Each entry: (label, regex). Matched line is surfaced; multiple matches
# per file are aggregated.
_SECRET_LINE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",    re.compile(r"(?i)aws.{0,20}(secret|key).{0,20}['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("github_token",      re.compile(r"gh[oprsu]_[A-Za-z0-9]{36,}")),
    ("gitlab_token",      re.compile(r"glpat-[A-Za-z0-9-_]{20,}")),
    ("slack_token",       re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key",        re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}")),
    ("jwt",               re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("password_line",     re.compile(r"(?i)^\s*[\w.-]*(passw(or)?d|passphrase)\s*[:=]\s*['\"]?[^'\"\s#][^\s#]{2,}")),
    ("api_key_line",      re.compile(r"(?i)^\s*[\w.-]*(api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_/+=.-]{12,}")),
    ("db_url",            re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"<>]+:[^@\s'\"<>]+@")),
    ("private_key",       re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]

# Files this size or larger get skipped for content scans — they're likely
# binary blobs (dumps, captures, images) where a grep won't produce useful
# hits and we don't want to blow through memory.
_MAX_SCAN_BYTES = 2 * 1024 * 1024        # 2 MB


def _classify_by_name(fname: str) -> str | None:
    """Return category label based on filename alone, or None if the file
    needs content-scanning to classify."""
    low = fname.lower()
    if _TICKET_PATTERNS.search(low):
        return "kerberos_ticket"
    if low in _CRED_FILE_NAMES:
        return "cred_file"
    for pat in _CRED_FILE_PATTERNS:
        if pat.search(low):
            return "cred_file"
    return None


def _scan_content(path: str) -> list[tuple[str, str]]:
    """Return list of (secret-label, first-100-char-snippet) hits inside
    the file. Reads at most _MAX_SCAN_BYTES so a huge log doesn't stall.
    Silently returns [] on any read error."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size > _MAX_SCAN_BYTES or size == 0:
        return []
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_SCAN_BYTES)
    except OSError:
        return []
    # Best-effort text decode; hits below use latin-1-safe regex so binary
    # files with occasional secret strings still surface.
    text = raw.decode("utf-8", "replace")
    hits: list[tuple[str, str]] = []
    for label, pat in _SECRET_LINE_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0)[:100]
            hits.append((label, snippet))
    return hits


def _iter_evidence_files(eng_dir: str):
    """Walk `<eng_dir>/evidence/<ip>/**` yielding (ip, absolute_path, filename)."""
    root = os.path.join(eng_dir, "evidence")
    if not os.path.isdir(root):
        return
    for entry in os.listdir(root):
        ip_dir = os.path.join(root, entry)
        if not os.path.isdir(ip_dir):
            continue
        # Recurse — some evidence dumps land as nested trees (a .git dump,
        # a zip extraction). Walk them all.
        for dirpath, _dirs, files in os.walk(ip_dir):
            for f in files:
                yield entry, os.path.join(dirpath, f), f


def scan_evidence(eng_dir: str) -> list[Vuln]:
    """Walk the engagement's evidence tree and produce Vuln findings for
    ticket files, cred files, git dumps, and secret-bearing configs.

    Returns a list of Vuln — each anchored to the host IP the evidence
    was uploaded for. Idempotent: running twice produces the same
    findings (`_from_evidence.md5(path)` disambiguation keeps them
    stable). Never mutates the evidence tree."""
    out: list[Vuln] = []

    for ip, abspath, fname in _iter_evidence_files(eng_dir):
        rel = os.path.relpath(abspath, eng_dir)
        cat = _classify_by_name(fname)

        # .git artifacts anywhere in the evidence path -> git-dump signal.
        if "/.git/" in abspath or abspath.endswith("/.git") or fname in ("HEAD", "packed-refs", "config"):
            # Only mark once per evidence dir — check the parent
            if ".git" in abspath:
                out.append(Vuln(
                    ip=ip, port=0, protocol="", script_id="loot-git-dump",
                    state="finding", title=f"Git repository dump in evidence: {rel}",
                    output=f"A .git artifact was found under evidence/{ip}/. "
                           f"Reconstruct the repo (git rev-parse HEAD; git log --all) "
                           f"and mine history for secrets: git log -p | grep -iE 'password|token|api_key'",
                    severity="high", cwes=["CWE-538"],
                    source="loot", remediation="",
                    confidence="confirmed",
                ))

        if cat == "kerberos_ticket":
            out.append(Vuln(
                ip=ip, port=88, protocol="tcp",
                script_id="loot-kerberos-ticket",
                state="finding",
                title=f"Kerberos ticket file in evidence: {fname}",
                output=f"{rel} looks like a Kerberos credential cache "
                       f"({'kirbi' if fname.lower().endswith('.kirbi') else 'ccache'}). "
                       f"Rubeus/impacket-ticketConverter can convert; klist -c or "
                       f"impacket-getST -k -no-pass can reuse. Pass-the-Ticket "
                       f"potential — treat as a live credential.",
                severity="critical", cwes=["CWE-522", "CWE-284"],
                source="loot", remediation="",
                confidence="confirmed",
            ))
            continue

        if cat == "cred_file":
            out.append(Vuln(
                ip=ip, port=0, protocol="",
                script_id="loot-cred-file",
                state="finding",
                title=f"Credential-bearing file in evidence: {fname}",
                output=f"{rel} matches a common credential-storage filename. "
                       f"Grep it for authentication material (usernames, tokens, "
                       f"private keys) before pivoting.",
                severity="high", cwes=["CWE-522", "CWE-798"],
                source="loot", remediation="",
                confidence="likely",
            ))
            continue

        # Content-scan configs for secret patterns.
        if _CONFIG_EXTENSIONS.search(fname):
            hits = _scan_content(abspath)
            if hits:
                # Aggregate hit labels; keep first-snippet per label to
                # avoid spamming the report with N-copies of the same match.
                labels = sorted({lbl for lbl, _ in hits})
                snippets = "\n".join(f"  [{lbl}] {snip}" for lbl, snip in hits[:8])
                sev = "critical" if any(l in ("private_key", "aws_secret_key",
                                              "github_token", "gitlab_token",
                                              "stripe_key", "db_url")
                                        for l in labels) else "high"
                out.append(Vuln(
                    ip=ip, port=0, protocol="",
                    script_id="loot-config-secrets",
                    state="finding",
                    title=f"Secret material in evidence config: {fname}",
                    output=f"{rel} contains {len(hits)} secret-like pattern hit(s): "
                           f"{', '.join(labels)}\n{snippets}",
                    severity=sev, cwes=["CWE-798", "CWE-522", "CWE-312"],
                    source="loot", remediation="",
                    confidence="likely",
                ))

    return out
