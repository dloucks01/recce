"""Universal loose parser — the LAST-RESORT fallback for any text that no
specific detector claimed.

Fights tool drift by extracting anything that *looks like* a finding from
arbitrary text — CVE refs, IP:port pairs, severity markers, credential rows,
hash formats — and folding each as a **low-confidence lead** (tier so the
Findings tab marks them for triage). It's deliberately over-eager: better
to surface noise the tester filters than silently drop a file the tester
just spent time producing.

Never runs when a specific parser matched — only when detect_scanner()
returned '' AND filename hints turned up nothing.

Every finding it emits carries:
  * source="generic-import"     — visible in the Findings tab source column
  * confidence="potential"      — QoD → tier "lead" → hidden behind the
                                  "Leads" toggle by default
  * script_id="generic-<kind>"  — grouped in the Findings dedupe by kind
"""
from __future__ import annotations

import re
from collections import defaultdict

from ..models import Vuln


# Well-known patterns. Ordered by specificity — more specific first so an
# IP:port line doesn't get double-counted as a bare IP.

_CVE_RE = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.I)

_IP_PORT_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b")

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.I)

# User:pass patterns — deliberately strict so we don't grab URLs / CIDRs / etc.
_USERPASS_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9._@-]{1,60})[:\t|]([^\s:]{4,120})\s*$", re.M)

# secretsdump format: user:rid:lmhash:nthash:::  (already covered by
# the specific `secretsdump` parser; we skip lines that match it here)
_SECDUMP_RE = re.compile(r"^[^:\s]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::", re.I | re.M)

# Severity markers a lot of tools emit inline.
_SEV_MARKERS = [
    (re.compile(r"\bCRITICAL\b|\[CRIT\]|CRITICAL VULNERABILITY", re.I), "critical"),
    (re.compile(r"\bHIGH RISK\b|\[HIGH\]|\bHIGH SEVERITY\b", re.I), "high"),
    (re.compile(r"\bMEDIUM RISK\b|\[MED(?:IUM)?\]|\bMEDIUM SEVERITY\b", re.I), "medium"),
    (re.compile(r"\bLOW RISK\b|\[LOW\]|\bLOW SEVERITY\b", re.I), "low"),
    (re.compile(r"\[\+\]|VULNERABLE|EXPLOITABLE", re.I), "medium"),
]

# NT hash (32 hex) — user:hash style
_NT_LINE_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9._@-]{1,60})[:\t\|]([0-9a-f]{32})\s*$", re.M)


def _looks_like_ip(ip: str) -> bool:
    """Quick sanity check — no octet > 255, no leading zeros beyond a single 0."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
        if len(p) > 1 and p.startswith("0"):
            return False
    return True


def _sniff_severity(context: str) -> str:
    """The most severe marker present in the surrounding line wins."""
    for rx, sev in _SEV_MARKERS:
        if rx.search(context):
            return sev
    return "info"


def _line_context(text: str, pos: int, span: int = 200) -> str:
    """Return the text within ±span chars of pos (single line preferred)."""
    start = max(0, pos - span)
    end = min(len(text), pos + span)
    chunk = text[start:end]
    # Prefer the line containing pos
    line_start = chunk.rfind("\n", 0, pos - start) + 1
    line_end = chunk.find("\n", pos - start)
    if line_end == -1:
        line_end = len(chunk)
    return chunk[line_start:line_end]


def parse_generic(text: str) -> list[Vuln]:
    """Best-effort extraction of findings from arbitrary text. Returns
    findings tagged low-confidence so they land in the Leads bucket."""
    if not text or not text.strip():
        return []

    # Guard: skip lines that a specific credential parser will already claim.
    # (secretsdump uses `_SECDUMP_RE` — those lines get handled by
    # parse_secretsdump; we don't want to double-emit them here.)
    secdump_positions = {m.start() for m in _SECDUMP_RE.finditer(text)}

    out: list[Vuln] = []

    # 1) CVE mentions — one lead finding per unique CVE. Attach the nearest
    # IP:port to the finding when the CVE appears on the same line.
    cve_hits: dict[str, tuple[str, int | None, str]] = {}
    for m in _CVE_RE.finditer(text):
        cve = m.group(0).upper()
        if cve in cve_hits:
            continue
        ctx = _line_context(text, m.start())
        ip, port = "", None
        ipm = _IP_PORT_RE.search(ctx)
        if ipm and _looks_like_ip(ipm.group(1)):
            ip = ipm.group(1)
            port = int(ipm.group(2)) if ipm.group(2) else None
        cve_hits[cve] = (ip, port, ctx.strip())
    for cve, (ip, port, ctx) in cve_hits.items():
        out.append(Vuln(
            ip=ip or "generic-import",
            port=port, protocol="tcp",
            script_id=f"generic-cve-{cve.lower()}",
            state="finding",
            title=f"Referenced CVE — {cve}",
            output=ctx[:400], severity=_sniff_severity(ctx),
            ids=[cve], source="generic-import", confidence="potential"))

    # 2) Severity-marked lines with no CVE — surface one finding per unique
    # (severity, first-80-chars-of-line) so a "[CRIT] Buffer overflow at X"
    # gets captured even without a CVE ref. Skip lines already claimed by a
    # CVE finding (avoid duplication).
    used_line_hashes = set()
    for cve, (_ip, _port, ctx) in cve_hits.items():
        used_line_hashes.add(hash(ctx))
    for rx, sev in _SEV_MARKERS[:4]:              # skip the generic [+] marker — too noisy
        for m in rx.finditer(text):
            ctx = _line_context(text, m.start()).strip()
            if hash(ctx) in used_line_hashes or not ctx:
                continue
            used_line_hashes.add(hash(ctx))
            ip, port = "", None
            ipm = _IP_PORT_RE.search(ctx)
            if ipm and _looks_like_ip(ipm.group(1)):
                ip = ipm.group(1)
                port = int(ipm.group(2)) if ipm.group(2) else None
            # Take the finding title from the line, stripping the marker text
            title = rx.sub("", ctx).strip(" -:[]") or ctx[:80]
            out.append(Vuln(
                ip=ip or "generic-import",
                port=port, protocol="tcp",
                script_id=f"generic-marker-{sev}",
                state="finding", title=title[:120],
                output=ctx[:400], severity=sev,
                source="generic-import", confidence="potential"))

    # 3) Credential-shaped rows (user:password, user|password). Filter out
    # secretsdump rows (their own parser handles them), URLs, comments.
    for m in _USERPASS_RE.finditer(text):
        if m.start() in secdump_positions:
            continue
        line = text[m.start():m.end()]
        # Skip URLs (host:port confusable), comments, IPs, kv-config
        if "://" in line or line.strip().startswith("#") or line.strip().startswith("//"):
            continue
        user, secret = m.group(1), m.group(2)
        # Don't emit findings for obviously non-cred rows like `date: 2024`
        if user.lower() in ("date", "time", "url", "user-agent", "host", "port",
                            "server", "protocol", "target", "connection"):
            continue
        if _looks_like_ip(user):    # `10.0.0.1:8080` looks like ip:port not cred
            continue
        # A 32-hex "secret" is an NT hash, not a password — the NT hash
        # loop below handles that shape. Skip so we don't emit both a
        # "credential candidate" and an "NT hash candidate" for one line.
        if re.fullmatch(r"[0-9a-f]{32}", secret, re.I):
            continue
        out.append(Vuln(
            ip="generic-import", port=None, protocol="tcp",
            script_id=f"generic-cred-{user[:20]}",
            state="finding",
            title=f"Credential candidate: {user} (unverified)",
            output=f"user={user}\nsecret preview: {secret[:6]}…",
            severity="info", source="generic-import", confidence="potential"))

    # 4) Bare NT hashes (user:32hex) — skip if secretsdump-shaped
    for m in _NT_LINE_RE.finditer(text):
        if m.start() in secdump_positions:
            continue
        user, nthash = m.group(1), m.group(2)
        out.append(Vuln(
            ip="generic-import", port=None, protocol="tcp",
            script_id=f"generic-nthash-{user[:20]}",
            state="finding",
            title=f"NT hash candidate: {user}",
            output=f"NT: {nthash}",
            severity="medium", source="generic-import", confidence="potential"))

    return out


def _dedupe_by_key(findings: list[Vuln]) -> list[Vuln]:
    """Collapse the same (ip, port, script_id, title) so the loose sweep
    doesn't spam the Findings tab if a file mentions the same CVE 20 times."""
    seen = set()
    out = []
    for v in findings:
        key = (v.ip, v.port, v.script_id, v.title)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def parse_generic_deduped(text: str) -> list[Vuln]:
    """Wrapper — parse then dedupe. This is what the registry entry points to."""
    return _dedupe_by_key(parse_generic(text))


PARSERS = {"generic": parse_generic_deduped}
