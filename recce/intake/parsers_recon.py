"""IP2: recon/AD-adjacent importers.

* kerbrute        — userenum text output (kerbrute userenum -d DOMAIN ...)
* impacket-adusers — GetADUsers.py --all text output
* impacket-adcomps — findDelegation / findComputers text
* whatweb         — JSON (`whatweb --log-json=... URL`)
* wafw00f         — text output ("... is behind WAF")

Same defensive contract as parsers_web: raw text in, list[Vuln] out.
Where a tool emits primarily inventory (users, computers, WAF verdict) we
still surface it as info/low findings so the tester sees them in the
Findings tab — they're not vulns but they're actionable context.
"""
from __future__ import annotations

import json
import re

from ..models import Vuln


def _safe_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


# ---- kerbrute userenum -------------------------------------------------------
# Real output line:
#   2024/01/15 10:00:00 >  [+] VALID USERNAME:       svc_sql@CORP.LOCAL
# With --dc-ip we also have header lines like:
#   Domain: CORP.LOCAL

_KB_VALID_RE = re.compile(r"^\s*(?:\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s*)?>\s*"
                          r"\[\+\]\s+VALID\s+USERNAME:\s+(\S+)", re.I | re.M)
_KB_DC_RE = re.compile(r"^\s*(?:Using KDC|Domain):\s+(\S+)", re.I | re.M)
_KB_DCIP_RE = re.compile(r"KDC:\s+(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def parse_kerbrute(text: str) -> list[Vuln]:
    """kerbrute userenum text output. Each VALID USERNAME line is a
    confirmed-valid AD user (pre-auth AS-REQ came back w/o KDC_ERR_C_
    PRINCIPAL_UNKNOWN) — meaningful enumeration finding."""
    users = _KB_VALID_RE.findall(text)
    if not users:
        return []
    dcip_m = _KB_DCIP_RE.search(text)
    dc_ip = dcip_m.group(1) if dcip_m else ""
    # Fall back to the domain name if no KDC IP surfaced — better than nothing;
    # the Findings tab shows it in the host column.
    if not dc_ip:
        dm = _KB_DC_RE.search(text)
        dc_ip = dm.group(1) if dm else "active-directory"
    return [Vuln(
        ip=dc_ip, port=88, protocol="tcp",
        script_id="kerbrute-userenum", state="finding",
        title=f"AD user enumeration via Kerberos pre-auth ({len(users)} valid users)",
        output=", ".join(sorted(set(users))[:50])[:2000],
        severity="medium", source="kerbrute", confidence="confirmed",
        cwes=["CWE-204"])]


# ---- Impacket GetADUsers.py / findComputers ---------------------------------
# GetADUsers --all outputs:
#   Name                  Email                  PasswordLastSet         LastLogon
#   ...                   ...                    2023-01-15 12:00        2024-02-01 09:00

_ADU_LINE_RE = re.compile(r"^([A-Za-z][\w.$-]{1,60})\s+(?:\S+@\S+|-)\s+"
                          r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|<never>)\s+", re.M)


def parse_impacket_adusers(text: str) -> list[Vuln]:
    """impacket-getADUsers text output. Surfaces the count as an info-level
    directory-exposure finding (an anonymous / low-priv operator ran it
    successfully = exposure)."""
    # findall returns tuples because the regex captures the timestamp too —
    # take just the first group (the account name).
    matches = _ADU_LINE_RE.findall(text)
    users = [m[0] if isinstance(m, tuple) else m for m in matches]
    users = [u for u in users if u != "Name"]           # drop header row if it matched
    if not users:
        return []
    return [Vuln(
        ip="active-directory", port=389, protocol="tcp",
        script_id="impacket-adusers", state="finding",
        title=f"AD user directory readable ({len(users)} accounts enumerated)",
        output=", ".join(sorted(set(users))[:60])[:3000],
        severity="info", source="impacket", confidence="confirmed",
        cwes=["CWE-200"])]


# findDelegation lines:
#   AccountName          AccountType  DelegationRightsTo
#   svc_sql              User         cifs/dc01.corp.local

_DEL_RE = re.compile(r"^(\S+)\s+(User|Computer)\s+(\S.+)$", re.M)


def parse_impacket_delegation(text: str) -> list[Vuln]:
    """impacket-findDelegation output. Every account with delegation rights
    is a high-value target — constrained delegation to a DC-service SPN is
    often the shortest path to DA."""
    rows = _DEL_RE.findall(text)
    if not rows or rows == [("AccountName", "AccountType", "DelegationRightsTo")]:
        return []
    # drop the header if present
    rows = [r for r in rows if r[0] != "AccountName"]
    if not rows:
        return []
    return [Vuln(
        ip="active-directory", port=389, protocol="tcp",
        script_id="impacket-findDelegation", state="finding",
        title=f"AD delegation rights configured ({len(rows)} account(s))",
        output="\n".join(f"{a} ({t}) -> {r}" for a, t, r in rows[:20])[:2000],
        severity="high", source="impacket", confidence="confirmed",
        cwes=["CWE-269"])]


# ---- WhatWeb JSON -----------------------------------------------------------
# whatweb --log-json output is a JSON ARRAY (or one array per line).
# Each entry: {"target": "http://x", "plugins": {"Apache":{"version":["2.4.51"]}, ...}}

def _split_host_port(url_or_host: str, default_port: int | None = None):
    m = re.match(r"^(?:https?://)?([^/:\s]+)(?::(\d+))?", url_or_host or "", re.I)
    if not m:
        return "", default_port
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else default_port
    if not port:
        if (url_or_host or "").lower().startswith("https://"):
            port = 443
        elif (url_or_host or "").lower().startswith("http://"):
            port = 80
    return host, port


def parse_whatweb(text: str) -> list[Vuln]:
    """WhatWeb JSON log. One info-level fingerprint finding per host, listing
    the plugins that matched (tech stack surface)."""
    body = text.lstrip()
    entries = []
    if body.startswith("["):
        d = _safe_json(text)
        if isinstance(d, list):
            entries = d
    else:
        # JSONL — one object per line
        for line in body.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = _safe_json(line)
            if isinstance(obj, dict):
                entries.append(obj)
    out: list[Vuln] = []
    for e in entries:
        target = e.get("target") or ""
        ip, port = _split_host_port(target, 80)
        if not ip:
            continue
        plugins = e.get("plugins") or {}
        tech = []
        for name, meta in plugins.items():
            if not isinstance(meta, dict):
                tech.append(name)
                continue
            ver = meta.get("version") or meta.get("string") or []
            if isinstance(ver, list) and ver:
                tech.append(f"{name} {ver[0]}")
            else:
                tech.append(name)
        if not tech:
            continue
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id="whatweb-fingerprint", state="finding",
            title=f"Web tech fingerprint ({len(tech)} technologies)",
            output=", ".join(sorted(tech))[:3000],
            severity="info", source="whatweb", confidence="confirmed"))
    return out


# ---- wafw00f -----------------------------------------------------------------
# Text output like:
#   [+] The site https://x.com is behind Cloudflare (Cloudflare Inc.) WAF.
#   [-] No WAF detected by the generic detection

_WAF_HIT_RE = re.compile(r"The site\s+(\S+)\s+is behind\s+(.+?)\s+WAF", re.I)
_WAF_NONE_RE = re.compile(r"No WAF detected", re.I)


def parse_wafw00f(text: str) -> list[Vuln]:
    """wafw00f text output. Both "WAF detected" and "no WAF" are actionable
    context: the presence tells the tester what payloads to avoid; absence
    means the app is unprotected against generic attack patterns."""
    hits = _WAF_HIT_RE.findall(text)
    out: list[Vuln] = []
    for target, waf in hits:
        ip, port = _split_host_port(target, 443)
        if not ip:
            continue
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id="wafw00f-detected", state="finding",
            title=f"WAF detected: {waf.strip()}",
            output=f"target={target}\nwaf={waf.strip()}",
            severity="info", source="wafw00f", confidence="confirmed"))
    if not hits and _WAF_NONE_RE.search(text):
        # Pull the URL from the "Checking ..." line if present, else skip
        m = re.search(r"Checking\s+(\S+)", text)
        if m:
            ip, port = _split_host_port(m.group(1), 443)
            if ip:
                out.append(Vuln(
                    ip=ip, port=port, protocol="tcp",
                    script_id="wafw00f-none", state="finding",
                    title="No WAF detected — direct payload delivery possible",
                    severity="low", source="wafw00f", confidence="confirmed"))
    return out


PARSERS = {
    "kerbrute": parse_kerbrute,
    "impacket-adusers": parse_impacket_adusers,
    "impacket-delegation": parse_impacket_delegation,
    "whatweb": parse_whatweb,
    "wafw00f": parse_wafw00f,
}
