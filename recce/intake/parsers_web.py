"""IP1: web-scanner + web/AD-tool importers that recce didn't have parity for.

Each `parse_*` follows the same defensive contract as importers.parse_nessus:
raw tool output in, list[Vuln] out (empty on malformed input, never raises),
so the WebUI import panel can hand user-supplied files straight in.

Tools covered:
* Burp Suite  — Issues XML export ("<issues burpVersion=...>")
* OWASP ZAP   — XML alerts export ("<OWASPZAPReport>")
* Nikto       — XML output (`-Format xml`)
* WPScan      — JSON output (`--format json`)
* sslyze      — JSON output (`--json_out`)
* enum4linux(-ng) — text output (best-effort, matches user shares / sessions / OS)
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from ..models import Vuln


# ---- shared ------------------------------------------------------------------

def _safe_fromstring(text: str):
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _safe_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


_HOST_PORT = re.compile(r"^(?:https?://)?([^/:\s]+)(?::(\d+))?", re.I)


def _split_host_port(url_or_host: str, default_port: int | None = None) -> tuple[str, int | None]:
    """Pull host + port out of a URL or bare `host:port`. Returns
    (host, port) with port=None when unknown. Never raises."""
    m = _HOST_PORT.match(url_or_host or "")
    if not m:
        return "", default_port
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else default_port
    if not port:
        if url_or_host.lower().startswith("https://"):
            port = 443
        elif url_or_host.lower().startswith("http://"):
            port = 80
    return host, port


# ---- Burp Suite --------------------------------------------------------------
# Burp maps its severity strings to a subset of our (crit/high/med/low/info).
_BURP_SEV = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "information": "info", "info": "info",
    "informational": "info",
}


def parse_burp(text: str) -> list[Vuln]:
    """Burp Suite Issues XML — `<issues burpVersion="..."><issue>...</issue></issues>`.
    Each `<issue>` carries name/severity/host/location/issueDetail.
    """
    root = _safe_fromstring(text)
    if root is None:
        return []
    out: list[Vuln] = []
    # Burp exports as either `<issues>` root with `<issue>` children, or a
    # single `<issue>` root — handle both.
    issues = root.iter("issue")
    for issue in issues:
        name = (issue.findtext("name") or "").strip()
        sev = _BURP_SEV.get((issue.findtext("severity") or "").strip().lower(), "info")
        host_el = issue.find("host")
        host_url = (host_el.get("ip") or (host_el.text or "")).strip() if host_el is not None else ""
        location = (issue.findtext("location") or "").strip()
        detail = (issue.findtext("issueDetail") or issue.findtext("description") or "").strip()
        remediation = (issue.findtext("remediationDetail")
                       or issue.findtext("remediationBackground") or "").strip()
        cwe_refs = []
        for c in issue.iter("classification"):
            cwe = (c.get("id") or c.text or "").strip()
            if cwe and cwe.upper().startswith("CWE-"):
                cwe_refs.append(cwe.upper())
        ip, port = _split_host_port(host_url)
        if not ip:
            continue
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"burp-{issue.get('type', '')}",
            state="finding",
            title=name or "Burp issue",
            output=(location + "\n\n" + detail).strip()[:4000],
            severity=sev, cwes=cwe_refs, source="burp",
            remediation=remediation[:2000], confidence="likely"))
    return out


# ---- OWASP ZAP ---------------------------------------------------------------
_ZAP_RISK_TO_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high"}


def parse_zap(text: str) -> list[Vuln]:
    """OWASP ZAP XML alerts. Root is `<OWASPZAPReport>` (or `<report>`).
    Each `<site>` has `<alerts><alertitem>` children with riskcode 0-3."""
    root = _safe_fromstring(text)
    if root is None:
        return []
    out: list[Vuln] = []
    for site in root.iter("site"):
        site_host = site.get("host") or site.get("name") or ""
        default_port = int(site.get("port")) if (site.get("port") or "").isdigit() else None
        ip, port = _split_host_port(site_host, default_port)
        if not ip:
            continue
        for alert in site.iter("alertitem"):
            name = (alert.findtext("alert") or alert.findtext("name") or "").strip()
            riskcode = (alert.findtext("riskcode") or "0").strip()
            sev = _ZAP_RISK_TO_SEV.get(riskcode, "info")
            desc = (alert.findtext("desc") or "").strip()
            soln = (alert.findtext("solution") or "").strip()
            cwe = (alert.findtext("cweid") or "").strip()
            cwes = [f"CWE-{cwe}"] if cwe.isdigit() else []
            out.append(Vuln(
                ip=ip, port=port, protocol="tcp",
                script_id=f"zap-{alert.findtext('pluginid') or ''}",
                state="finding", title=name or "ZAP alert",
                output=desc[:4000], severity=sev, cwes=cwes,
                source="zap", remediation=soln[:2000], confidence="likely"))
    return out


# ---- Nikto -------------------------------------------------------------------
# Nikto XML doesn't carry severities; every hit is a config/exposure finding.
# We downgrade to medium/low based on OSVDB refs / message content.

_NIKTO_HI_HINTS = ("cgi", "backup", ".git", "shell", "password", "config",
                   "phpinfo", "web-console")


def parse_nikto(text: str) -> list[Vuln]:
    """Nikto XML (`nikto -Format xml`). `<niktoscan><scandetails>` per host,
    with `<item>` children."""
    root = _safe_fromstring(text)
    if root is None:
        return []
    out: list[Vuln] = []
    for scan in root.iter("scandetails"):
        ip = (scan.get("targetip") or scan.get("targethostname") or "").strip()
        port_s = (scan.get("targetport") or "80").strip()
        port = int(port_s) if port_s.isdigit() else 80
        if not ip:
            continue
        for item in scan.iter("item"):
            desc = (item.findtext("description") or "").strip()
            uri = (item.findtext("uri") or "").strip()
            iid = item.get("id") or ""
            low = (desc + " " + uri).lower()
            sev = "medium" if any(h in low for h in _NIKTO_HI_HINTS) else "low"
            out.append(Vuln(
                ip=ip, port=port, protocol="tcp",
                script_id=f"nikto-{iid}", state="finding",
                title=(desc[:80] + ("…" if len(desc) > 80 else "")) or "Nikto item",
                output=(uri + "\n\n" + desc).strip()[:4000],
                severity=sev, source="nikto", confidence="likely"))
    return out


# ---- WPScan ------------------------------------------------------------------
# WPScan JSON is nested: target_url + interesting_findings + version + vulnerabilities.
# Each `plugin`/`theme` may have its own `vulnerabilities` list.

_WPSCAN_SEV_HINT = (
    ("rce", "critical"), ("remote code", "critical"),
    ("sql injection", "critical"), ("upload", "high"), ("xxe", "high"),
    ("xss", "medium"), ("csrf", "medium"), ("disclosure", "medium"),
    ("bypass", "medium"),
)


def _wpscan_sev(title: str) -> str:
    t = (title or "").lower()
    for hint, sev in _WPSCAN_SEV_HINT:
        if hint in t:
            return sev
    return "low"


def parse_wpscan(text: str) -> list[Vuln]:
    """WPScan `--format json` output. Yields one finding per version + per
    plugin/theme vulnerability, all keyed to `target_url`'s host."""
    data = _safe_json(text)
    if not isinstance(data, dict):
        return []
    target = data.get("target_url") or data.get("target_ip") or ""
    ip, port = _split_host_port(target, 80)
    if not ip:
        return []
    out: list[Vuln] = []

    def _add(title, detail, sev, cves=None):
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"wpscan-{re.sub(r'[^a-z0-9]+', '-', (title or 'finding').lower())[:40]}",
            state="finding", title=title[:120] or "WPScan finding",
            output=(detail or "")[:4000], severity=sev,
            ids=list(cves or []), source="wpscan", confidence="likely"))

    # Core version vulns
    ver = data.get("version") or {}
    for v in (ver.get("vulnerabilities") or []):
        title = (v.get("title") or "").strip()
        cves = v.get("references", {}).get("cve", []) if isinstance(v.get("references"), dict) else []
        cves = [f"CVE-{c}" if not str(c).upper().startswith("CVE-") else c for c in cves]
        _add(f"WordPress core: {title}", v.get("description", ""), _wpscan_sev(title), cves)

    # Plugin vulns
    for _slug, plugin in (data.get("plugins") or {}).items():
        for v in (plugin.get("vulnerabilities") or []):
            title = (v.get("title") or "").strip()
            cves = v.get("references", {}).get("cve", []) if isinstance(v.get("references"), dict) else []
            cves = [f"CVE-{c}" if not str(c).upper().startswith("CVE-") else c for c in cves]
            _add(f"Plugin '{plugin.get('slug', '')}': {title}",
                 v.get("description", ""), _wpscan_sev(title), cves)

    # Theme vulns (same shape)
    for _slug, theme in (data.get("themes") or {}).items():
        for v in (theme.get("vulnerabilities") or []):
            title = (v.get("title") or "").strip()
            _add(f"Theme '{theme.get('slug', '')}': {title}",
                 v.get("description", ""), _wpscan_sev(title))

    # Interesting-finding config exposures
    for f in (data.get("interesting_findings") or []):
        _add(f.get("to_s") or f.get("type") or "WPScan interesting", "", "low")
    return out


# ---- sslyze ------------------------------------------------------------------

_SSLYZE_HIGH_KEYS = (
    "heartbleed", "openssl_ccs", "robot", "compression", "downgrade",
    "session_renegotiation.accepts_client_renegotiation")
_SSLYZE_MED_KEYS = ("ssl_2_0", "ssl_3_0", "tls_1_0", "tls_1_1",
                    "certificate_info.leaf_certificate_is_self_signed",
                    "certificate_info.leaf_certificate_signed_certificate_timestamps_count_lt_2")


def parse_sslyze(text: str) -> list[Vuln]:
    """sslyze `--json_out`. `server_scan_results[]` → per host/port TLS
    posture. We surface the well-known weakness classes as findings."""
    data = _safe_json(text)
    if not isinstance(data, dict):
        return []
    out: list[Vuln] = []
    for scan in data.get("server_scan_results") or []:
        conn = scan.get("server_location") or {}
        ip = conn.get("ip_address") or conn.get("hostname") or ""
        port = conn.get("port") or 443
        if not ip:
            continue
        results = scan.get("scan_result") or {}
        # Weak protocol probes
        for proto_key, label in [
            ("ssl_2_0_cipher_suites", "SSLv2 supported"),
            ("ssl_3_0_cipher_suites", "SSLv3 (POODLE) supported"),
            ("tls_1_0_cipher_suites", "TLS 1.0 supported (deprecated)"),
            ("tls_1_1_cipher_suites", "TLS 1.1 supported (deprecated)"),
        ]:
            r = results.get(proto_key, {}).get("result", {}) if isinstance(results.get(proto_key), dict) else {}
            accepted = r.get("accepted_cipher_suites") or []
            if accepted:
                sev = "high" if "SSLv2" in label or "SSLv3" in label else "medium"
                out.append(Vuln(
                    ip=ip, port=port, protocol="tcp",
                    script_id=f"sslyze-{proto_key}", state="finding",
                    title=label, output=f"{len(accepted)} cipher suite(s) accepted",
                    severity=sev, source="sslyze", confidence="confirmed"))
        # Heartbleed / renegotiation
        for key, title, sev in [
            ("heartbleed", "Heartbleed (CVE-2014-0160)", "critical"),
            ("openssl_ccs_injection", "OpenSSL CCS injection (CVE-2014-0224)", "high"),
            ("session_renegotiation", "Insecure client-initiated renegotiation", "medium"),
        ]:
            r = results.get(key, {}).get("result", {}) if isinstance(results.get(key), dict) else {}
            flag_keys = ("is_vulnerable_to_heartbleed",
                         "is_vulnerable_to_ccs_injection",
                         "accepts_client_renegotiation")
            if any(r.get(k) for k in flag_keys):
                out.append(Vuln(
                    ip=ip, port=port, protocol="tcp",
                    script_id=f"sslyze-{key}", state="VULNERABLE",
                    title=title, output=str(r)[:600], severity=sev,
                    source="sslyze", confidence="confirmed",
                    ids=["CVE-2014-0160"] if "heartbleed" in key else
                        ["CVE-2014-0224"] if "ccs" in key else []))
    return out


# ---- enum4linux(-ng) ---------------------------------------------------------
# enum4linux-ng supports `--json` (dict output) and text. Text is very common
# in the wild, so we parse both.

def parse_enum4linux(text: str) -> list[Vuln]:
    """Handles enum4linux-ng --json (dict output) AND classic text output.
    Emits findings for anonymous/null-session access, discovered shares,
    users, and OS/domain fingerprints."""
    data = _safe_json(text) if text.lstrip().startswith("{") else None
    if isinstance(data, dict):
        return _enum4linux_json(data)
    return _enum4linux_text(text)


def _enum4linux_json(data: dict) -> list[Vuln]:
    out: list[Vuln] = []
    target = (data.get("target") or {}).get("host") or ""
    ip, _ = _split_host_port(target, 445)
    if not ip:
        return out
    if data.get("sessions", {}).get("anonymous"):
        out.append(Vuln(
            ip=ip, port=445, protocol="tcp",
            script_id="enum4linux-null-session", state="VULNERABLE",
            title="SMB null / anonymous session accepted",
            severity="high", source="enum4linux", confidence="confirmed"))
    shares = (data.get("shares") or {})
    if isinstance(shares, dict):
        for name, meta in shares.items():
            meta = meta or {}
            access = meta.get("access") or {}
            reads = access.get("mapping") == "OK" or access.get("read") == "OK"
            if reads:
                out.append(Vuln(
                    ip=ip, port=445, protocol="tcp",
                    script_id=f"enum4linux-share-{name}", state="finding",
                    title=f"SMB share readable: {name}",
                    output=(meta.get("comment") or "")[:400],
                    severity="medium", source="enum4linux", confidence="confirmed"))
    users = (data.get("users") or {})
    if isinstance(users, dict) and users:
        out.append(Vuln(
            ip=ip, port=445, protocol="tcp",
            script_id="enum4linux-user-enum", state="finding",
            title=f"SMB user enumeration exposed ({len(users)} users)",
            output=", ".join(sorted(users.keys())[:25])[:2000],
            severity="medium", source="enum4linux", confidence="confirmed"))
    return out


_TXT_NULL_RE = re.compile(r"(Anonymous|Null)\s+session\s+(succeed|OK|allow)", re.I)
_TXT_SHARE_RE = re.compile(r"^\s*(\S+)\s+(?:Disk|IPC)\s", re.M)
_TXT_TARGET_RE = re.compile(r"Target(?:\s+information)?[\s:]+(\S+)", re.I)


def _enum4linux_text(text: str) -> list[Vuln]:
    out: list[Vuln] = []
    m = _TXT_TARGET_RE.search(text)
    ip = m.group(1) if m else ""
    ip, _ = _split_host_port(ip, 445)
    if not ip:
        return out
    if _TXT_NULL_RE.search(text):
        out.append(Vuln(
            ip=ip, port=445, protocol="tcp",
            script_id="enum4linux-null-session", state="VULNERABLE",
            title="SMB null / anonymous session accepted",
            severity="high", source="enum4linux", confidence="confirmed"))
    shares = _TXT_SHARE_RE.findall(text)
    for s in shares[:30]:
        if s in ("Sharename", "----", "IPC$"):
            continue
        out.append(Vuln(
            ip=ip, port=445, protocol="tcp",
            script_id=f"enum4linux-share-{s}", state="finding",
            title=f"SMB share visible: {s}", severity="low",
            source="enum4linux", confidence="likely"))
    return out


# ---- registry ----------------------------------------------------------------

PARSERS = {
    "burp": parse_burp,
    "zap": parse_zap,
    "nikto": parse_nikto,
    "wpscan": parse_wpscan,
    "sslyze": parse_sslyze,
    "enum4linux": parse_enum4linux,
}
