"""Parsers that fold third-party scanner output into recce's model.

Each `parse_*` takes the raw text of a tool's export and returns a list of `Vuln`
(with `ip` set) ready to fold onto hosts. Everything is stdlib-only and defensive:
a malformed document yields `[]`, never an exception, so the web Import panel can
hand user-supplied files straight in.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from .models import Vuln

# --- upload decoding + shared classifiers ---------------------------------------
# CSI + a few OSC/other escape sequences a piped tool log can carry.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]*$")
_NT_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_LMNT_RE = re.compile(r"^([0-9a-fA-F]{32}):([0-9a-fA-F]{32})$")


def decode_bytes(raw: bytes) -> str:
    """Decode uploaded bytes to text, handling the encodings real tool output uses —
    UTF-16 (the DEFAULT of a Windows PowerShell `>` / Out-File redirect), a UTF-8/UTF-16
    BOM, then UTF-8, falling back to latin-1. Never raises."""
    if not raw:
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):        # UTF-16 with BOM (decode auto-picks endianness)
        try:
            return raw.decode("utf-16")
        except (UnicodeDecodeError, ValueError):
            pass
    head = raw[:512]
    if head.count(0) > len(head) // 4:               # BOM-less UTF-16: interleaved NULs
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                pass
    if raw[:3] == b"\xef\xbb\xbf":                    # UTF-8 BOM
        return raw[3:].decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def strip_ansi(text: str) -> str:
    """Remove ANSI colour/escape sequences a piped/`tee`'d tool log carries, so line
    parsers (netexec, on-target loot) match on the real text."""
    return _ANSI_RE.sub("", text)


def is_ip(value: str) -> bool:
    """True if value is an IPv4 or (loosely) IPv6 literal — used to reject a hostname/URL
    being stored as a host's `ip` key."""
    v = (value or "").strip()
    return bool(_IPV4_RE.match(v) or (":" in v and _IPV6_RE.match(v)))


def classify_secret(secret: str) -> tuple[str, str]:
    """(kind, sprayable_secret) for a captured secret. An `LM:NT` pair collapses to the NT
    half (the sprayable one); a bare 32-hex is an NT hash; a `$krb5*` is a roast hash;
    anything else is a plaintext password."""
    s = (secret or "").strip()
    m = _LMNT_RE.match(s)
    if m:
        return "nthash", m.group(2)
    if _NT_RE.match(s):
        return "nthash", s
    if s.startswith(("$krb5tgs$", "$krb5asrep$")):
        return "hash", s
    return "password", s

# Nessus severity code (0-4) and OpenVAS/GVM threat word -> recce severity.
_NESSUS_SEV = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
_THREAT_SEV = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "log": "info", "info": "info", "debug": "info"}


def _safe_fromstring(text: str):
    """Parse XML, refusing DTD/entity declarations. stdlib ElementTree expands internal
    entities (a 'billion laughs' DoS vector on untrusted input, and we have no defusedxml
    in an airgapped stdlib-only build). Returns the root element, or None on any problem."""
    # Scan the WHOLE document: comments/whitespace are legal in the prolog, so a DOCTYPE
    # can be padded past any fixed prefix window. The regex over the (already size-capped)
    # text runs once and is cheap.
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text, re.I):
        return None
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _cvss_to_sev(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _split_port(text: str) -> tuple[int | None, str]:
    """'445/tcp' or '445' -> (445, 'tcp'); 'general/tcp' -> (None, 'tcp')."""
    m = re.match(r"(\d+)?/?(tcp|udp)?", (text or "").strip(), re.I)
    if not m:
        return None, "tcp"
    port = int(m.group(1)) if m.group(1) else None
    return port, (m.group(2) or "tcp").lower()


def parse_nessus(text: str, include_info: bool = False) -> list[Vuln]:
    """Nessus v2 export (.nessus): ReportHost > ReportItem. Info-level (severity 0)
    items are open-port/service noise and are skipped unless include_info."""
    out: list[Vuln] = []
    root = _safe_fromstring(text)
    if root is None:
        return out
    for host in root.iter("ReportHost"):
        ip = host.get("name", "")
        for tag in host.findall("./HostProperties/tag"):
            if tag.get("name") == "host-ip" and tag.text:
                ip = tag.text.strip()
                break
        if not ip:
            continue
        for item in host.findall("ReportItem"):
            sev = _NESSUS_SEV.get(item.get("severity", "0"), "info")
            if sev == "info" and not include_info:
                continue
            port, proto = item.get("port", "0"), (item.get("protocol", "tcp") or "tcp")
            cves = [c.text.strip() for c in item.findall("cve") if c.text]
            desc = (item.findtext("synopsis") or item.findtext("description") or "").strip()
            out.append(Vuln(
                ip=ip, port=int(port) if port and port.isdigit() and port != "0" else None,
                protocol=proto, script_id=f"nessus-{item.get('pluginID', '')}",
                state="VULNERABLE" if sev in ("critical", "high") else "finding",
                title=(item.get("pluginName") or "Nessus finding").strip(),
                severity=sev, ids=cves, output=desc[:4000],
                remediation=(item.findtext("solution") or "").strip(),
                source="nessus", confidence="likely"))
    return out


def parse_openvas(text: str) -> list[Vuln]:
    """OpenVAS / Greenbone (GVM) XML report: results > result."""
    out: list[Vuln] = []
    root = _safe_fromstring(text)
    if root is None:
        return out
    for res in root.iter("result"):
        ip = (res.findtext("host") or "").strip().split()[0] if res.findtext("host") else ""
        if not ip:
            continue
        port, proto = _split_port(res.findtext("port") or "")
        threat = (res.findtext("threat") or "").strip().lower()
        sev = _THREAT_SEV.get(threat, "")
        if not sev:
            try:
                sev = _cvss_to_sev(float(res.findtext("severity") or 0))
            except ValueError:
                sev = "info"
        if sev == "info":
            continue
        nvt = res.find("nvt")
        name = (nvt.findtext("name") if nvt is not None else None) or res.findtext("name") or "OpenVAS finding"
        cves = []
        if nvt is not None:
            cves = [c.text.strip() for c in nvt.iter("cve") if c.text] or \
                   re.findall(r"CVE-\d{4}-\d+", nvt.findtext("refs") or "")
        out.append(Vuln(
            ip=ip, port=port, protocol=proto,
            script_id="openvas", state="VULNERABLE" if sev in ("critical", "high") else "finding",
            title=name.strip(), severity=sev, ids=cves,
            output=(res.findtext("description") or "").strip()[:4000],
            source="openvas", confidence="likely"))
    return out


def parse_nuclei(text: str) -> list[Vuln]:
    """nuclei JSON lines (`-json`/`-jsonl`): one result object per line."""
    out: list[Vuln] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info") or {}
        host = (r.get("ip") or r.get("host") or "").strip()
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", host or r.get("matched-at", ""))
        ip = m.group(1) if m else host
        if not ip:
            continue
        pm = re.search(r":(\d+)", r.get("matched-at", "") or host)
        cls = info.get("classification") or {}
        cves = [c.upper() for c in (cls.get("cve-id") or []) if c]
        out.append(Vuln(
            ip=ip, port=int(pm.group(1)) if pm else None, protocol="tcp",
            script_id=f"nuclei-{r.get('template-id', '')}",
            state="VULNERABLE", title=(info.get("name") or r.get("template-id") or "nuclei finding").strip(),
            severity=(info.get("severity") or "info").lower(), ids=cves,
            output=(r.get("matched-at", "") + "\n" + (info.get("description") or "")).strip()[:4000],
            source="nuclei", confidence="likely"))
    return out


def parse_testssl(text: str) -> list[Vuln]:
    """testssl.sh JSON (`--jsonfile`): a flat array of finding objects."""
    out: list[Vuln] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    rows = data.get("scanResult", data) if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return out
    sev_map = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "warn": "low"}
    for r in rows:
        if not isinstance(r, dict):
            continue
        sev = sev_map.get(str(r.get("severity", "")).lower())
        if not sev:                                    # OK / INFO / LOW-noise dropped
            continue
        ip = (r.get("ip") or "").split("/")[-1] or r.get("ip", "")
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", ip)
        ip = m.group(1) if m else ip
        if not ip:
            continue
        cve = [c.upper() for c in re.findall(r"CVE-\d{4}-\d+", r.get("cve", "") or "")]
        out.append(Vuln(
            ip=ip, port=int(r["port"]) if str(r.get("port", "")).isdigit() else None,
            protocol="tcp", script_id=f"testssl-{r.get('id', '')}",
            state="VULNERABLE" if sev in ("critical", "high") else "finding",
            title=f"TLS: {r.get('id', 'finding')}", severity=sev, ids=cve,
            output=str(r.get("finding", ""))[:4000], source="testssl", confidence="likely"))
    return out


# Registry the web importer routes to. Each returns list[Vuln] with ip set.
SCANNER_PARSERS = {
    "nessus": parse_nessus,
    "openvas": parse_openvas,
    "nuclei": parse_nuclei,
    "testssl": parse_testssl,
}


def detect_scanner(text: str) -> str:
    """Sniff a scanner export -> a SCANNER_PARSERS key, or '' if not one of them."""
    head = text.lstrip()[:600]
    low = head.lower()
    wide = text[:8000].lower()          # GVM/OpenVAS markers can sit well past the first tag
    if "nessusclientdata" in low:
        return "nessus"
    if "<report" in wide and ("openvas" in wide or "<results" in wide or "greenbone" in wide
                              or "gmp" in wide):
        return "openvas"
    if head[:1] == "{" and '"template-id"' in text[:4000]:
        return "nuclei"
    if head[:1] in "[{" and ('"severity"' in text[:4000] and
                             ('"finding"' in text[:4000] or '"testssl"' in low
                              or "scanresult" in low)):
        return "testssl"
    return ""
