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

# Nessus severity code (0-4) and OpenVAS/GVM threat word -> recce severity.
_NESSUS_SEV = {"4": "critical", "3": "high", "2": "medium", "1": "low", "0": "info"}
_THREAT_SEV = {"critical": "critical", "high": "high", "medium": "medium",
               "low": "low", "log": "info", "info": "info", "debug": "info"}


def _safe_fromstring(text: str):
    """Parse XML, refusing DTD/entity declarations. stdlib ElementTree expands internal
    entities (a 'billion laughs' DoS vector on untrusted input, and we have no defusedxml
    in an airgapped stdlib-only build). Returns the root element, or None on any problem."""
    if re.search(r"<!(?:DOCTYPE|ENTITY)", text[:8000], re.I):
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
    if "nessusclientdata" in low:
        return "nessus"
    if "<report" in low and ("openvas" in low or "<results" in low or "greenbone" in low
                             or "gmp" in low):
        return "openvas"
    if head[:1] == "{" and '"template-id"' in text[:4000]:
        return "nuclei"
    if head[:1] in "[{" and ('"severity"' in text[:4000] and
                             ('"finding"' in text[:4000] or '"testssl"' in low
                              or "scanresult" in low)):
        return "testssl"
    return ""
