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

from ..models import Vuln

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


def host_from(value: str) -> str:
    """Best-effort host key from a scanner's target field — an IP, hostname, URL, or
    `host:port`. Returns the IP when present, else a bare hostname; strips scheme/port/path.
    Never returns a URL (the nuclei/testssl bug that stuffed `https://…` into `ip`)."""
    v = (value or "").strip()
    if not v:
        return ""
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", v)
    if m:                                     # an IP anywhere wins (testssl 'host/ip', URLs, host:port)
        return m.group(0)
    if "://" in v:
        from urllib.parse import urlparse
        v = urlparse(v).hostname or v.split("://", 1)[1]
    v = v.split("/")[0]                       # strip any path
    if v.startswith("["):                     # [IPv6]:port
        v = v[1:].split("]")[0]
    elif v.count(":") == 1:                   # host:port (not IPv6)
        v = v.split(":")[0]
    return v.lower().rstrip(".")


def port_from(value: str) -> int | None:
    """Extract a :port from a URL / host:port / `443/tcp` string, or None."""
    m = re.search(r":(\d{1,5})(?:[/?#]|$)", value or "") or re.match(r"\s*(\d{1,5})/", value or "")
    if m:
        p = int(m.group(1))
        return p if 0 < p < 65536 else None
    return None


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
        root = ET.fromstring(text.lstrip("﻿"))
    except ET.ParseError:
        return None
    # Strip namespace prefixes so a report wrapped in a default xmlns still matches the
    # literal-name lookups (iter("ReportHost") / iter("result")) the parsers use.
    for el in root.iter():
        if isinstance(el.tag, str) and el.tag.startswith("{"):
            el.tag = el.tag.rsplit("}", 1)[1]
    return root


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
        ip = host_from(ip)                         # a hostname-target scan won't pretend to be an IP
        if not ip:
            continue
        for item in host.findall("ReportItem"):
            sev = _NESSUS_SEV.get(item.get("severity", "0"), "info")
            if sev == "info":
                # a compliance-audit item is severity 0 but its verdict lives in a
                # compliance-result child — a FAILED/WARNING is a real finding, not noise.
                verdict = next((ch.text or "" for ch in item
                                if ch.tag.rsplit("}", 1)[-1] == "compliance-result"), "")
                if verdict.strip().upper() in ("FAILED", "WARNING"):
                    sev = "medium"
                elif not include_info:
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
        ip = host_from((res.findtext("host") or "").strip().split()[0] if res.findtext("host") else "")
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
            # legacy <cve> children, modern <refs><ref type="cve" id="CVE-…"/>, then any CVE
            # text anywhere in the NVT as a last resort.
            cves = ([c.text.strip() for c in nvt.iter("cve") if c.text]
                    or [r.get("id") for r in nvt.iter("ref")
                        if (r.get("type") or "").lower() == "cve" and r.get("id")]
                    or re.findall(r"CVE-\d{4}-\d+", ET.tostring(nvt, encoding="unicode")))
        out.append(Vuln(
            ip=ip, port=port, protocol=proto,
            script_id="openvas", state="VULNERABLE" if sev in ("critical", "high") else "finding",
            title=name.strip(), severity=sev, ids=cves,
            output=(res.findtext("description") or "").strip()[:4000],
            source="openvas", confidence="likely"))
    return out


def _nuclei_rows(text: str):
    """Yield nuclei result objects from either the JSON array export (`-je`) or the JSON
    lines form (`-jsonl`/`-json`), tolerant of a BOM / pretty-printing."""
    s = text.lstrip("﻿").lstrip()
    if s[:1] == "[":                              # array export: parse the whole document
        try:
            data = json.loads(s)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            yield from (r for r in data if isinstance(r, dict))
        return
    for line in text.splitlines():               # JSONL: one object per line
        line = line.strip().lstrip("﻿")
        if not line or line[0] != "{":
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_nuclei(text: str, include_info: bool = False) -> list[Vuln]:
    """nuclei output — JSON array (`-je`) or JSON lines (`-jsonl`). info/detection templates
    are skipped unless include_info (they're not vulnerabilities)."""
    out: list[Vuln] = []
    for r in _nuclei_rows(text):
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        sev = (info.get("severity") or "info").lower()
        if sev in ("info", "unknown", "") and not include_info:
            continue
        target = (r.get("host") or r.get("matched-at") or r.get("matched")
                  or r.get("url") or r.get("ip") or "")
        host = host_from(r.get("ip") or target)      # never a URL; IP if present else hostname
        if not host:
            continue
        port = port_from(target) or port_from(host)
        cls = info.get("classification") or {}
        cve = cls.get("cve-id") or []
        if isinstance(cve, str):                     # a single cve-id as a bare string, not a list
            cve = [cve]
        cves = [c.upper() for c in cve if c]
        tid = r.get("template-id") or r.get("templateID") or ""
        out.append(Vuln(
            ip=host, port=port, protocol="tcp", script_id=f"nuclei-{tid}",
            state="VULNERABLE" if sev in ("critical", "high") else "finding",
            title=(info.get("name") or tid or "nuclei finding").strip(),
            severity=sev, ids=cves,
            output=(str(target) + "\n" + (info.get("description") or "")).strip()[:4000],
            source="nuclei", confidence="likely"))
    return out


_TESTSSL_SEV = {"critical": "critical", "high": "high", "medium": "medium",
                "low": "low", "warn": "low"}


def parse_testssl(text: str) -> list[Vuln]:
    """testssl.sh JSON — the flat `--jsonfile` array [{id,severity,finding,ip,port}, …] AND
    the nested `--jsonfile-pretty` shape {"scanResult":[{ip,port, <category>:[findings…]}]}
    where findings live in per-host category arrays (previously imported as zero)."""
    out: list[Vuln] = []
    try:
        data = json.loads(text.lstrip("﻿"))
    except json.JSONDecodeError:
        return out

    def emit(finding: dict, ip: str, port) -> None:
        sev = _TESTSSL_SEV.get(str(finding.get("severity", "")).lower())
        if not sev:                                    # OK / INFO / LOW-noise dropped
            return
        host = host_from(ip)
        if not host:
            return
        cve = [c.upper() for c in re.findall(r"CVE-\d{4}-\d+", finding.get("cve", "") or "")]
        out.append(Vuln(
            ip=host, port=int(port) if str(port).isdigit() else None,
            protocol="tcp", script_id=f"testssl-{finding.get('id', '')}",
            state="VULNERABLE" if sev in ("critical", "high") else "finding",
            title=f"TLS: {finding.get('id', 'finding')}", severity=sev, ids=cve,
            output=str(finding.get("finding", ""))[:4000], source="testssl", confidence="likely"))

    if isinstance(data, list):                         # flat array
        for f in data:
            if isinstance(f, dict):
                emit(f, f.get("ip", ""), f.get("port", ""))
    elif isinstance(data, dict):
        hosts = data.get("scanResult")
        if isinstance(hosts, list):                    # nested pretty: per-host category arrays
            for h in hosts:
                if not isinstance(h, dict):
                    continue
                ip, port = h.get("ip", ""), h.get("port", "")
                for val in h.values():
                    if isinstance(val, list):
                        for f in val:
                            if isinstance(f, dict) and "severity" in f:
                                emit(f, ip, port)
    return out


# Registry the web importer routes to. Each returns list[Vuln] with ip set.
SCANNER_PARSERS = {
    "nessus": parse_nessus,
    "openvas": parse_openvas,
    "nuclei": parse_nuclei,
    "testssl": parse_testssl,
}
# IP1/IP2/IP3 additions — pulled in lazily so the base importers.py stays small.
def _extend_scanner_parsers() -> None:
    global SCANNER_PARSERS
    if "burp" in SCANNER_PARSERS:
        return
    from . import parsers_web, parsers_recon, parsers_supply, parsers_generic
    SCANNER_PARSERS = {**SCANNER_PARSERS, **parsers_web.PARSERS,
                       **parsers_recon.PARSERS, **parsers_supply.PARSERS,
                       **parsers_generic.PARSERS}
_extend_scanner_parsers()


def detect_scanner(text: str) -> str:
    """Sniff a scanner export -> a SCANNER_PARSERS key, or '' if not one of them."""
    body = text.lstrip("﻿").lstrip()    # strip a UTF-8 BOM before sniffing the first char
    head = body[:600]
    low = head.lower()
    wide = text[:8000].lower()          # GVM/OpenVAS markers can sit well past the first tag
    if "nessusclientdata" in low:
        return "nessus"
    if "<report" in wide and ("openvas" in wide or "<results" in wide or "greenbone" in wide
                              or "gmp" in wide):
        return "openvas"
    if body[:1] in "[{":                # nuclei (array OR jsonl) vs testssl (flat OR pretty)
        w = text[:8000]
        if ('"template-id"' in w or '"templateID"' in w or '"matched-at"' in w
                or '"matched"' in w):
            return "nuclei"
        if ("scanresult" in wide or '"testssl"' in wide
                or ('"severity"' in w and '"finding"' in w)):
            return "testssl"
        # IP1: WPScan / sslyze / enum4linux-ng JSON
        if '"target_url"' in w or '"wpscan_version"' in w:
            return "wpscan"
        if '"server_scan_results"' in w or '"sslyze_version"' in w:
            return "sslyze"
        # enum4linux-ng --json — its output has a distinctive combination
        # (target + one of sessions/shares/users) that's stable across versions.
        if '"target"' in w and ('"sessions"' in w or '"shares"' in w or '"nmblookup"' in wide
                                or '"smb_dialects"' in wide):
            return "enum4linux"
    # IP1: XML-shaped scanners
    if "<issues" in wide and ("burp" in wide or "burpversion" in wide):
        return "burp"
    if "<owaspzapreport" in wide or ('<alertitem' in wide and '<riskcode>' in wide):
        return "zap"
    if "<niktoscan" in wide or "<scandetails" in wide and "niktoscan" in wide:
        return "nikto"
    # enum4linux plain-text: has the classic "Target Information" banner
    if "target information" in wide and ("[+] enumerating" in wide or "workgroup" in wide):
        return "enum4linux"
    # IP2 — text/JSON scanners
    if "[+] valid username:" in wide or "kerbrute" in wide:
        return "kerbrute"
    if wide.startswith("[") or "\n[" in wide[:2000]:
        # WhatWeb JSON array/lines: entries have "target" + "plugins"
        if '"target"' in wide[:4000] and '"plugins"' in wide[:4000]:
            return "whatweb"
    if "is behind" in wide and ("waf" in wide or "wafw00f" in wide):
        return "wafw00f"
    if "no waf detected by the generic detection" in wide:
        return "wafw00f"
    if "getadusers" in wide or ("passwordlastset" in wide and "lastlogon" in wide):
        return "impacket-adusers"
    if "delegationrightsto" in wide or "finddelegation" in wide:
        return "impacket-delegation"
    # IP3 — content-discovery + container/SBOM scanners (all JSON)
    if body[:1] in "[{":
        w = text[:8000]
        # ffuf: distinctive "commandline" + "results" keys
        if '"commandline"' in w and '"results"' in w:
            return "ffuf"
        # Trivy: ArtifactName + Results with Vulnerabilities/Misconfigurations
        if '"ArtifactName"' in w or ('"SchemaVersion"' in w and '"Results"' in w):
            return "trivy"
        # Grype: matches[] + vulnerability + artifact combo
        if '"matches"' in w and '"vulnerability"' in w and '"artifact"' in w:
            return "grype"
        # gobuster --format json (one obj per line)
        if '"path"' in w and '"status"' in w and '"gobuster"' in wide:
            return "gobuster"
    return ""
