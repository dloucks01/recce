"""Parse nmap XML output into the normalized data model.

Uses only the stdlib xml.etree parser. Designed to be tolerant: missing
attributes/elements are skipped rather than raising, because real-world scans
produce partial records all the time.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .models import Account, Host, Port, Script, Vuln

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
# Phrasings that mean the host is NOT affected, so a CVE mentioned in the same output
# (reference/advice text) must not be turned into a finding.
_NOT_AFFECTED_RE = re.compile(
    r"not\s+vulnerable|not\s+affected|not\s+susceptible|not\s+exploitable|"
    r"\bpatched\b|no\s+longer\s+vulnerable|appears\s+(?:to\s+be\s+)?safe", re.I)
# A CVSS *base score* in the phrasings NSE/community scripts emit -
# "CVSS Base Score: 7.5", "CVSSv3: 9.8", "CVSS: 9.8", "... (7.5)" - but NOT the
# version inside a vector string ("CVSS:3.1/AV:N/..."), where 3.1 is the CVSS
# version, not the score. The negative lookahead (?![\d./]) drops the vector case.
_CVSS_RE = re.compile(
    r"CVSS[^\n]*?base\s*score[:\s]*([0-9]{1,2}\.[0-9])"      # "Base Score: 7.5"
    r"|CVSS(?:v?\d)?[:\s]+([0-9]{1,2}\.[0-9])(?![\d./])"     # "CVSSv3: 9.8" (not a vector)
    r"|CVSS[^\n(]*\(([0-9]{1,2}\.[0-9])\)",                  # "CVSS2#... (7.5)"
    re.IGNORECASE)
# vulners lines look like:  CVE-2021-42013   9.8   https://vulners.com/...
_VULNERS_RE = re.compile(r"CVE-\d{4}-\d{4,7}\s+([0-9]{1,2}\.[0-9])\b", re.IGNORECASE)


def _to_int(value, default: int = 0) -> int:
    """Tolerant int() for XML attributes: a well-formed nmap XML can still carry an
    empty/odd numeric attribute (portid="", accuracy=""), and parse_nmap_xml promises
    to never raise - it returns [] on bad input, not a ValueError up the call stack."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_elements(node: ET.Element) -> dict:
    """Flatten <elem key=..> and nested <table> into a dict for structured access."""
    result: dict = {}
    for elem in node.findall("elem"):
        key = elem.get("key")
        if key:
            result[key] = (elem.text or "").strip()
    for i, table in enumerate(node.findall("table")):
        key = table.get("key") or f"_table{i}"
        result[key] = _parse_elements(table)
    return result


def _script_from_node(node: ET.Element) -> Script:
    return Script(
        id=node.get("id", ""),
        output=(node.get("output") or "").strip(),
        elements=_parse_elements(node),
    )


def _classify_vuln(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """Turn a vuln-flavored NSE script result into a Vuln, or None if not relevant."""
    sid = script.id
    out = script.output or ""
    up = out.upper()
    # "VULNERABLE" as a real positive state, NOT the substring inside "NOT VULNERABLE"
    # (a patched host that prints "State: NOT VULNERABLE" must not become a finding).
    positive = re.search(r"(?<!NOT )VULNERABLE", up) is not None
    is_vuln_family = (
        positive
        or sid.startswith("vuln")
        or sid == "vulners"
        or "CVE-" in up
    )
    if not is_vuln_family:
        return None
    # Explicitly not-vulnerable (patched) → drop it; never report a NOT-VULNERABLE
    # script as a finding. Beyond the exact "NOT VULNERABLE" state string, catch the
    # other ways a script says the host is fine while still mentioning a CVE in its
    # reference/advice text ("host is not affected. See CVE-2021-44228") - which
    # otherwise slipped past the CVE gate below and became a spurious info finding.
    if not positive and _NOT_AFFECTED_RE.search(out):
        return None
    # Skip scripts that report nothing actionable (no positive state, no CVE).
    if not positive and "CVE-" not in up and sid != "vulners":
        return None

    state = ""
    m = re.search(r"State:\s*(.+)", out)
    if m:
        state = m.group(1).strip()
    elif positive:
        state = "VULNERABLE"

    ids = sorted(set(_CVE_RE.findall(out)))
    cvss_scores = [float(g) for tup in _CVSS_RE.findall(out) for g in tup if g]
    cvss_scores += [float(s) for s in _VULNERS_RE.findall(out)]
    # A confirmed-vulnerable NSE script with no embedded CVSS defaults to "high", but
    # a few well-known families are unambiguously critical (RCE) - rate them so.
    _CRITICAL_SIDS = ("smb-vuln-ms17-010", "smb-vuln-ms08-067", "rdp-vuln-ms12-020",
                      "smb-vuln-cve-2017-7494", "smb-double-pulsar-backdoor")
    if cvss_scores:
        severity = _severity_from_cvss(max(cvss_scores))
    elif positive:
        severity = "critical" if any(s in sid for s in _CRITICAL_SIDS) else "high"
    else:
        severity = "info"

    title = sid
    tm = re.search(r"Title:\s*(.+)", out)
    if tm:
        title = tm.group(1).strip()

    return Vuln(
        ip=host_ip,
        port=port.portid if port else None,
        protocol=port.protocol if port else "",
        script_id=sid,
        state=state,
        title=title,
        output=out,
        severity=severity,
        ids=[i.upper() for i in ids],
    )


# --- weak-configuration findings from enumeration scripts -----------------------

def _weak_config(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """Classify notable weak-config / exposure findings from enum NSE scripts.

    These are not CVEs but are real engagement findings (cleartext auth, anonymous
    access, weak TLS, dangerous HTTP methods, exposed data stores, ...).
    """
    sid = script.id
    out = script.output or ""
    low = out.lower()
    sev = title = None
    cwe: list[str] = []

    if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
        sev, title, cwe = "medium", "Anonymous FTP login allowed", ["CWE-1392", "CWE-306"]
    elif sid == "ssl-enum-ciphers":
        if re.search(r"least strength:\s*[c-f]\b", low) or any(
                w in out for w in ("SSLv2", "SSLv3", "RC4", "NULL", "EXPORT",
                                   "SWEET32", "anonymous")):
            sev, title, cwe = "medium", "Weak SSL/TLS ciphers or protocols", ["CWE-327", "CWE-326"]
    elif sid == "ssl-cert":
        if "expired" in low:
            sev, title, cwe = "low", "Expired TLS certificate", ["CWE-298", "CWE-295"]
        elif "self-signed" in low or "self signed" in low:
            sev, title, cwe = "low", "Self-signed TLS certificate", ["CWE-295"]
    elif sid == "http-methods" and ("put" in low or "delete" in low or "trace" in low):
        if "potentially risky methods" in low:
            sev, title, cwe = "low", "Risky HTTP methods enabled (PUT/DELETE/TRACE)", ["CWE-650"]
    elif sid == "http-webdav-scan" and "webdav" in low:
        sev, title, cwe = "low", "WebDAV enabled", ["CWE-650"]
    elif sid == "http-git" and ".git" in low:
        sev, title, cwe = "medium", "Exposed .git repository", ["CWE-527", "CWE-538"]
    elif sid in ("mysql-empty-password", "ms-sql-empty-password") and \
            ("account has empty password" in low or "empty password" in low):
        sev, title, cwe = "high", "Database account with empty password", ["CWE-521", "CWE-287"]
    elif sid == "redis-info" and "version" in low:
        sev, title, cwe = "medium", "Unauthenticated Redis exposed", ["CWE-306"]
    elif sid == "mongodb-info" and "version" in low:
        sev, title, cwe = "medium", "Unauthenticated MongoDB exposed", ["CWE-306"]
    elif sid == "telnet-encryption" and "does not support encryption" in low:
        sev, title, cwe = "medium", "Telnet without encryption (cleartext)", ["CWE-319"]
    elif sid == "smtp-open-relay" and "is an open relay" in low:
        sev, title, cwe = "high", "SMTP open relay", ["CWE-269"]
    elif sid == "nfs-showmount" and "/" in out:
        sev, title, cwe = "low", "NFS exports readable", ["CWE-284"]
    elif sid.startswith("snmp") and re.search(
            r"valid credential|(?:public|private)\b[^\n]*\bvalid\b", low):
        # Require the snmp-brute "public - Valid credentials" signal, not a bare
        # "public"/"private" substring that could just be a device description.
        sev, title, cwe = "medium", "SNMP community string exposed", ["CWE-1392", "CWE-319"]
    elif sid == "dns-zone-transfer" and "domain" in low and "failed" not in low:
        sev, title, cwe = "medium", "DNS zone transfer allowed", ["CWE-200"]
    elif sid == "vnc-info" and "no authentication" in low:
        sev, title, cwe = "high", "VNC without authentication", ["CWE-306"]
    elif sid == "http-open-proxy" and "potentially open proxy" in low:
        sev, title, cwe = "medium", "Open HTTP proxy", ["CWE-441"]

    if not sev:
        return None
    return Vuln(
        ip=host_ip,
        port=port.portid if port else None,
        protocol=port.protocol if port else "",
        script_id=sid,
        state="finding",
        title=title,
        output=out,
        severity=sev,
        cwes=cwe,
        source="config",
    )


def _classify_any(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """A CVE/vuln finding takes precedence; otherwise try weak-config."""
    return _classify_vuln(host_ip, port, script) or _weak_config(host_ip, port, script)


# --- AD / SMB / LDAP host-script harvesting -------------------------------------

def _accounts_from_host_scripts(host_ip: str, script: Script) -> list[Account]:
    accounts: list[Account] = []
    sid = script.id
    out = script.output or ""

    if sid == "smb-enum-users":
        # Lines look like:  DOMAIN\alice (RID: 1001) ...
        for m in re.finditer(r"([\w.-]+)\\([\w.$-]+)\s*\(RID:\s*(\d+)\)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="user",
                                    domain=m.group(1), name=m.group(2), rid=m.group(3)))
    elif sid in ("smb-enum-shares",):
        for m in re.finditer(r"\\\\[\w.$-]+\\([\w.$ -]+)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="share", name=m.group(1).strip()))
    elif sid == "smb-os-discovery":
        el = script.elements
        domain = el.get("domain", "") or el.get("Domain", "")
        fqdn = el.get("fqdn", "") or el.get("FQDN", "")
        if domain or fqdn:
            accounts.append(Account(ip=host_ip, source=sid, kind="domain",
                                    domain=domain, name=fqdn, detail=out.replace("\n", "; ")))
    elif sid.startswith("ldap"):
        for m in re.finditer(r"(?:dnsHostName|defaultNamingContext|rootDomainNamingContext):\s*(.+)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="domain", detail=m.group(1).strip()))
    return accounts


def parse_nmap_xml(path: str) -> list[Host]:
    """Parse one nmap XML file into a list of Host objects (up hosts only).

    Never raises: a missing/unreadable/empty/truncated XML (nmap failed to start,
    was killed by a timeout, or wrote a partial file) yields [] rather than
    crashing the phase - the caller treats it as "nothing found here"."""
    try:
        tree = ET.parse(path)
    except (FileNotFoundError, OSError):
        return []
    except ET.ParseError:
        # nmap may leave a truncated file if interrupted; try lenient recovery.
        try:
            with open(path, "r", errors="replace") as fh:
                data = fh.read()
        except OSError:
            return []
        end = data.rfind("</nmaprun>")
        if end == -1:
            # Close the last complete <host> block and the run so we salvage partials.
            last_host_end = data.rfind("</host>")
            if last_host_end == -1:
                return []
            data = data[: last_host_end + len("</host>")] + "\n</nmaprun>"
        try:
            tree = ET.ElementTree(ET.fromstring(data))
        except ET.ParseError:
            return []

    root = tree.getroot()
    start = root.get("start", "")
    hosts: list[Host] = []

    for hnode in root.findall("host"):
        status = hnode.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        up_reason = status.get("reason", "") if status is not None else ""
        if state == "down":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in hnode.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr", ip)
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            continue

        host = Host(ip=ip, state=state, up_reason=up_reason, mac=mac, vendor=vendor,
                    last_scanned=start)

        hn_node = hnode.find("hostnames")
        if hn_node is not None:
            for hn in hn_node.findall("hostname"):
                name = hn.get("name")
                if name and name not in host.hostnames:
                    host.hostnames.append(name)

        # OS detection.
        os_node = hnode.find("os")
        if os_node is not None:
            matches = os_node.findall("osmatch")
            if matches:
                best = max(matches, key=lambda m: _to_int(m.get("accuracy", "0")))
                host.os_name = best.get("name", "")
                host.os_accuracy = _to_int(best.get("accuracy", "0"))
                oclass = best.find("osclass")
                if oclass is not None:
                    host.os_family = oclass.get("osfamily", "")

        dist = hnode.find("distance")
        if dist is not None:
            host.distance = _to_int(dist.get("value", "0"))

        # Ports.
        ports_node = hnode.find("ports")
        if ports_node is not None:
            for pnode in ports_node.findall("port"):
                st = pnode.find("state")
                pstate = st.get("state", "") if st is not None else ""
                if pstate in ("closed", "filtered"):
                    continue  # keep only open / open|filtered
                port = Port(
                    portid=_to_int(pnode.get("portid", "0")),
                    protocol=pnode.get("protocol", "tcp"),
                    state=pstate or "open",
                    reason=st.get("reason", "") if st is not None else "",
                )
                svc = pnode.find("service")
                if svc is not None:
                    port.service = svc.get("name", "")
                    port.product = svc.get("product", "")
                    port.version = svc.get("version", "")
                    port.extrainfo = svc.get("extrainfo", "")
                    port.tunnel = svc.get("tunnel", "")
                    port.ostype = svc.get("ostype", "")
                    port.cpe = [c.text for c in svc.findall("cpe") if c.text]
                    # The raw probe response nmap collected but couldn't match to a
                    # signature - free evidence we mine later (svcdetect) instead of
                    # discarding it, so an unmatched port isn't a dead end.
                    port.servicefp = svc.get("servicefp", "")
                    # A concrete name from nmap (not the "unknown"/"tcpwrapped"
                    # non-answers) is authoritative; record that provenance so our
                    # fallback naming only fills the genuine gaps.
                    if port.service and port.service not in ("unknown", "tcpwrapped"):
                        port.detect_source = "nmap"
                for snode in pnode.findall("script"):
                    script = _script_from_node(snode)
                    port.scripts.append(script)
                    vuln = _classify_any(ip, port, script)
                    if vuln:
                        host.vulns.append(vuln)
                host.ports.append(port)

        # Host-level scripts (SMB/LDAP/AD enrichment, host-level vuln scripts).
        hostscript = hnode.find("hostscript")
        if hostscript is not None:
            for snode in hostscript.findall("script"):
                script = _script_from_node(snode)
                host.host_scripts.append(script)
                vuln = _classify_any(ip, None, script)
                if vuln:
                    host.vulns.append(vuln)
                host.accounts.extend(_accounts_from_host_scripts(ip, script))

        _infer_os(host)
        hosts.append(host)

    return hosts


def _infer_os(host: Host) -> None:
    """When nmap ran no OS-detection block, fall back to the OS stated by
    smb-os-discovery or by service ostype / product fingerprints. Best-effort:
    os_accuracy stays 0 so it reads as an inference, not a real fingerprint, and
    a genuine osmatch (which sets os_family) always wins - this only fills a gap.
    Populates os_family so the Overview counts, the priv-esc playbook, and the
    OS-gated vuln signatures classify the host instead of treating it as unknown."""
    if host.os_family:
        return
    # 1) smb-os-discovery is authoritative when present.
    for sc in host.host_scripts:
        if sc.id != "smb-os-discovery":
            continue
        osv = (sc.elements.get("os") if sc.elements else "") or ""
        if not osv:
            m = re.search(r"OS:\s*([^;\n]+)", sc.output or "")
            osv = m.group(1).strip() if m else ""
        low = osv.lower()
        if "windows" in low:
            host.os_name = host.os_name or osv
            host.os_family = "Windows"
            return
        if "linux" in low or "unix" in low:
            host.os_name = host.os_name or osv
            host.os_family = "Linux"
            return
    # 2) majority ostype across ports, else product/service keywords.
    win = lin = 0
    for p in host.ports:
        ot = (p.ostype or "").lower()
        if "windows" in ot:
            win += 1
        elif "linux" in ot or "unix" in ot:
            lin += 1
    if not win and not lin:
        blob = " ".join(f"{p.service} {p.product}" for p in host.ports).lower()
        if any(k in blob for k in ("microsoft", "ms-wbt", "netbios-ssn", "microsoft-ds")):
            win += 1
        if any(k in blob for k in ("ubuntu", "debian", " linux", "openssh")):
            lin += 1
    if win > lin:
        host.os_family, host.os_name = "Windows", host.os_name or "Windows"
    elif lin > win:
        host.os_family, host.os_name = "Linux", host.os_name or "Linux"


def _split_product_version(s: str) -> tuple[str, str]:
    """gnmap merges product+version+extra into one field, e.g.
    'OpenSSH 8.2p1 Ubuntu 4ubuntu0.1' -> ('OpenSSH', '8.2p1'). The version is the
    first token that starts with a digit; everything before it is the product."""
    s = s.strip()
    if not s:
        return "", ""
    toks = s.split()
    for i, t in enumerate(toks):
        if t[0].isdigit():
            return " ".join(toks[:i]), t
    return s, ""


def parse_gnmap(path: str) -> list[Host]:
    """Parse nmap grepable output (-oG / .gnmap) into Host objects.

    Grepable output carries host + open ports + service + version (when -sV was
    used) but NO NSE scripts or structured OS match - so it feeds enumeration and
    the offline version->CVE engine, just with less fidelity than XML. Prefer XML
    (-oX) when you have it. Never raises."""
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    hosts: dict[str, Host] = {}
    for line in lines:
        line = line.rstrip("\n")
        m = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not m:
            continue
        ip, hostname = m.group(1), m.group(2)
        host = hosts.get(ip)
        if host is None:
            # A host explicitly listed in an imported scan report is treated as up:
            # the grepable format carries no status reason, and hiding a host the
            # operator's own report enumerated would be the worst kind of miss.
            host = Host(ip=ip, state="up", up_reason="report-listed")
            hosts[ip] = host
        if hostname and hostname not in host.hostnames:
            host.hostnames.append(hostname)
        pm = re.search(r"Ports:\s*(.+?)(?:\tIgnored State:|$)", line)
        if pm:
            for entry in pm.group(1).split(","):
                fields = entry.strip().split("/")
                if len(fields) < 3 or not fields[0].isdigit():
                    continue
                if "open" not in fields[1]:
                    continue
                portid, proto = int(fields[0]), (fields[2] or "tcp")
                if any(p.portid == portid and p.protocol == proto for p in host.ports):
                    continue
                service = fields[4] if len(fields) > 4 else ""
                product, version = _split_product_version(
                    fields[6] if len(fields) > 6 else "")
                host.ports.append(Port(portid=portid, protocol=proto, state="open",
                                       service=service, product=product, version=version))
        om = re.search(r"\bOS:\s*([^\t]+)", line)
        if om and not host.os_name:
            host.os_name = om.group(1).strip()
            low = host.os_name.lower()
            host.os_family = ("Windows" if "windows" in low else
                              "Linux" if ("linux" in low or "unix" in low) else "")
    result = list(hosts.values())
    for h in result:
        _infer_os(h)
    return result


_NORMAL_HOST = re.compile(
    r"Nmap scan report for (?:([^\s()]+)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)"
    r"|(\d{1,3}(?:\.\d{1,3}){3}))")
_NORMAL_PORT = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S+)(?:\s+(.*\S))?\s*$")


def parse_normal(path: str) -> list[Host]:
    """Parse nmap normal output (-oN, the default human-readable .nmap file).

    Reads the 'Nmap scan report for <host> (<ip>)' blocks and their PORT table
    (open ports only, with service + version when -sV was used). Less structured
    than XML - no NSE script data - but covers the format testers most often have
    lying around. Never raises."""
    try:
        with open(path, "r", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    hosts: list[Host] = []
    cur: Host | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        m = _NORMAL_HOST.search(line)
        if m:
            hostname, ip = (m.group(1) or ""), (m.group(2) or m.group(3))
            # Explicitly listed in an imported report => up (see parse_grepable).
            cur = Host(ip=ip, state="up", up_reason="report-listed")
            if hostname:
                cur.hostnames.append(hostname)
            hosts.append(cur)
            continue
        if cur is None:
            continue
        pm = _NORMAL_PORT.match(line.strip())
        if pm and "open" in pm.group(3):
            product, version = _split_product_version(pm.group(5) or "")
            cur.ports.append(Port(portid=int(pm.group(1)), protocol=pm.group(2),
                                  state="open", service=pm.group(4),
                                  product=product, version=version))
            continue
        om = re.match(r"(?:OS details|Running|Service Info:\s*OS):\s*(.+)", line)
        if om and not cur.os_name:
            cur.os_name = om.group(1).split(";")[0].strip()
            low = cur.os_name.lower()
            cur.os_family = ("Windows" if "windows" in low else
                             "Linux" if ("linux" in low or "unix" in low) else "")
    for h in hosts:
        _infer_os(h)
    return hosts


def parse_nmap_file(path: str) -> list[Host]:
    """Parse an already-completed nmap scan, auto-detecting the format: XML (-oX),
    grepable (-oG), or normal text (-oN). Also handles masscan/other tools that
    emit nmap-compatible XML. Sniffs content when the extension is ambiguous."""
    low = path.lower()
    if low.endswith(".xml"):
        return parse_nmap_xml(path)
    if low.endswith((".gnmap", ".grep")):
        return parse_gnmap(path)
    if low.endswith(".nmap"):
        return parse_normal(path)
    try:
        with open(path, "r", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return []
    if "<nmaprun" in head or head.lstrip().startswith("<?xml"):
        return parse_nmap_xml(path)
    if re.search(r"^Host:\s+\S+\s+\(", head, re.M):
        return parse_gnmap(path)
    if "Nmap scan report for" in head:
        return parse_normal(path)
    return []
