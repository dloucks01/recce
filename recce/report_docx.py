"""Per-finding Word (.docx) write-ups, matching the walkthrough template.

recce auto-fills every field it can (title, affected systems, CWE, CVE, severity,
tools/techniques, recommendations, a drafted narrative and vuln-type, and the raw
evidence). Fields only the tester can supply - Mission Risk & Impact, Level of
Difficulty, and the step-by-step walkthrough with screenshots - are written as
clearly-marked [TESTER: ...] placeholders. The tester finishes each doc in Word
and pastes screenshots inline; recce never overwrites an edited write-up.

Findings are grouped by title across hosts, so one finding that spans many systems
becomes one write-up listing every affected IP:port.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import playbook as _pb
from . import exploitplan as _xp
from .docx import Document
from .exploitref import proven_exploit_ref
from .models import Host, Vuln

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# How the finding was established. "" = observed by an actual check (an NSE script
# that reported VULNERABLE, a config/probe observation, or an ingested on-target
# finding) and treated as REAL. Version-inferred guesses are "likely" or, at the
# weakest, "potential". By default the write-ups cover real findings and drop the
# "potential" version guesses; --include-potential brings them back.
_CONF_RANK = {"confirmed": 3, "likely": 2, "": 2, "potential": 1}


def _is_real(f: "Finding") -> bool:
    """A finding backed by an actual observation/check, not just a version guess."""
    return _CONF_RANK.get((f.confidence or "").lower(), 2) >= 2

# First matching CWE -> (vulnerability type, CIA aspects) for auto-draft. Ordered
# most-specific first; every CWE recce can emit is covered (see the coverage test).
_CIA = "Confidentiality, Integrity, Availability"
_CWE_TYPE = [
    (("CWE-78", "CWE-77", "CWE-88", "CWE-94", "CWE-95", "CWE-134", "CWE-74", "CWE-917",
      "CWE-1336"),
     "Injection / Remote Code Execution", _CIA),
    (("CWE-89",), "SQL Injection", "Confidentiality, Integrity"),
    (("CWE-79",), "Cross-Site Scripting", "Integrity"),
    (("CWE-352",), "Cross-Site Request Forgery (CSRF)", "Integrity"),
    (("CWE-601",), "Open Redirect", "Integrity"),
    (("CWE-502",), "Insecure Deserialization", _CIA),
    (("CWE-918",), "Server-Side Request Forgery (SSRF)", "Confidentiality, Integrity"),
    (("CWE-611",), "XML External Entity (XXE) Injection", "Confidentiality, Integrity"),
    (("CWE-434",), "Unrestricted File Upload", _CIA),
    (("CWE-444",), "HTTP Request Smuggling / Desync", "Integrity"),
    (("CWE-22", "CWE-98"), "Path Traversal / File Inclusion", "Confidentiality, Integrity"),
    (("CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-415", "CWE-416", "CWE-190",
      "CWE-193"), "Memory Corruption / Buffer Error", _CIA),
    (("CWE-287", "CWE-306", "CWE-288", "CWE-1188", "CWE-521", "CWE-307", "CWE-798",
      "CWE-290", "CWE-640", "CWE-863", "CWE-262"),
     "Authentication / Access Control Weakness", "Confidentiality, Integrity"),
    (("CWE-269", "CWE-250", "CWE-264", "CWE-426", "CWE-427", "CWE-428", "CWE-732",
      "CWE-266", "CWE-276"),
     "Privilege Escalation", "Confidentiality, Integrity"),
    (("CWE-319",), "Cleartext Transmission of Sensitive Data", "Confidentiality"),
    (("CWE-327", "CWE-326", "CWE-295", "CWE-297", "CWE-298", "CWE-330", "CWE-347"),
     "Cryptographic / TLS Weakness", "Confidentiality, Integrity"),
    (("CWE-522", "CWE-312", "CWE-256", "CWE-257", "CWE-260", "CWE-200", "CWE-538",
      "CWE-527", "CWE-532", "CWE-203", "CWE-204", "CWE-215", "CWE-548", "CWE-615"),
     "Information / Credential Disclosure", "Confidentiality"),
    (("CWE-693", "CWE-1021", "CWE-16", "CWE-650", "CWE-441", "CWE-284", "CWE-1004",
      "CWE-614", "CWE-942", "CWE-799", "CWE-1275"), "Security Misconfiguration", "Integrity"),
    (("CWE-364",), "Race Condition", "Integrity, Availability"),
    (("CWE-406", "CWE-400"), "Resource Exhaustion / Denial of Service", "Availability"),
    (("CWE-1104", "CWE-1392", "CWE-477"), "Unmaintained / Default Components", _CIA),
    (("CWE-506",), "Embedded Malicious Code / Backdoor", _CIA),
    (("CWE-20",), "Improper Input Validation", "Integrity"),  # generic - keep last
]

# CWE id -> short official name, so a finding references each CWE by name.
_CWE_NAME = {
    "CWE-16": "Configuration", "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal", "CWE-74": "Injection", "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection", "CWE-79": "Cross-site Scripting",
    "CWE-88": "Argument Injection", "CWE-89": "SQL Injection", "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection", "CWE-98": "PHP Remote File Inclusion",
    "CWE-119": "Improper Restriction of Memory Bounds", "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-bounds Read", "CWE-134": "Uncontrolled Format String",
    "CWE-190": "Integer Overflow", "CWE-193": "Off-by-one Error",
    "CWE-200": "Exposure of Sensitive Information", "CWE-203": "Observable Discrepancy",
    "CWE-204": "Observable Response Discrepancy",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-256": "Plaintext Storage of a Password",
    "CWE-257": "Storing Passwords in a Recoverable Format",
    "CWE-260": "Password in Configuration File",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-477": "Use of Obsolete Function / Protocol",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-215": "Information Exposure Through Debug Information",
    "CWE-262": "Not Using Password Aging / Weak Password Requirements",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-615": "Sensitive Information in Source Code / Comments",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-1336": "Server-Side Template Injection (Improper Template Neutralization)",
    "CWE-548": "Information Exposure Through Directory Listing",
    "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-266": "Incorrect Privilege Assignment",
    "CWE-269": "Improper Privilege Management", "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-364": "Signal Handler Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-406": "Insufficient Control of Network Message Volume",
    "CWE-415": "Double Free", "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-441": "Unintended Proxy or Intermediary (Confused Deputy)",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests (Request Smuggling)",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-506": "Embedded Malicious Code",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-527": "Exposure of Version-Control Repository",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-640": "Weak Password Recovery Mechanism",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-693": "Protection Mechanism Failure", "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials", "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1392": "Use of Default Credentials",
}


def cwe_label(cwe: str) -> str:
    """'CWE-22 (Path Traversal)' - the id plus its short name for reference."""
    name = _CWE_NAME.get(cwe)
    return f"{cwe} ({name})" if name else cwe

_SOURCE_TOOL = {
    "nse": "nmap NSE scripts",
    "version-db": "recce offline vulnerability database (service-version match)",
    "probe": "recce HTTP/TLS probe (standard library)",
    "config": "nmap NSE weak-configuration checks",
    "cred": "netexec / impacket / ssh (credentialed)",
    "bloodhound": "BloodHound / SharpHound (AD graph analysis)",
    "adcs": "Certipy (AD CS / ESC enumeration)",
    "mssql": "MSSQL enum (recce probes + nxc / impacket-mssqlclient)",
    "smb": "SMB enum (recce stdlib negotiate probe + nxc / smbclient)",
    "ftp": "FTP enum (recce stdlib control-channel probe + ftplib)",
    "docker": "Docker Engine API enum (recce stdlib HTTP probe)",
    "kubernetes": "Kubernetes enum (recce stdlib kubelet/API/etcd probe)",
    "ldap": "LDAP / AD enum (recce stdlib BER/ASN.1 client)",
    "snmp": "SNMP enum (recce stdlib BER v2c UDP client)",
    "mongodb": "MongoDB enum (recce stdlib OP_MSG/BSON wire client)",
    "redis": "Redis enum (recce stdlib RESP wire client)",
    "elasticsearch": "Elasticsearch enum (recce stdlib HTTP API client)",
    "rsync": "rsync-daemon enum (recce stdlib rsync protocol client)",
    "nfs": "NFS / mountd enum (recce stdlib ONC RPC client)",
    "kerberos": "AD roasting (recce stdlib Kerberos AS-REP client)",
}

# Severity -> hex colour (no #), matching the workbook + HTML-preview severity ramp.
_SEV_COLOR = {"critical": "C00000", "high": "C15A11", "medium": "9C7A00",
              "low": "2E5AAC", "info": "5F6F6E"}

# --- auto-drafted narrative building blocks (plain, management-level language) ---

# Port -> plain-language description of what the service is/does, for the opening
# context sentence. Falls back to banner keywords, then a generic phrase.
_SERVICE_ROLE = {
    80: "web service", 443: "web service (HTTPS)", 8080: "web service",
    8443: "web service (HTTPS)", 8000: "web service", 8888: "web service",
    8081: "web service", 9443: "web service (HTTPS)",
    21: "file-transfer (FTP) service", 22: "remote-administration (SSH) service",
    23: "remote-terminal (Telnet) service", 25: "mail (SMTP) service",
    110: "mail (POP3) service", 143: "mail (IMAP) service", 53: "DNS service",
    389: "directory (LDAP) service", 636: "directory (LDAPS) service",
    3268: "Active Directory directory service",
    88: "Kerberos authentication service",
    445: "Windows file-sharing (SMB) service",
    139: "Windows file-sharing (SMB) service",
    3389: "remote-desktop (RDP) service",
    5985: "Windows remote-management (WinRM) service",
    5986: "Windows remote-management (WinRM) service",
    3306: "database service (MySQL)", 5432: "database service (PostgreSQL)",
    1433: "database service (Microsoft SQL Server)", 1521: "database service (Oracle)",
    27017: "database service (MongoDB)", 6379: "in-memory data store (Redis)",
    9200: "search / analytics service (Elasticsearch)",
    161: "network-management (SNMP) service", 2049: "file-sharing (NFS) service",
}

# Vulnerability type (from _vuln_type) -> plain-language "an attacker could ..."
_TYPE_IMPACT = {
    "Injection / Remote Code Execution":
        "run their own commands on the affected system - in practice this often "
        "means full control of the host, its data, and any credentials stored on it",
    "SQL Injection":
        "read or alter the information held in the application's database, exposing "
        "sensitive records or corrupting data",
    "Cross-Site Scripting":
        "run malicious content in the browser of a legitimate user, which can be "
        "used to steal their session or trick them into unwanted actions",
    "Cross-Site Request Forgery (CSRF)":
        "trick a logged-in user's browser into performing unwanted actions on the "
        "application without their knowledge or consent",
    "Open Redirect":
        "abuse the site's own domain to send victims to an attacker-controlled page - "
        "lending credibility to phishing, or smuggling a token through a trusted "
        "OAuth/SSO redirect",
    "Path Traversal / File Inclusion":
        "read files outside the intended area of the application - and in some cases "
        "run code - exposing configuration, credentials, or source",
    "Authentication / Access Control Weakness":
        "bypass or abuse the service's sign-in and access controls to reach data or "
        "functions that should be restricted",
    "Privilege Escalation":
        "raise their level of access on the system, moving from a limited foothold "
        "toward full administrative control",
    "Cleartext Transmission of Sensitive Data":
        "observe sensitive information - including credentials - as it crosses the "
        "network, because it is not encrypted",
    "Cryptographic / TLS Weakness":
        "undermine the encryption protecting the service, potentially exposing or "
        "tampering with data in transit",
    "Information / Credential Disclosure":
        "obtain sensitive information - such as internal details or credentials - "
        "that makes further attack easier",
    "Security Misconfiguration":
        "take advantage of an insecure default or misconfiguration to gain access or "
        "information they should not have",
    "Resource Exhaustion / Denial of Service":
        "disrupt or disable the service, denying it to legitimate users",
    "Unmaintained / Default Components":
        "exploit publicly known weaknesses in outdated or default components that no "
        "longer receive security fixes",
    "Embedded Malicious Code / Backdoor":
        "use a built-in backdoor to gain direct, unauthenticated access to the system",
    "Insecure Deserialization":
        "abuse unsafe deserialization of untrusted data to run their own code on the "
        "server, typically taking full control",
    "Server-Side Request Forgery (SSRF)":
        "make the server send requests on their behalf to internal systems it can "
        "reach, exposing internal services or cloud metadata and credentials",
    "XML External Entity (XXE) Injection":
        "abuse XML parsing to read local files or reach internal systems, exposing "
        "sensitive data",
    "Unrestricted File Upload":
        "upload an executable file and run it on the server, typically gaining full "
        "control of the host",
    "HTTP Request Smuggling / Desync":
        "desynchronise how front-end and back-end servers interpret requests - "
        "poisoning other users' traffic or slipping past security controls",
    "Memory Corruption / Buffer Error":
        "corrupt the service's memory to crash it or, in the worst case, run their "
        "own code on the host",
    "Race Condition":
        "exploit a timing window to reach an unintended state, potentially "
        "escalating access or disrupting the service",
    "Improper Input Validation":
        "supply crafted input the service fails to validate, leading to unexpected "
        "and potentially exploitable behaviour",
}
_FALLBACK_IMPACT = ("weaken the security of the affected service, potentially "
                    "exposing data or functionality to unauthorized access")

# Hand-tuned, specific impact wording for marquee named vulnerabilities. Matched
# by CVE first, then by a name keyword in the title/script (so NSE-only hits like
# ms17-010, which carry no CVE, are still recognised). Each phrase follows
# "an attacker could ...".
_ETERNALBLUE = ("run code remotely and without any credentials over SMBv1 to take "
                "full control of the host - the EternalBlue flaw behind the WannaCry "
                "and NotPetya outbreaks")
_ZEROLOGON = ("reset a domain controller's machine-account password with no "
              "credentials at all and then seize control of the entire Active "
              "Directory domain (ZeroLogon)")
_PRINTNIGHTMARE = ("run code as SYSTEM through the Windows Print Spooler and, on a "
                   "domain controller, take over the whole domain (PrintNightmare)")
_SMBGHOST = ("run code remotely and without credentials against the SMBv3 "
             "compression flaw to take full control of the host (SMBGhost)")
_BLUEKEEP = ("run code remotely and without a login over Remote Desktop to take "
             "full control of the host - a wormable flaw (BlueKeep)")
_LOG4SHELL = ("make the application load and run attacker-supplied code simply by "
              "getting it to log a crafted string, usually leading to full remote "
              "control of the host (Log4Shell)")
_HEARTBLEED = ("read chunks of the server's live memory over TLS, exposing "
               "credentials, session tokens, and even the server's private key "
               "(Heartbleed)")
_SHELLSHOCK = ("run arbitrary commands by smuggling them through a crafted "
               "environment variable, taking control of the host (Shellshock)")
_PROXYLOGON = ("authenticate as the Exchange server itself and, chained with "
               "related flaws, run code as SYSTEM and read every mailbox (ProxyLogon)")
_PROXYSHELL = ("chain Exchange flaws to run code as SYSTEM and reach all mailboxes "
               "without authentication (ProxyShell)")
_SPRING4SHELL = ("achieve remote code execution against the Spring framework and "
                 "take control of the application server (Spring4Shell)")

_MARQUEE_CVE = {
    "CVE-2020-1472": _ZEROLOGON,
    "CVE-2021-34527": _PRINTNIGHTMARE, "CVE-2021-1675": _PRINTNIGHTMARE,
    "CVE-2017-0143": _ETERNALBLUE, "CVE-2017-0144": _ETERNALBLUE,
    "CVE-2017-0145": _ETERNALBLUE, "CVE-2017-0146": _ETERNALBLUE,
    "CVE-2017-0147": _ETERNALBLUE, "CVE-2017-0148": _ETERNALBLUE,
    "CVE-2020-0796": _SMBGHOST, "CVE-2019-0708": _BLUEKEEP,
    "CVE-2021-44228": _LOG4SHELL, "CVE-2021-45046": _LOG4SHELL,
    "CVE-2014-0160": _HEARTBLEED,
    "CVE-2014-6271": _SHELLSHOCK, "CVE-2014-7169": _SHELLSHOCK,
    "CVE-2021-26855": _PROXYLOGON, "CVE-2021-34473": _PROXYSHELL,
    "CVE-2022-22965": _SPRING4SHELL,
}
_MARQUEE_KW = {
    "ms17-010": _ETERNALBLUE, "eternalblue": _ETERNALBLUE, "zerologon": _ZEROLOGON,
    "printnightmare": _PRINTNIGHTMARE, "smbghost": _SMBGHOST, "bluekeep": _BLUEKEEP,
    "log4shell": _LOG4SHELL, "log4j": _LOG4SHELL, "heartbleed": _HEARTBLEED,
    "shellshock": _SHELLSHOCK, "proxylogon": _PROXYLOGON, "proxyshell": _PROXYSHELL,
    "spring4shell": _SPRING4SHELL,
}


def _marquee_impact(f: Finding) -> str | None:
    """Specific impact wording for a well-known named vuln, or None."""
    for cve in f.cves:
        if cve in _MARQUEE_CVE:
            return _MARQUEE_CVE[cve]
    hay = (f.title + " " + " ".join(f.scripts)).lower()
    for kw, impact in _MARQUEE_KW.items():
        if kw in hay:
            return impact
    return None


def _proven_exploit(f: Finding) -> str | None:
    """A verifiable, proven public exploit for this finding, or None (shared with
    the Vulnerabilities sheet via exploitref)."""
    return proven_exploit_ref(f.cves, f.title + " " + " ".join(f.scripts))
_SEV_FRAME = {
    "critical": "This is considered a critical-risk exposure",
    "high": "This is considered a high-risk exposure",
    "medium": "This is considered a moderate-risk issue",
    "low": "This is considered a lower-risk issue",
    "info": "This is an informational observation",
}


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _service_role(port: int, banner: str) -> str:
    role = _SERVICE_ROLE.get(port)
    if role:
        return role
    b = (banner or "").lower()
    if "http" in b:
        return "web service"
    if "ssh" in b:
        return "remote-administration (SSH) service"
    if "ftp" in b:
        return "file-transfer (FTP) service"
    if "smb" in b or "microsoft-ds" in b or "netbios" in b:
        return "Windows file-sharing (SMB) service"
    if any(k in b for k in ("sql", "postgres", "mysql", "oracle", "mongo")):
        return "database service"
    if "ldap" in b:
        return "directory (LDAP) service"
    return "network service"


def _narrative(f: Finding) -> list[str]:
    """Auto-draft a 3-paragraph, management-level narrative: what the service is,
    what was found (and where / how sure), and the plain-language impact."""
    if not f.affected:
        return [f"During testing, {f.title.lower()} was identified. {_SEV_FRAME.get(f.severity.lower(), 'This is an issue')}."]
    ip0, port0, _hn0 = f.affected[0]
    banner0 = f.services.get((ip0, port0), "")
    roles = []
    for ip, port, _hn in f.affected:
        r = _service_role(port, f.services.get((ip, port), ""))
        if r not in roles:
            roles.append(r)

    # 1) Context - what the affected component is.
    if len(roles) == 1:
        ctx = f"This finding concerns a {roles[0]}"
        if banner0:
            ctx += f" ({banner0})"
        ctx += ", exposed on the network to the tested environment."
    else:
        ctx = (f"This finding concerns {_join(roles)} exposed on the network to the "
               "tested environment.")

    # 2) What was found, where, and how confident we are.
    n = len(f.affected)
    where = _join([f"{ip}" + (f" ({hn})" if hn else "")
                   for ip, _p, hn in f.affected[:3]])
    more = f", and {n - 3} other system(s)" if n > 3 else ""
    cve = f" (tracked as {', '.join(f.cves[:3])})" if f.cves else ""
    found = (f"During testing, recce identified {f.title.lower()}{cve}, affecting "
             f"{n} system(s) - {where}{more}.")
    if f.confidence == "potential":
        found += (" This was inferred from the service's version and banner data, so "
                  "it should be confirmed through hands-on validation before it is "
                  "relied upon.")
    elif f.confidence == "likely":
        found += " The detected version falls within a range known to be affected."

    # 3) Plain-language impact, framed by severity. A marquee named vuln gets its
    # own hand-tuned wording; otherwise fall back to the vulnerability-type impact.
    vtype, _cia = _vuln_type(f.cwes)
    impact = _marquee_impact(f) or _TYPE_IMPACT.get(vtype, _FALLBACK_IMPACT)
    frame = _SEV_FRAME.get(f.severity.lower(), "This is an issue")
    consequence = (f"{frame}: if exploited, an attacker could {impact}.")
    return [ctx, found, consequence]


@dataclass
class Finding:
    title: str
    severity: str = "info"
    cwes: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    remediation: str = ""
    confidence: str = ""
    affected: list[tuple] = field(default_factory=list)   # (ip, port, hostname)
    evidence: list[tuple] = field(default_factory=list)    # (ip, port, output)
    services: dict = field(default_factory=dict)           # (ip,port) -> "product version"
    exploits: list[tuple] = field(default_factory=list)    # (edb_id, title)


# Common nmap NSE vuln/enum scripts -> CWE(s). Matched as a substring of the
# script id (or title), so variants and the "http-vuln-cveYYYY-N" family resolve.
# Every CWE here is already named + typed (enforced by the coverage test).
_NSE_CWE = {
    # SMB / Windows
    "ms17-010": ["CWE-787"], "ms08-067": ["CWE-119"], "ms06-025": ["CWE-119"],
    "ms07-029": ["CWE-119"], "ms10-054": ["CWE-119"], "ms10-061": ["CWE-119"],
    "cve2009-3103": ["CWE-119"], "cve-2017-7494": ["CWE-94"], "cve2017-7494": ["CWE-94"],
    "regsvc-dos": ["CWE-400"], "webexec": ["CWE-78"], "double-pulsar": ["CWE-506"],
    "rdp-vuln-ms12-020": ["CWE-119"],
    # HTTP (CVE-named + generic)
    "shellshock": ["CWE-78"], "cve2012-1823": ["CWE-78"], "cve2017-5638": ["CWE-94"],
    "cve2014-3704": ["CWE-89"], "cve2010-2861": ["CWE-22"], "cve2015-1635": ["CWE-119"],
    "cve2011-3192": ["CWE-400"], "cve2017-1001000": ["CWE-306"],
    "cve2021-41773": ["CWE-22"], "cve2021-42013": ["CWE-22"], "misfortune-cookie": ["CWE-119"],
    "sql-injection": ["CWE-89"], "phpself-xss": ["CWE-79"], "stored-xss": ["CWE-79"],
    "dombased-xss": ["CWE-79"], "-xss": ["CWE-79"], "csrf": ["CWE-352"],
    "slowloris": ["CWE-400"], "http-passwd": ["CWE-22"],
    "fileupload-exploiter": ["CWE-434"], "internal-ip-disclosure": ["CWE-200"],
    "http-git": ["CWE-527"], "config-backup": ["CWE-538"], "http-webdav-scan": ["CWE-16"],
    # TLS / crypto
    "ssl-heartbleed": ["CWE-125"], "ssl-poodle": ["CWE-327"],
    "ssl-ccs-injection": ["CWE-326"], "ssl-dh-params": ["CWE-326"],
    "sslv2": ["CWE-327"], "ssl-known-key": ["CWE-798"],
    # Services
    "vsftpd-backdoor": ["CWE-506"], "proftpd-backdoor": ["CWE-506"],
    "distcc-cve2004-2687": ["CWE-78"], "smtp-vuln-cve2010-4344": ["CWE-119"],
    "smtp-vuln-cve2011-1720": ["CWE-119"], "ms-sql-empty-password": ["CWE-521"],
    "mysql-empty-password": ["CWE-521"], "rmi-vuln-classloader": ["CWE-502"],
    "rmi-dumpregistry": ["CWE-502"], "snmp-info": ["CWE-200"],
}

# Famous scripts whose id carries no CVE token - map to the CVE(s) directly, so
# an NSE-only Windows finding still resolves to its published exploit reference.
_NSE_CVE = {
    "ms17-010": ["CVE-2017-0144"], "double-pulsar": ["CVE-2017-0144"],
    "ms08-067": ["CVE-2008-4250"], "conficker": ["CVE-2008-4250"],
    "ms12-020": ["CVE-2012-0002"], "ms10-061": ["CVE-2010-2729"],
    "ms06-025": ["CVE-2006-2370"], "ms07-029": ["CVE-2007-1748"],
    "ms10-054": ["CVE-2010-2550"], "webexec": ["CVE-2018-15442"],
    "regsvc-dos": ["CVE-2011-1002"],
    "vsftpd-backdoor": ["CVE-2011-2523"], "proftpd-backdoor": ["CVE-2010-3867"],
    "shellshock": ["CVE-2014-6271"], "ssl-heartbleed": ["CVE-2014-0160"],
    "ssl-poodle": ["CVE-2014-3566"], "ssl-ccs-injection": ["CVE-2014-0224"],
}

_CVE_IN_ID = re.compile(r"cve[-_]?(\d{4})[-_](\d{3,7})", re.I)


def _enrich_from_nse(f: "Finding") -> None:
    """Fill CVE/CWE for NSE-only findings (which carry neither) by mapping the
    script id/title: extract any embedded CVE, add well-known script->CVE, and
    map common script ids to CWEs. Never overrides data the finding already has."""
    text = " ".join([f.title] + sorted(f.scripts)).lower()
    if not f.cves:
        cves: list[str] = []
        for m in _CVE_IN_ID.finditer(text):
            cve = f"CVE-{m.group(1)}-{m.group(2)}"
            if cve not in cves:
                cves.append(cve)
        for key, mapped in _NSE_CVE.items():
            if key in text:
                for c in mapped:
                    if c not in cves:
                        cves.append(c)
        f.cves = cves
    if not f.cwes:
        cwes: list[str] = []
        for key, mapped in _NSE_CWE.items():
            if key in text:
                for c in mapped:
                    if c not in cwes:
                        cwes.append(c)
        f.cwes = cwes


def _norm_key(v: Vuln) -> str:
    return re.sub(r"\s+", " ", (v.title or v.script_id or "finding").strip().lower())


def group_findings(hosts: list[Host]) -> list[Finding]:
    """One Finding per distinct title, aggregating every affected host."""
    groups: dict[str, Finding] = {}
    for h in hosts:
        for v in h.vulns:
            key = _norm_key(v)
            f = groups.get(key)
            if f is None:
                f = Finding(title=v.title or v.script_id or "Finding",
                            severity=v.severity, remediation=v.remediation,
                            confidence=v.confidence)
                groups[key] = f
            # Severity: keep the highest seen.
            if _SEV_ORDER.get(v.severity, 9) < _SEV_ORDER.get(f.severity, 9):
                f.severity = v.severity
            # Confidence: keep the strongest seen, so a title confirmed by any one
            # check isn't dropped as a "potential" version guess.
            if (_CONF_RANK.get((v.confidence or "").lower(), 2)
                    > _CONF_RANK.get((f.confidence or "").lower(), 2)):
                f.confidence = v.confidence
            for c in v.cwes:
                if c not in f.cwes:
                    f.cwes.append(c)
            for c in v.ids:
                if c not in f.cves:
                    f.cves.append(c)
            f.sources.add(v.source)
            if v.script_id:
                f.scripts.add(v.script_id)
            f.remediation = f.remediation or v.remediation
            entry = (h.ip, v.port, h.hostname)
            if entry not in f.affected:
                f.affected.append(entry)
            if v.output:
                f.evidence.append((h.ip, v.port, v.output))
            # Record the detected service banner + any public exploit on this port.
            port = next((p for p in h.ports if p.portid == v.port), None)
            if port and port.service_banner:
                f.services[(h.ip, v.port)] = port.service_banner
            for e in h.exploits:
                if e.port == v.port and (e.edb_id, e.title) not in f.exploits:
                    f.exploits.append((e.edb_id, e.title))
    for f in groups.values():
        _enrich_from_nse(f)          # NSE-only findings get CVE/CWE from the script id
    ordered = sorted(groups.values(),
                     key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.title.lower()))
    return ordered


def _all_findings_with_ids(hosts: list[Host]) -> list[tuple[str, "Finding"]]:
    """Every grouped finding with a STABLE F-id = its position in the full
    severity-sorted list. Ids don't shift when severity/confidence filters are
    applied, so `F-007` names the same finding in the bulk run, the combined
    report, and a single-finding write-up."""
    return [(f"F-{i:03d}", f) for i, f in enumerate(group_findings(hosts), 1)]


def list_findings(hosts: list[Host], *, min_severity: str = "info") -> list[dict]:
    """A pickable index of findings for the CLI (id, severity, title, affected,
    confidence, whether it's real). Used to let the tester choose one to write up."""
    cutoff = _SEV_ORDER.get(min_severity, 4)
    out = []
    for fid, f in _all_findings_with_ids(hosts):
        if _SEV_ORDER.get(f.severity, 9) > cutoff:
            continue
        out.append({"id": fid, "severity": f.severity, "title": f.title,
                    "affected": sorted({a[0] for a in f.affected}),
                    "cves": f.cves, "confidence": f.confidence or "confirmed",
                    "real": _is_real(f)})
    return out


def _match_findings(allf: list[tuple[str, "Finding"]],
                    selector: str) -> list[tuple[str, "Finding"]]:
    """Resolve a selector to finding(s): an exact id ('F-007', '7'), else a
    case-insensitive substring of the title / CVE / affected IP / IP:port."""
    q = (selector or "").strip()
    if not q:
        return []
    m = re.fullmatch(r"[Ff]?-?0*(\d+)", q)
    if m:
        n = int(m.group(1))
        return [(fid, f) for fid, f in allf if int(fid.split("-")[1]) == n]
    ql = q.lower()
    out = []
    for fid, f in allf:
        hay = " | ".join(
            [f.title.lower()] + [c.lower() for c in f.cves]
            + [f"{ip}:{p}" for ip, p, _h in f.affected]
            + [ip for ip, _p, _h in f.affected]
            + [(hn or "").lower() for _i, _p, hn in f.affected])
        if ql in hay:
            out.append((fid, f))
    return out


def _looted_for(f: "Finding", hosts_by_ip: dict) -> list[str]:
    """Evidence already OBTAINED on the affected host(s): ingested on-target
    (recce-enum) findings and high-value harvested accounts/credentials. This is
    what a single-finding report pulls in to pre-fill 'what we already have'."""
    lines: list[str] = []
    for ip in sorted({a[0] for a in f.affected}):
        h = hosts_by_ip.get(ip)
        if not h:
            continue
        for lf in getattr(h, "local_findings", []) or []:
            txt = (lf.get("text") or lf.get("vector") or "").strip()
            if txt:
                sect = lf.get("section", "")
                lines.append(f"{ip}: on-target finding" + (f" [{sect}]" if sect else "")
                             + f" - {txt}")
        for a in getattr(h, "accounts", []) or []:
            attrs = a.attrs or {}
            tags = [t for t, on in (
                ("kerberoastable", attrs.get("kerberoastable")),
                ("AS-REP roastable", attrs.get("asrep_roastable")),
                ("adminCount=1", attrs.get("admincount")),
                ("password recovered", attrs.get("password") or attrs.get("cleartext")),
                ("hash captured", attrs.get("hash") or attrs.get("ntlm")),
            ) if on]
            if not tags:
                continue
            label = "/".join(x for x in (a.domain, a.name) if x) or a.name or "account"
            lines.append(f"{ip}: obtained account - {label} ({', '.join(tags)})")
    return lines


def _vuln_type(cwes: list[str]) -> tuple[str, str]:
    for keys, label, cia in _CWE_TYPE:
        if any(c in keys for c in cwes):
            return label, cia
    return "", ""


def _tools_line(f: Finding) -> str:
    tools = sorted({_SOURCE_TOOL.get(s, s) for s in f.sources})
    scripts = sorted(s for s in f.scripts if s and s not in ("version-db",))
    line = "; ".join(tools)
    if scripts:
        line += f" (checks: {', '.join(scripts[:8])})"
    return line


def _slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:n] or "finding"


def _walkthrough_steps(f: Finding) -> list[str]:
    """Draft concrete reproduction steps from what recce knows about the finding.

    These are the mechanical, repeatable steps (discovery command, confirmation
    check, candidate exploit). The tester still adds the exploitation result and
    screenshots - that part is a placeholder."""
    ip, port, _hn = f.affected[0]
    ports = sorted({p for _i, p, _h in f.affected if p})
    portspec = ",".join(str(p) for p in ports)
    banner = f.services.get((ip, port), "")
    scripts = sorted(s for s in f.scripts if s and s != "version-db")
    steps: list[str] = []

    # 1. Discovery / service identification. Host-level findings (e.g. an
    # on-target priv-esc finding) have no port - frame them as on-host context
    # instead of an empty "nmap -p None".
    if portspec:
        ident = f"Enumerate the target service: nmap -sV -p {portspec} {ip}"
        if banner:
            ident += f"  -> identifies \"{banner}\" on {port}/tcp."
    else:
        ident = (f"From a shell on {ip}, confirm the local condition this finding "
                 f"describes (see Evidence).")
    steps.append(ident)

    # 2. Confirmation, tailored to how recce detected it.
    if "version-db" in f.sources or "nse" in f.sources:
        if scripts:
            steps.append(f"Confirm the vulnerability with the NSE check(s): "
                         f"nmap --script {','.join(scripts[:4])} -p {portspec} {ip} "
                         f"(the script reports the vulnerable condition).")
        else:
            cve = f.cves[0] if f.cves else "the associated advisory"
            steps.append(f"Cross-check the detected version against {cve}: the "
                         f"running version falls within the known-vulnerable range.")
    elif "config" in f.sources:
        steps.append(f"Confirm the weak configuration: "
                     f"nmap --script {','.join(scripts[:4]) or 'default'} "
                     f"-p {portspec} {ip} (the check flags the exposed condition).")
    elif "probe" in f.sources:
        low = f.title.lower()
        if "tls" in low or "cipher" in low or "certificate" in low:
            steps.append(f"Enumerate TLS: nmap --script ssl-enum-ciphers,ssl-cert "
                         f"-p {portspec} {ip}  (or: openssl s_client -connect "
                         f"{ip}:{port}) - the weak protocol/cipher/cert is offered.")
        else:
            steps.append(f"Inspect the HTTP response headers: "
                         f"curl -sI http://{ip}:{port}/  - the flagged security "
                         f"header is absent from the response.")
    elif "cred" in f.sources:
        steps.append(f"Authenticate and enumerate with valid credentials, e.g.: "
                     f"netexec smb {ip} -u <user> -p <password> --shares "
                     f"(the tool output above confirms the access).")

    # 3. Exploit step - ONLY when there is a verifiable, PROVEN exploit: a
    # searchsploit / Exploit-DB match on the detected service, or a curated
    # well-known public exploit. Never for an advisory/potential lead (unconfirmed
    # version), and never a speculative "go research one" - if nothing proven is
    # known, the tester's [TESTER: perform the exploitation] placeholder stands.
    if f.confidence != "potential":
        # Remote exploit: if the finding maps to a published Metasploit module,
        # cite the ready-to-run invocation (recce `exploitplan` writes it as a .rc).
        msf = _xp._msf_for(f"{f.title} {' '.join(f.cves)} {' '.join(f.scripts)}")
        if msf:
            ip0, port0, _h0 = f.affected[0]
            steps.append(
                f"Exploit with the published module - {_xp._msf_cmd(msf, ip0, port0, '<LHOST>', 4444)} "
                f"({msf['note']}). recce `exploitplan` writes this as a ready-to-run "
                f".rc; run only within the rules of engagement.")
        if f.exploits:
            ids = ", ".join(f"EDB-{eid}" for eid, _t in f.exploits[:5] if eid)
            steps.append(f"Run the indexed public exploit(s) for this service: "
                         f"{ids}. Inspect with `searchsploit -x <id>`, then, if in "
                         f"scope, `searchsploit -m <id>` and validate.")
        else:
            proven = _proven_exploit(f)
            if proven:
                steps.append(f"Proven public exploit available: {proven}. Validate "
                             f"it in a controlled manner within the rules of "
                             f"engagement.")
        # Priv-esc findings: point at the exact EXISTING tool + command, with the
        # finding's own values filled in (see the Exploitation sheet). Reference to
        # vetted tooling, gated to confirmed findings - never for an advisory.
        evidence = " ".join(o for _i, _p, o in f.evidence)
        play = _pb.for_text(f"{f.title} {evidence}")
        if play:
            steps.append(
                f"Escalate with existing tooling - {play['tool']}: {play['cmd']} "
                f"(prerequisite: {play['prereq']}; confirm success by: "
                f"{play['validate']}).")

    return steps


def _finding_body(doc: Document, f: Finding, fid: str,
                  shots: dict | None = None,
                  looted: list[str] | None = None) -> None:
    """Render one finding's sections into `doc` (shared by per-finding + combined)."""
    vtype, cia = _vuln_type(f.cwes)
    sev = f.severity.lower()

    # Severity chip under the title, colour-coded like the workbook/preview.
    doc.para(f"● {f.severity.upper()} SEVERITY   ·   {len(f.affected)} "
             f"affected system(s)", bold=True, color=_SEV_COLOR.get(sev, "5F6F6E"))

    doc.heading("Narrative", 2)
    doc.placeholder("Refine the plain-language summary below for management.")
    for paragraph in _narrative(f):
        doc.para(paragraph)

    doc.heading("Finding Details", 2)
    doc.field("Finding ID", fid, mono=True)
    doc.field("Severity", f.severity.upper(), value_color=_SEV_COLOR.get(sev))
    doc.field("Affected systems", ", ".join(
        (f"{ip}:{port}" if port else ip) + (f" ({hn})" if hn else "")
        for ip, port, hn in f.affected), mono=True)
    doc.field("Vulnerability Type", vtype, placeholder="classify the vulnerability")
    doc.field("CWE Associated", "; ".join(cwe_label(c) for c in f.cwes),
              placeholder="add CWE reference(s)")
    doc.field("CVE / References", ", ".join(f.cves) or "None mapped", mono=True)
    doc.field("Security Aspect Compromised", cia,
              placeholder="confirm Confidentiality / Integrity / Availability")
    doc.field("Tools/Techniques Used", _tools_line(f))
    doc.field("Level of Difficulty", "", placeholder="rate exploitation difficulty "
              "(e.g. Low / Moderate / High) and justify")

    doc.heading("Mission Risk and Impact", 2)
    doc.placeholder("Describe the mission risk and impact if this finding is "
                    "exploited (engagement/mission specific).")

    doc.heading("Recommendations", 2)
    if f.remediation:
        doc.para(f.remediation)
    else:
        doc.placeholder("Provide remediation and mitigation guidance.")

    doc.heading("Evidence", 2)
    for ip, port, out in f.evidence[:6]:
        doc.para(f"{ip}:{port}" if port else ip, italic=True)
        doc.mono_block(out if len(out) < 1500 else out[:1500] + " ...")

    # Evidence already obtained on the affected host(s) - looted on-target findings
    # and harvested credentials/accounts. Only rendered when there is such data
    # (single-finding reports pass it in); pre-fills "what we already have".
    if looted:
        doc.heading("Obtained Access / Looted Evidence", 2)
        doc.placeholder("Credentials, shells, or on-target findings already "
                        "obtained on the affected host(s). Cite the items relevant "
                        "to this finding and remove the rest.")
        for line in looted[:25]:
            doc.para(line)

    doc.heading("Technical Walkthrough with screenshots", 2)
    # recce drafts the mechanical steps; the tester adds the exploitation result.
    n = 0
    for step in _walkthrough_steps(f):
        n += 1
        doc.para(f"Step {n}. {step}")
    for ip, _port, _hn in f.affected:
        for url, png in (shots or {}).get(ip, []):
            n += 1
            doc.para(f"Step {n}. Observe the affected service at {url}:")
            doc.image(png, caption=f"Screenshot: {url}")
    doc.para(f"Step {n + 1}. ")
    doc.placeholder("Perform the exploitation/validation, describe the result, "
                    "and capture a screenshot of the outcome above.")


def _write_one(f: Finding, fid: str, path: str,
               shots: dict | None = None,
               looted: list[str] | None = None) -> None:
    doc = Document()
    doc.title(f"{fid}: {f.title}")
    _finding_body(doc, f, fid, shots, looted)
    doc.save(path)


def build_writeups(hosts: list[Host], out_dir: str, *, min_severity: str = "low",
                   include_potential: bool = False,
                   screenshots: dict | None = None,
                   overwrite: bool = False) -> dict:
    """Generate one .docx per finding into out_dir. Returns a summary dict.

    Covers REAL findings by default - those backed by an actual check/observation.
    Version-inferred "potential" guesses are skipped unless include_potential=True.
    Informational (info severity) observations are excluded unless min_severity is
    lowered to 'info'. F-ids are stable (a finding's position in the full
    severity-sorted list), so they match the combined report and single write-ups.
    Never overwrites an existing write-up unless overwrite=True, so tester edits
    survive a regenerate."""
    os.makedirs(out_dir, exist_ok=True)
    cutoff = _SEV_ORDER.get(min_severity, 4)
    written, skipped, dropped = [], [], 0
    total = 0
    for fid, f in _all_findings_with_ids(hosts):
        if _SEV_ORDER.get(f.severity, 9) > cutoff:
            continue
        if not include_potential and not _is_real(f):
            dropped += 1
            continue
        total += 1
        fname = f"{fid}_{f.severity}_{_slug(f.title)}.docx"
        path = os.path.join(out_dir, fname)
        if os.path.exists(path) and not overwrite:
            skipped.append(fname)
            continue
        _write_one(f, fid, path, screenshots)
        written.append(fname)
    return {"written": written, "skipped": skipped, "total": total,
            "dropped_potential": dropped}


def build_one_writeup(hosts: list[Host], out_dir: str, selector: str, *,
                      screenshots: dict | None = None,
                      overwrite: bool = False) -> dict:
    """Write up a SINGLE finding chosen by `selector` (an F-id, CVE, IP, IP:port,
    or a title substring), pre-filled with everything recce already has for the
    affected host(s) - including looted on-target findings and obtained accounts/
    credentials. Returns {matched, written, ...}; if the selector is ambiguous or
    unmatched, `matched` lists the candidates instead of writing anything."""
    os.makedirs(out_dir, exist_ok=True)
    matches = _match_findings(_all_findings_with_ids(hosts), selector)
    cand = [{"id": fid, "severity": f.severity, "title": f.title,
             "affected": sorted({a[0] for a in f.affected})} for fid, f in matches]
    if len(matches) != 1:
        return {"matched": cand, "written": None,
                "reason": "none" if not matches else "ambiguous"}
    fid, f = matches[0]
    hosts_by_ip = {h.ip: h for h in hosts}
    looted = _looted_for(f, hosts_by_ip)
    fname = f"{fid}_{f.severity}_{_slug(f.title)}.docx"
    path = os.path.join(out_dir, fname)
    if os.path.exists(path) and not overwrite:
        return {"matched": cand, "written": None, "reason": "exists", "path": path}
    _write_one(f, fid, path, screenshots, looted)
    return {"matched": cand, "written": path, "looted": len(looted),
            "real": _is_real(f)}


def build_combined(hosts: list[Host], out_path: str, *, title: str = "",
                   min_severity: str = "low", include_potential: bool = False,
                   screenshots: dict | None = None) -> dict:
    """One document: title, severity summary, findings-summary table, then every
    finding as a section. Regenerated each run (it's a rollup, not hand-edited).
    Real findings only by default (include_potential brings back version guesses);
    informational (info) items excluded unless min_severity is lowered to 'info'."""
    cutoff = _SEV_ORDER.get(min_severity, 4)
    findings_with_ids = [(fid, f) for fid, f in _all_findings_with_ids(hosts)
                         if _SEV_ORDER.get(f.severity, 9) <= cutoff
                         and (include_potential or _is_real(f))]
    findings = [f for _fid, f in findings_with_ids]
    doc = Document()
    doc.title(title or "Penetration Test - Findings Report")
    doc.para(f"{len(findings)} finding(s) across "
             f"{len({a[0] for f in findings for a in f.affected})} affected host(s).",
             italic=True, color="666666")

    # Severity counts.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    doc.heading("Summary", 1)
    doc.table(["Critical", "High", "Medium", "Low", "Info"],
              [[str(counts.get(s, 0)) for s in
                ("critical", "high", "medium", "low", "info")]],
              widths=[1600, 1600, 1600, 1600, 1600])

    # Findings summary table.
    doc.heading("Findings", 1)
    rows = []
    for fid, f in findings_with_ids:
        hosts_txt = ", ".join(sorted({a[0] for a in f.affected}))
        rows.append([fid, f.severity.upper(), f.title,
                     ", ".join(f.cwes) or "-",
                     hosts_txt if len(hosts_txt) < 60 else f"{len(f.affected)} systems"])
    doc.table(["ID", "Severity", "Finding", "CWE", "Affected"], rows,
              widths=[900, 1100, 3860, 1500, 2000])

    # Each finding as a section.
    for fid, f in findings_with_ids:
        doc.page_break()
        doc.heading(f"{fid}: {f.title}", 1)
        _finding_body(doc, f, fid, screenshots)

    doc.save(out_path)
    return {"path": out_path, "total": len(findings)}
