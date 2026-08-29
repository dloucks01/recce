"""CWE (Common Weakness Enumeration) naming + inference + coverage.

Findings already carry hand-assigned `cwes`, and report_docx has a name table + an
NSE-script->CWE inference. This is the fuller, first-class layer (like attack.py):
a comprehensive CWE id->name table, an inference that covers recce's own deep-module
finding types (not just NSE scripts), a `label()` for reports, and an engagement-wide
`coverage()` summary. Offline and curated - no external MITRE/NVD lookups.
"""
from __future__ import annotations

# Comprehensive CWE id -> short name for the weaknesses recce findings actually hit,
# plus the common web/crypto/auth set. Names follow the MITRE CWE catalogue.
NAMES: dict[str, str] = {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-59": "Link Following",
    "CWE-74": "Injection",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-90": "Improper Neutralization of Special Elements used in an LDAP Query",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-93": "Improper Neutralization of CRLF Sequences (CRLF Injection)",
    "CWE-98": "PHP Remote File Inclusion",
    "CWE-113": "HTTP Response Splitting",
    "CWE-119": "Improper Restriction of Memory Buffer",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-134": "Uncontrolled Format String",
    "CWE-190": "Integer Overflow",
    "CWE-193": "Off-by-one Error",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-201": "Insertion of Sensitive Information Into Sent Data",
    "CWE-203": "Observable Discrepancy",
    "CWE-204": "Observable Response Discrepancy",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",
    "CWE-215": "Insertion of Sensitive Information Into Debugging Code",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-256": "Plaintext Storage of a Password",
    "CWE-257": "Storing Passwords in a Recoverable Format",
    "CWE-259": "Use of Hard-coded Password",
    "CWE-260": "Password in Configuration File",
    "CWE-262": "Not Using Password Aging / Weak Password Requirements",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-266": "Incorrect Privilege Assignment",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Authentication Bypass Using an Alternate Path",
    "CWE-290": "Authentication Bypass by Spoofing",
    "CWE-294": "Authentication Bypass by Capture-Replay",
    "CWE-295": "Improper Certificate Validation",
    "CWE-297": "Improper Validation of Certificate with Host Mismatch",
    "CWE-298": "Improper Validation of Certificate Expiration",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-321": "Use of Hard-coded Cryptographic Key",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-346": "Origin Validation Error",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-349": "Acceptance of Extraneous Untrusted Data With Trusted Data",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-359": "Exposure of Private Personal Information",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)",
    "CWE-364": "Signal Handler Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-405": "Asymmetric Resource Consumption (Amplification)",
    "CWE-406": "Insufficient Control of Network Message Volume",
    "CWE-451": "User Interface Misrepresentation of Critical Information",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-425": "Direct Request (Forced Browsing)",
    "CWE-426": "Untrusted Search Path",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-428": "Unquoted Search Path or Element",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-441": "Unintended Proxy or Intermediary (Confused Deputy)",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests (Request Smuggling)",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-477": "Use of Obsolete Function / Protocol",
    "CWE-494": "Download of Code Without Integrity Check",
    "CWE-497": "Exposure of Sensitive System Information",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-506": "Embedded Malicious Code",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-523": "Unprotected Transport of Credentials",
    "CWE-525": "Use of Web Browser Cache Containing Sensitive Information",
    "CWE-526": "Cleartext Storage of Sensitive Information in an Environment Variable",
    "CWE-527": "Exposure of Version-Control Repository to an Unauthorized Sphere",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File",
    "CWE-540": "Inclusion of Sensitive Information in Source Code",
    "CWE-489": "Active Debug Code",
    "CWE-943": "Improper Neutralization in Data Query Logic (NoSQL Injection)",
    "CWE-548": "Exposure of Information Through Directory Listing",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-598": "Information Exposure Through Query Strings in GET Request",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
    "CWE-615": "Sensitive Information in Source Code / Comments",
    "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
    "CWE-1391": "Use of Weak Credentials",
    "CWE-640": "Weak Password Recovery Mechanism",
    "CWE-650": "Trusting HTTP Permission Methods on the Server Side",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-749": "Exposed Dangerous Method or Function",
    "CWE-776": "XML Entity Expansion (Billion Laughs)",
    "CWE-778": "Insufficient Logging",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-799": "Improper Control of Interaction Frequency",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-1025": "Comparison Using Wrong Factors",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection",
    "CWE-916": "Use of Password Hash With Insufficient Computational Effort",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-923": "Improper Restriction of Communication Channel to Intended Endpoints",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
    "CWE-1035": "Using Components with Known Vulnerabilities",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1275": "Sensitive Cookie with Improper SameSite Attribute",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes",
    "CWE-1336": "Server-Side Template Injection (Improper Template Neutralization)",
    "CWE-1392": "Use of Default Credentials",
    "CWE-73": "External Control of File Name or Path",
    "CWE-184": "Incomplete List of Disallowed Inputs",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-300": "Channel Accessible by Non-Endpoint (MitM)",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-354": "Improper Validation of Integrity Check Value",
    "CWE-361": "7PK - Time and State",
    "CWE-665": "Improper Initialization",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-757": "Selection of Less-Secure Algorithm During Negotiation",
    "CWE-807": "Reliance on Untrusted Inputs in a Security Decision",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-940": "Improper Verification of Source of a Communication Channel",
    "CWE-1247": "Improper Protection Against Voltage and Clock Glitches",
    "CWE-1263": "Improper Physical Access Control",
    "CWE-1327": "Binding to an Unrestricted IP Address",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}


def name(cwe: str) -> str:
    return NAMES.get(cwe, "")


def label(cwe: str) -> str:
    n = NAMES.get(cwe)
    return f"{cwe} ({n})" if n else cwe


def url(cwe: str) -> str:
    num = cwe.split("-", 1)[-1]
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


# --- inference: finding -> CWE(s), for recce's own deep-module findings that don't
# already carry a CWE. Keyword rules over "script_id title"; first match wins.
_INFER: list[tuple[tuple[str, ...], list[str]]] = [
    (("kerberoast", "asrep", "as-rep", "krb5tgs", "roastable"), ["CWE-522"]),
    (("default cred", "default-cred", "default password", "default community",
      "public community"), ["CWE-1392"]),
    (("gpp", "cpassword", "unattend", "autologon"), ["CWE-257"]),
    (("web-git", "gitconfig", ".git", "source tree", "source code"), ["CWE-527", "CWE-540"]),
    (("dotenv", ".env"), ["CWE-526"]),
    (("-aws", ".aws", "secret-file", "credentials in file", "id_rsa", "private key",
      "htpasswd", "exposed .env", "credential"), ["CWE-522"]),
    (("pg_shadow", "mysql.user", "password hash", "password store"), ["CWE-522"]),
    (("trust authentication", "trust-auth", "empty password", "empty-password",
      "no password required", "without authentication", "unauth", "anonymous bind",
      "null session", "anonymous access"), ["CWE-306"]),
    (("smb signing", "smb-security-mode", "signing not required", "ntlm relay",
      "relay"), ["CWE-287"]),
    (("no_root_squash", "world-export", "world-readable", "incorrect permission",
      "writable share"), ["CWE-732"]),
    (("cleartext", "telnet", "sends credentials over http", "over http", "plaintext "),
     ["CWE-319"]),
    (("tls 1.0", "tls 1.1", "sslv2", "sslv3", "weak cipher", "poodle", "broken cipher"),
     ["CWE-327"]),
    (("directory listing", "autoindex"), ["CWE-548"]),
    (("sql injection", "sqli"), ["CWE-89"]),
    (("xss", "cross-site scripting"), ["CWE-79"]),
    (("ssrf",), ["CWE-918"]),
    (("xxe", "xml external"), ["CWE-611"]),
    (("deserial",), ["CWE-502"]),
    (("path traversal", "directory traversal", "lfi"), ["CWE-22"]),
    (("rce", "remote code execution", "command injection"), ["CWE-94"]),
    (("open relay", "mail relay"), ["CWE-284"]),
    (("exposed", "disclosure", "information exposure"), ["CWE-200"]),
]


def for_text(text: str) -> list[str]:
    """CWE(s) implied by a free-text finding/action title (no Vuln object needed)."""
    lower = (text or "").lower()
    for needles, cwes in _INFER:
        if any(n in lower for n in needles):
            return list(cwes)
    return []


def infer(vuln) -> list[str]:
    """CWE(s) for a finding that carries none, from recce's own finding vocabulary."""
    existing = list(getattr(vuln, "cwes", None) or [])
    if existing:
        return existing
    text = f"{getattr(vuln, 'script_id', '')} {getattr(vuln, 'title', '')}".lower()
    for needles, cwes in _INFER:
        if any(n in text for n in needles):
            return list(cwes)
    return []


def cwes_of(vuln) -> list[str]:
    """The finding's CWEs, inferring when it has none."""
    return infer(vuln)


def coverage(hosts) -> dict:
    """Engagement-wide CWE coverage: each weakness (id + name) with the hosts it was
    seen on, most-common first. For the report's weakness section."""
    seen: dict[str, set] = {}
    for h in hosts:
        for v in getattr(h, "vulns", []):
            for cwe in cwes_of(v):
                seen.setdefault(cwe, set()).add(h.ip)
    rows = [{"id": cwe, "name": NAMES.get(cwe, ""), "url": url(cwe),
             "hosts": sorted(ips)} for cwe, ips in seen.items()]
    rows.sort(key=lambda r: (-len(r["hosts"]), r["id"]))
    return {"weaknesses": rows, "count": len(rows)}
