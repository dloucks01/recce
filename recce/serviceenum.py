"""Bridge from recce's discovered open ports to the per-service enumeration
scripts in recce/scripts/. Mirrors recce-service.sh's service-name / port -> script
map so `recce services` can tell the tester exactly what to run next against each
open port (the tool's answer to "what command do I type here?").

Keep this in sync with recce/scripts/recce-service.sh (name_to_svc / port_to_svc).
"""
from __future__ import annotations

# nmap service name -> per-service script basename.
_NAME = {
    "ftp": "ftp", "ftp-data": "ftp", "ssh": "ssh", "telnet": "telnet",
    "smtp": "smtp", "smtps": "smtp", "submission": "smtp",
    "domain": "dns", "dns": "dns", "finger": "finger",
    "http": "http", "http-proxy": "http", "http-alt": "http", "https": "http",
    "https-alt": "http", "http-mgmt": "http", "www": "http",
    "kerberos": "kerberos", "kerberos-sec": "kerberos", "kpasswd": "kerberos",
    "pop3": "pop-imap", "pop3s": "pop-imap", "imap": "pop-imap", "imaps": "pop-imap",
    "rpcbind": "rpc-nfs", "nfs": "rpc-nfs", "nfs_acl": "rpc-nfs", "mountd": "rpc-nfs",
    "msrpc": "msrpc", "epmap": "msrpc",
    "netbios-ssn": "smb", "microsoft-ds": "smb", "smb": "smb",
    "ldap": "ldap", "ldaps": "ldap", "globalcatldap": "ldap", "globalcatldapssl": "ldap",
    "snmp": "snmp", "snmptrap": "snmp",
    "ms-sql-s": "mssql", "ms-sql": "mssql", "mssql": "mssql",
    "mysql": "mysql", "mariadb": "mysql",
    "postgresql": "postgres", "postgres": "postgres",
    "ms-wbt-server": "rdp", "rdp": "rdp", "ms-term-serv": "rdp",
    "vnc": "vnc", "vnc-http": "vnc",
    "redis": "redis", "wsman": "winrm", "winrm": "winrm",
    "mongodb": "mongodb", "mongod": "mongodb",
    "oracle": "oracle", "oracle-tns": "oracle",
    "ajp13": "ajp", "ajp": "ajp", "elasticsearch": "elasticsearch",
}

# port number -> per-service script (fallback when the service name is unknown).
_PORT = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 465: "smtp", 587: "smtp",
    53: "dns", 79: "finger",
    80: "http", 81: "http", 443: "http", 8000: "http", 8008: "http", 8080: "http",
    8081: "http", 8443: "http", 8888: "http",
    88: "kerberos", 110: "pop-imap", 143: "pop-imap", 993: "pop-imap", 995: "pop-imap",
    111: "rpc-nfs", 2049: "rpc-nfs", 135: "msrpc", 139: "smb", 445: "smb",
    389: "ldap", 636: "ldap", 3268: "ldap", 3269: "ldap", 161: "snmp",
    1433: "mssql", 1434: "mssql", 3306: "mysql", 5432: "postgres", 3389: "rdp",
    5900: "vnc", 5901: "vnc", 5902: "vnc", 6379: "redis", 5985: "winrm", 5986: "winrm",
    27017: "mongodb", 27018: "mongodb", 1521: "oracle", 1522: "oracle",
    8009: "ajp", 9200: "elasticsearch", 9300: "elasticsearch",
}

DRIVER = "./scripts/recce-service.sh"


def script_for(service: str, port: int) -> str:
    """The per-service script basename for a service name / port, or "" if none.
    Service name wins; the port is the fallback (and handles ssl/http-style names)."""
    # WinRM (5985/5986) is almost always labelled "http" by nmap; the port is the
    # authoritative signal, so it wins over the generic service name here.
    if port in (5985, 5986):
        return "winrm"
    s = (service or "").lower()
    if s in _NAME:
        return _NAME[s]
    for part in s.split("/"):
        if part in _NAME:
            return _NAME[part]
    return _PORT.get(port, "")


def commands_for_host(host) -> list[tuple[int, str, str, str]]:
    """[(port, service, script, command)] for each open port that maps to a script."""
    out = []
    for p in host.open_ports:
        script = script_for(p.service, p.portid)
        if not script:
            continue
        out.append((p.portid, p.service or script, script,
                    f"{DRIVER} {script} {host.ip} {p.portid}"))
    return out


def unmapped_ports(host) -> list[tuple[int, str]]:
    """Open ports with no dedicated script (enumerate manually)."""
    return [(p.portid, p.service or "")
            for p in host.open_ports if not script_for(p.service, p.portid)]
