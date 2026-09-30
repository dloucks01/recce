"""A curated, offline default-credential knowledge base + per-service test commands.

Default creds are one of the highest-value, lowest-effort footholds - a NAS with
admin/admin, a switch with cisco/cisco, sa with a blank password. recce had only a
handful of web defaults; this is the broader, per-service set, plus the exact
lockout-aware command to test them.

Testing default creds SENDS authentication attempts (lockout risk), so recce's role
here is guided-by-default: it emits the precise `nxc`/`hydra` command with the right
pairs for each discovered service. It never sprays them unattended.
"""
from __future__ import annotations

import shlex

# service key -> list of (user, password, note). "" password = blank; a "" user for
# snmp means a community string. Kept deliberately short - the *most common* defaults,
# not a brute-force wordlist (that's what SecLists + --user-list are for).
_DB: dict[str, list[tuple[str, str, str]]] = {
    "ssh": [("root", "root", ""), ("root", "toor", ""), ("admin", "admin", ""),
            ("pi", "raspberry", "Raspberry Pi"), ("ubnt", "ubnt", "Ubiquiti"),
            ("vagrant", "vagrant", "Vagrant box"), ("admin", "password", "")],
    "ftp": [("anonymous", "anonymous", "anon FTP"), ("ftp", "ftp", ""),
            ("admin", "admin", ""), ("root", "root", "")],
    "telnet": [("admin", "admin", ""), ("root", "root", ""), ("cisco", "cisco", "Cisco"),
               ("admin", "", "blank"), ("Administrator", "admin", "")],
    "mysql": [("root", "root", ""), ("root", "", "blank root"), ("root", "toor", ""),
              ("mysql", "mysql", "")],
    "postgresql": [("postgres", "postgres", ""), ("postgres", "", "blank"),
                   ("postgres", "admin", "")],
    "mssql": [("sa", "sa", ""), ("sa", "", "blank sa"), ("sa", "Password123", "")],
    "redis": [("", "", "no auth / requirepass unset")],
    "mongodb": [("", "", "no auth")],
    "vnc": [("", "password", ""), ("", "admin", ""), ("", "vnc", "")],
    "rdp": [("administrator", "administrator", ""), ("admin", "admin", "")],
    "smb": [("administrator", "", "blank admin"), ("guest", "", "guest"),
            ("administrator", "administrator", "")],
    "winrm": [("administrator", "administrator", ""), ("admin", "admin", "")],
    "snmp": [("", "public", "RO community"), ("", "private", "RW community")],
    "http": [("admin", "admin", ""), ("admin", "password", ""), ("admin", "", "blank"),
             ("root", "root", ""), ("tomcat", "tomcat", "Tomcat"),
             ("minioadmin", "minioadmin", "MinIO"), ("admin", "changeit", "")],
    "ipmi": [("ADMIN", "ADMIN", "Supermicro"), ("admin", "admin", ""),
             ("root", "calvin", "Dell iDRAC"), ("USERID", "PASSW0RD", "IBM/Lenovo")],
    "elasticsearch": [("elastic", "changeme", "")],
    "ldap": [("cn=admin,dc=example,dc=com", "admin", "")],
}

# nxc-supported protocols (preferred). Others fall back to hydra.
_NXC = {"ssh": "ssh", "smb": "smb", "winrm": "winrm", "mssql": "mssql", "ldap": "ldap",
        "rdp": "rdp", "ftp": "ftp", "vnc": "vnc"}

# port number -> service key (fallback when nmap's service name is generic)
_PORT_SVC = {
    22: "ssh", 21: "ftp", 23: "telnet", 3306: "mysql", 5432: "postgresql",
    1433: "mssql", 6379: "redis", 27017: "mongodb", 5900: "vnc", 5901: "vnc",
    3389: "rdp", 445: "smb", 139: "smb", 5985: "winrm", 5986: "winrm", 161: "snmp",
    623: "ipmi", 9200: "elasticsearch", 389: "ldap", 636: "ldap",
    8080: "http", 8443: "http", 80: "http", 443: "http",
}


def service_key(port) -> str | None:
    """The default-creds service key for a port (by service name, then port number)."""
    svc = (getattr(port, "service", "") or "").lower()
    for key in _DB:
        if key in svc:
            return key
    if "microsoft-ds" in svc or "netbios" in svc:
        return "smb"
    if "ms-wbt" in svc or "term" in svc:
        return "rdp"
    if "postgres" in svc:
        return "postgresql"
    return _PORT_SVC.get(getattr(port, "portid", 0))


def creds_for(port) -> list[tuple[str, str, str]]:
    key = service_key(port)
    return list(_DB.get(key, [])) if key else []


def test_command(service: str, ips: list[str]) -> str:
    """The exact command to test this service's default creds across the given IPs,
    with `--continue-on-success` and paired pairs (no cartesian brute) where possible."""
    pairs = _DB.get(service, [])
    tgt = _target_expr(ips)
    proto = _NXC.get(service)
    if service == "snmp":
        comms = " ".join(p for _u, p, _n in pairs)
        return f"onesixtyone {tgt} {comms}    # or: nxc snmp {tgt} -u '' -p {comms}"
    if service in ("redis", "mongodb"):
        return (f"nxc {service} {tgt}    # unauth check (no credentials); "
                f"redis-cli -h <ip> PING / mongosh --host <ip>")
    if proto:
        # `--no-bruteforce` pairs the -u and -p lists POSITIONALLY (i-th user with
        # i-th password), so the two lists must stay aligned and be passed as separate,
        # space-separated args. netexec does NOT split comma-joined values, and sorting
        # the user/password sets independently would test the wrong pairs entirely.
        seen: set[tuple[str, str]] = set()
        uniq: list[tuple[str, str]] = []
        for u, p, _n in pairs:
            if (u, p) not in seen:
                seen.add((u, p))
                uniq.append((u, p))
        us = " ".join(shlex.quote(u) for u, _p in uniq) or "''"
        ps = " ".join(shlex.quote(p) for _u, p in uniq) or "''"
        return (f"nxc {proto} {tgt} -u {us} -p {ps} "
                "--continue-on-success --no-bruteforce")
    # hydra fallback (http and anything nxc doesn't cover)
    pair_list = " ".join(f"{u}:{p}" for u, p, _n in pairs)
    return (f"# default creds to try on {tgt} ({service}): {pair_list}\n"
            f"#   hydra -C <user:pass-file> {service}://<ip>   (build the file from the pairs)")


def _target_expr(ips: list[str]) -> str:
    # Only the discovered in-scope IPs - never widen to a whole /24. Collapsing to
    # x.y.z.0/24 would emit a command that sprays up to 256 addresses, most of them
    # never enumerated (lockout risk on out-of-scope hosts). Cf. credentials._target_expr.
    return " ".join(ips) if ips else "<ip>"
