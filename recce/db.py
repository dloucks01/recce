"""Database enumeration & vulnerability scanning.

Identifies database services, drives DB-specific nmap NSE scripts (safe by
default, intrusive brute/RCE checks behind --aggressive), and produces a
structured Databases view for the report. Security issues (empty passwords,
unauth exposure) still flow into the Vulnerabilities sheet via the parser's
weak-config classifier; this module owns the inventory view.
"""

from __future__ import annotations

import re

from .models import Host, Port

# port -> engine
DB_PORTS = {
    1433: "mssql", 1434: "mssql", 3306: "mysql", 5432: "postgresql",
    1521: "oracle", 1522: "oracle", 27017: "mongodb", 27018: "mongodb",
    6379: "redis", 50000: "db2", 5984: "couchdb", 9200: "elasticsearch",
    11211: "memcached", 9042: "cassandra", 7000: "cassandra", 8086: "influxdb",
}
_NAME_HINTS = {
    "mysql": "mysql", "mariadb": "mysql", "ms-sql": "mssql", "mssql": "mssql",
    "microsoft sql": "mssql", "oracle": "oracle", "postgres": "postgresql",
    "pgsql": "postgresql", "mongodb": "mongodb", "redis": "redis",
    "db2": "db2", "couchdb": "couchdb", "elastic": "elasticsearch",
    "memcache": "memcached", "cassandra": "cassandra", "influx": "influxdb",
}

# Safe (detection/enumeration) DB scripts - nmap gates by port/service.
_DB_SCRIPTS_SAFE = [
    "mysql-info", "mysql-databases", "mysql-users", "mysql-variables",
    "mysql-empty-password",
    "ms-sql-info", "ms-sql-ntlm-info", "ms-sql-config", "ms-sql-empty-password",
    "oracle-tns-version", "oracle-sid-brute",
    "mongodb-info", "mongodb-databases",
    "redis-info", "couchdb-databases", "couchdb-stats",
]
# Intrusive checks (brute / command execution) - only with --aggressive.
_DB_SCRIPTS_AGGR = [
    "mysql-vuln-cve2012-2122", "mysql-audit", "mysql-brute",
    "ms-sql-xp-cmdshell", "ms-sql-dump-hashes", "ms-sql-brute",
    "oracle-brute", "pgsql-brute",
]


def engine_for(port: Port) -> str | None:
    """Return the DB engine name for a port, or None if not a database."""
    if port.portid in DB_PORTS:
        return DB_PORTS[port.portid]
    blob = f"{port.service} {port.product}".lower()
    for hint, engine in _NAME_HINTS.items():
        if hint in blob:
            return engine
    return None


def is_db_port(port: Port) -> bool:
    return engine_for(port) is not None


def db_ports(host: Host) -> list[Port]:
    return [p for p in host.open_ports if is_db_port(p)]


def script_selection(aggressive: bool) -> list[str]:
    return _DB_SCRIPTS_SAFE + (_DB_SCRIPTS_AGGR if aggressive else [])


def _script_text(port: Port, prefix: str) -> str:
    for s in port.scripts:
        if s.id.startswith(prefix):
            return s.output
    return ""


def db_instances(hosts: list[Host]) -> list[dict]:
    """One row per database instance for the Databases report sheet."""
    rows = []
    for h in hosts:
        for p in db_ports(h):
            engine = engine_for(p)
            # Databases / users pulled from NSE output when present.
            dbs = re.findall(r"^\s*\|?\s*([\w$-]+)\s*$",
                             _script_text(p, "mysql-databases") or
                             _script_text(p, "mongodb-databases"), re.M)
            users = re.findall(r"([\w$@.-]+)",
                               _script_text(p, "mysql-users"))
            # Auth posture from findings on this port.
            auth = ""
            for v in h.vulns:
                if v.port == p.portid and "empty password" in v.title.lower():
                    auth = "EMPTY PASSWORD"
                elif v.port == p.portid and "unauthenticated" in v.title.lower():
                    auth = "UNAUTHENTICATED"
            findings = "; ".join(sorted({v.title for v in h.vulns
                                         if v.port == p.portid}))
            rows.append({
                "ip": h.ip, "hostname": h.hostname, "port": p.portid,
                "engine": engine, "version": (f"{p.product} {p.version}").strip(),
                "auth": auth,
                "databases": ", ".join(sorted(set(d for d in dbs
                                        if d.lower() not in ("database", "databases"))))[:200],
                "users": ", ".join(sorted(set(u for u in users if len(u) > 1)))[:200],
                "findings": findings,
                "vuln_scanned": p.vuln_scanned,
            })
    return rows
