"""Shared shape for every DB engine module + a handful of common helpers.

The 12 engines here (mysql, postgres, mssql, mongodb, oracle, db2, redis,
memcached, cassandra, couchdb, elasticsearch, influxdb) all expose the
same contract — same function names, same signatures — because a single
dispatch layer in cli/scanner code walks that contract. This module codifies
it as a `DbEngine` typing.Protocol so future engines have a template and
misspellings surface at type-check time.

It also hosts the few helpers that were duplicated across engines:
  - recvn: read N bytes off a socket (the mysql/postgres wire flavor)
  - cred_list: normalize analyze() creds into [(user, pw), ...] tuples
  - finding: the {severity,title,target,detail,tool,command,remediation,cwes,kind}
             dict factory every engine produces
"""
from __future__ import annotations

import socket
from typing import Any, Protocol, runtime_checkable

from ...core.models import Host, Port


# --- constants ---------------------------------------------------------------
DEFAULT_TIMEOUT = 6.0


# --- shared low-level helpers ------------------------------------------------
def recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes off sock (mysql/postgres wire style). Raises on
    a socket error; returns a short buffer on EOF so callers can detect it."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def cred_list(creds: Any) -> list[tuple]:
    """Normalize analyze()'s `creds` arg (a single dict, or a list of them)
    into [(user, password), ...]. Accepts username/user + password/secret
    keys. Deduplicates. Silently drops entries missing either field.
    """
    if not creds:
        return []
    if isinstance(creds, dict):
        creds = [creds]
    out, seen = [], set()
    for c in creds:
        if not isinstance(c, dict):
            continue
        u = c.get("username") or c.get("user")
        pw = c.get("password") if c.get("password") is not None else c.get("secret")
        if u and pw is not None and (u, pw) not in seen:
            seen.add((u, pw))
            out.append((u, pw))
    return out


def finding(tool: str, sev: str, title: str, target: str, detail: str,
            cmd: str, rem: str, cwes: list, kind: str = "") -> dict:
    """The common finding dict every engine emits. Consumed by the engine's
    own `findings_to_vulns()` and by svccommon.finding_builder."""
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind}


# --- engine contract ---------------------------------------------------------
@runtime_checkable
class DbEngine(Protocol):
    """The shape every services/db/<engine>.py module conforms to.

    A caller (cli.cmd_db, cli.cmd_credenum, the workbook builder) picks
    the module by dispatch and calls these functions. Only the DISPATCHED
    surface is required; each engine also has read-only probes / auth /
    loot / datamine functions used internally, but their names vary
    (probe / probe_target / probe_creds), so they're not part of the
    Protocol.

    Required (walked by tests/test_db_engine_contract.py):
      analyze(hosts, creds=None, active=True) -> dict
      findings(hosts, probes=None) -> list[dict]
      findings_to_vulns(fs) -> dict
    """

    def analyze(self, hosts: list[Host], creds: Any = None,
                active: bool = True) -> dict:
        """Top-level entry. Runs probes across every matching port on
        every host, folds probe data into findings, returns a structured
        analysis blob the workbook consumes."""
        ...

    def findings(self, hosts: list[Host], probes: dict | None = None) -> list[dict]:
        """Derive finding dicts (see `finding()`) from probe data +
        already-recorded host state (open ports, product/version)."""
        ...

    def findings_to_vulns(self, fs: list[dict]) -> dict:
        """Wrap engine findings as recce Vuln objects, indexed by target
        so svccommon.finding_builder can fold them into per-host state."""
        ...
