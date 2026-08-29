"""Two DB-specific gaps the audit named: PostgreSQL legacy large-object file
read (lo_import) and MySQL server-side @@local_infile.

Both tests drive the findings() emit-chain with synthetic probe dicts so the
finding logic is validated in isolation from wire code; the wire-level probe
changes are covered by the pre-existing engine tests exercising the shared
_simple_query / MySQL SHOW VARIABLES flows.
"""
from __future__ import annotations

from recce.core.models import Host, Port
from recce.services.db import mysql, postgres


# --- PostgreSQL lo_import / lo_export ---------------------------------------

def _pg_host():
    return Host(ip="10.0.0.5",
                ports=[Port(portid=5432, state="open", service="postgres")])


def test_pg_lo_import_fires_without_pg_read_server_files_role():
    """The point of the finding: lo_import is reachable via SELECT on
    pg_largeobject alone — no pg_read_server_files role required, so it
    surfaces on pre-10 clusters (or upgraded ones) where the modern role gate
    would say clean."""
    pr = {("10.0.0.5", 5432): {"reachable": True, "unauth": True,
          "loot": {"current_user": "app", "is_superuser": False,
                   "can_read_files": False, "can_copy_program": False,
                   "lo_select_pg_largeobject": True,
                   "lo_import_exec": True, "lo_export_exec": False}}}
    fs = postgres.findings([_pg_host()], pr)
    lo = [f for f in fs if f["kind"] == "pg_lo_file_read"]
    assert len(lo) == 1
    f = lo[0]
    assert f["severity"] == "high"
    assert "pg_largeobject" in f["detail"]
    assert "pg_read_server_files role" in f["detail"] or "role" in f["detail"]


def test_pg_lo_export_bumps_to_read_plus_write_wording():
    """When lo_export is also EXECUTE-able, the same finding must call out
    the WRITE half — the operator's remediation and impact differ."""
    pr = {("10.0.0.5", 5432): {"reachable": True, "unauth": True,
          "loot": {"lo_select_pg_largeobject": True,
                   "lo_import_exec": True, "lo_export_exec": True}}}
    f = next(x for x in postgres.findings([_pg_host()], pr)
             if x["kind"] == "pg_lo_file_read")
    assert "WRITE" in f["detail"] or "write" in f["detail"]


def test_pg_no_lo_privs_emits_nothing():
    pr = {("10.0.0.5", 5432): {"reachable": True, "unauth": True,
          "loot": {"lo_select_pg_largeobject": False, "lo_import_exec": False}}}
    assert not any(f["kind"] == "pg_lo_file_read"
                   for f in postgres.findings([_pg_host()], pr))


# --- MySQL @@local_infile ---------------------------------------------------

def _mysql_host():
    return Host(ip="10.0.0.6",
                ports=[Port(portid=3306, state="open", service="mysql")])


def test_mysql_local_infile_on_fires_medium_and_names_the_rogue_server_attack():
    """@@local_infile is the SERVER-side toggle that consents to LOAD DATA
    LOCAL. It reads files off the APP HOST, not the DB — that framing must be
    in the finding so a report reader does not conflate it with FILE-priv."""
    pr = {("10.0.0.6", 3306): {"reachable": True, "cred_access": True,
          "cred_user": "app",
          "loot": {"local_infile": True, "file_priv": False,
                   "current_user": "app@%"}}}
    fs = mysql.findings([_mysql_host()], pr)
    li = [f for f in fs if f["kind"] == "mysql_local_infile"]
    assert len(li) == 1
    f = li[0]
    assert f["severity"] == "medium"
    assert "APP HOST" in f["detail"] or "app" in f["detail"].lower()
    assert "rogue" in f["command"].lower() or "LOAD DATA LOCAL" in f["command"]


def test_mysql_8x_default_off_produces_no_finding():
    """MySQL 8.0 defaulted @@local_infile to OFF; when the probe reports off,
    the finding must not fire — the whole exposure hinges on the server's
    consent."""
    pr = {("10.0.0.6", 3306): {"reachable": True, "cred_access": True,
          "cred_user": "root", "loot": {"local_infile": False}}}
    assert not any(f["kind"] == "mysql_local_infile"
                   for f in mysql.findings([_mysql_host()], pr))
