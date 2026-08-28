"""Command handlers for the `scan` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_enum` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed

from .. import ad
from ..vuln import exploits
from ..core import parser as np
from ..core import scanner
from ..core import tracking as tr
from ..core.models import Host
from ..report.excel import read_workbook_edits, update_workbook
from ..report.markdown import build_csv, build_markdown
from ..core.store import Store, StoreError
from ..core.targets import expand_excludes, explicit_targets, ip_matcher, load_targets

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_enum', 'cmd_vulns', 'cmd_scan', 'cmd_run', 'cmd_sweep', 'cmd_credsweep', 'cmd_services']




def cmd_enum(args: argparse.Namespace) -> int:
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map, disc_reasons, hostname_map = _discover(
        args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    if getattr(args, "targets_up", False):
        seeded = _seed_targets(store, live_ips, subnet_map, hostname_map)
        print(f"[+] Authoritative list: pre-seeded {seeded} host(s) - every target is "
              "in the report even if its scan times out or fails.")
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map,
                    disc_reasons, hostname_map)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, args.title)
        store.close()
    print(f"\n[+] Enumeration done -> {paths['xlsx']}")
    _print_next(paths, args.output_dir, n=2)
    return 0




def cmd_vulns(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Vuln scan done -> open the Vulnerabilities / Exploitation tabs.")
    _print_next(paths, args.output_dir, n=2)
    return 0




def cmd_scan(args: argparse.Namespace) -> int:
    """Convenience: run enum then vulns in one shot."""
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map, disc_reasons, hostname_map = _discover(
        args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    if getattr(args, "targets_up", False):
        seeded = _seed_targets(store, live_ips, subnet_map, hostname_map)
        print(f"[+] Authoritative list: pre-seeded {seeded} host(s) - every target is "
              "in the report even if its scan times out or fails.")
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map,
                    disc_reasons, hostname_map)
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, args.title)
        store.close()
    if getattr(args, "deep", False):
        # One kickoff: continue straight into the full credential-free deep sweep over
        # everything enum just discovered (each module self-skips where nothing matches).
        print("\n[*] --deep: running the credential-free deep sweep across all "
              "discovered hosts ...")
        return _run_sweep(args, authenticated=False)
    print("\n[+] Done.")
    _print_next(paths, args.output_dir, n=2)
    return 0




def cmd_run(args: argparse.Namespace) -> int:
    """THE front door: discover -> enum -> vulns -> every applicable deep module
    (credential-free, each self-skipping where nothing matches) -> + the authenticated
    modules when creds are supplied -> report. One adaptive, resumable command instead of
    sequencing ~9 by hand. The surgical subcommands still exist for precision work.

    Built by coordinating the existing phases (`scan --deep` + `credsweep`), so there is no
    new scan logic here - just the streamlined path and ambient next-step guidance.

    Cross-command calls (`cmd_scan`, `_run_sweep`, `_print_next`, `_open_paths`)
    resolve through the `cli` package rather than the local module bindings so
    tests can monkey-patch them at the `cli.NAME` boundary."""
    import sys
    _cli = sys.modules[__package__]  # recce.cli
    args.deep = True                       # enum -> vulns -> credential-free deep sweep
    rc = _cli.cmd_scan(args)                # (prints the banner; reports deferred inside)
    if rc != 0:
        # cmd_scan bailed early (e.g. store setup failed); don't run the
        # authenticated sweep / next-steps against a half-set-up engagement.
        return rc
    if getattr(args, "username", None):
        print("\n[*] Credentials supplied - running the authenticated modules "
              "(SMB/AD/mssql matrix) ...")
        _cli._run_sweep(args, authenticated=True)
    paths = _cli._open_paths(args.output_dir)
    print("\n[+] run complete.")
    _cli._print_next(paths, args.output_dir, n=3)
    return rc


def cmd_sweep(args: argparse.Namespace) -> int:
    """Unauthenticated deep pass: run every applicable credential-free module
    (web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/
    kubernetes/mssql) in one shot after `enum`, instead of typing each by hand. Each
    self-skips when there's no matching service;
    the workbook is rebuilt once at the end. For the authenticated modules use
    `credsweep`."""
    return _run_sweep(args, authenticated=False)




def cmd_credsweep(args: argparse.Namespace) -> int:
    """Authenticated deep pass (needs -u/-p): run the credentialed modules in one shot
    - the netexec/impacket phase (`credenum`) plus the authenticated facets of
    `ldap` (kerberoast/AS-REP/accounts), `smb` (credentialed shares + write proof),
    `mssql` (access/privilege matrix) and `ftp`. Assumes you already ran `sweep` for
    the credential-free surface."""
    return _run_sweep(args, authenticated=True)


def cmd_services(args: argparse.Namespace) -> int:
    """Print the exact per-service enumeration command to run for every open port
    recce found - the bridge from the datastore to recce/scripts/. Answers 'what
    do I type next?' for each service."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from ..services import serviceenum

    print("Per-service enumeration - run these against the open ports recce found.")
    print("Safe by default (banners, versions, anon/null checks, TLS, NSE 'safe');")
    print("add -a to a command for the intrusive checks (brute / nikto / dir-bust).\n")
    total = 0
    unmapped: list[tuple[str, int, str]] = []
    for h in hosts:
        cmds = serviceenum.commands_for_host(h)
        um = serviceenum.unmapped_ports(h)
        if not cmds and not um:
            continue
        label = h.ip + (f"  ({h.hostname})" if h.hostname else "")
        roles = f"   [{', '.join(h.roles)}]" if h.roles else ""
        print(f"{label}{roles}")
        for port, svc, _script, cmd in cmds:
            print(f"  {port:<6}{svc:<14}{cmd}" + ("  -a" if args.aggressive else ""))
            total += 1
        for port, svc in um:
            unmapped.append((h.ip, port, svc))
        print()
    if total == 0:
        print("No enumerable open ports yet. Run `enum` (or `import`) first.")
        return 0
    print(f"{total} service command(s) across {len({h.ip for h in hosts})} host(s).")
    raw_glob = os.path.join(args.output_dir, "raw", "*.xml")
    print("Or sweep every open port in one go from recce's own scans:")
    print(f"  {serviceenum.DRIVER} from-nmap {raw_glob}"
          + ("  -a" if args.aggressive else ""))
    if unmapped:
        print(f"\n{len(unmapped)} open port(s) have no dedicated script - "
              f"enumerate manually:")
        for ip, port, svc in unmapped[:15]:
            print(f"  {ip}:{port} ({svc or '?'})  ->  nmap -sV --script vuln -p {port} {ip}")
        if len(unmapped) > 15:
            print(f"  ... and {len(unmapped) - 15} more")
    return 0
