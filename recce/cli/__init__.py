"""Command-line entrypoint for recce.

Subcommands (see `recce -h` for the full, authoritative list):
  Scan/enumerate  enum, scan, vulns, db, privesc, credenum, services
  Import/ingest   import (nmap -oX/-oG/-oN), ingest (on-target loot)
  Post-exploit    exploitplan, attackpath, creds, deploy (mass local-enum)
  Report/track    report, status, review, writeups, writeup
  Utility         demo (bundled sample, no network), doctor (self-test)
"""

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
from .. import exploits
from .. import parser as np
from .. import scanner
from .helpers import *  # noqa: F401,F403 — private-helper re-export
from .parser import (  # noqa: F401 — some re-exported for callers
    build_arg_parser, _print_quickstart, _setup_proxy,
)
from .. import tracking as tr
from ..models import Host
from ..report_excel import read_workbook_edits, update_workbook
from ..report_markdown import build_csv, build_markdown
from ..store import Store, StoreError
from ..targets import expand_excludes, explicit_targets, ip_matcher, load_targets

BANNER = r"""
  ____  _____ ____ ____ _____
 |  _ \| ____/ ___/ ___| ____|
 | |_) |  _|| |  | |   |  _|
 |  _ <| |__| |__| |___| |___
 |_| \_\_____\____\____|_____|
   recon & coverage tracker for airgapped pentests
"""

# Canonical severity ordering for sorting findings worst-first (shared by every
# finding-fold path: the deep-service commands and the AD/bloodhound merge).
# The host-timeout auto-retry (a slow truncated host gets one more, longer pass)
# doubles the host-timeout - but capped, so it can't turn a 20-minute default into a
# 40-minute-per-host runaway on a dead/very-slow target. A small timeout still gets a
# real bump up to this floor; a host-timeout already >= this never grows on retry.
# A fast sweep that returns fewer than this many open ports on a non-reliable pass is
# treated as possibly under-reported (a lossy firewall silently dropping SYNs) and gets
def cmd_next(args: argparse.Namespace) -> int:
    """Print the ranked next-best-actions for an engagement — the ambient 'you are here,
    do this next' so the tester never has to remember which of the subcommands comes next."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No engagement at {args.output_dir}. Start one:  recce run <targets> "
              f"-o {args.output_dir}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    from .. import workflow
    acts = workflow.next_actions(store.all_hosts(), store.all_credentials(), args.output_dir)
    store.close()
    if not acts:
        print("Nothing outstanding — review the report / write-ups.")
        return 0
    print("\nNext best actions:\n")
    for a in acts[:5]:
        print(f"  {a.command}")
        print(f"      · {a.label} — {a.why}")
    print()
    return 0


def cmd_act(args: argparse.Namespace) -> int:
    """The Act phase: 'I found things - what do I DO?'. Classifies every finding into
    an action archetype (loot / crack / spray / exploit / escalate / pivot), ranks the
    cards by tier (readiness × safety × confidence) then impact × confidence × leverage,
    and prints the guided plan. Read-only/reversible actions are flagged as ones recce
    can run for you; intrusive ones are guided (exact command), never auto-fired."""
    from .. import act
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No engagement at {args.output_dir}. Start one:  recce run <targets> "
              f"-o {args.output_dir}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    print(BANNER)
    # --run: auto-execute the read-only/reversible links (loot flagged unauth services,
    # regenerate the spray plan) and feed the yields back, before printing the plan.
    if getattr(args, "run", False):
        print("[*] Act --run: executing read-only loot + regenerating the spray plan "
              "(intrusive actions are never auto-run) ...")
        summary = act.execute_auto(store, args.output_dir)
        looted = summary["looted"]
        if looted:
            print(f"[+] Looted {len(looted)} new credential(s) over {summary['passes']} "
                  "pass(es):")
            for c in looted[:20]:
                print(f"      {c.label}  [{c.kind} · {c.source}]")
        else:
            print("[i] No new credentials to loot (already captured, or none reachable).")
        if summary.get("spray", {}).get("files"):
            print("[+] Spray plan refreshed: "
                  + ", ".join(sorted(summary['spray']['files'])) + f"  (in {summary['spray'].get('dir', args.output_dir)})")

    hosts = _selected_hosts(store.all_hosts(), args)
    cards = act.action_plan(hosts, store.all_credentials(), args.output_dir)
    store.close()
    only = getattr(args, "only", None)
    if only:
        cards = [c for c in cards if c.archetype == only]
    # Lead with the single highest-value moves across every tier, so a time-boxed
    # operator sees the instant-DA exploit up top, not buried under read-only loot.
    if not only:
        highlights = act.top_moves(cards, n=3)
        if highlights:
            print("\n*** TOP PRIORITIES (highest impact you can act on now) ***")
            for c in highlights:
                where = "" if c.target == "engagement" else f" @ {c.target}"
                print(f"  {c.score:6.1f}  [{c.archetype}] {c.title}{where}  ->  {c.yields}")
                print(f"          $ {c.command}")
    print("\nFull action plan — grouped by what recce can run vs. what you drive:")
    for line in act.format_plan(cards, top=getattr(args, "top", 0) or 0):
        print(line)
    print()
    if not getattr(args, "run", False) and any(c.tier == act.AUTO for c in cards):
        print("[i] The read-only/reversible items above are ones recce can run for you: "
              "`recce act --run -o " + args.output_dir + "` loots + builds the spray plan.")
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    """Engagement-wide MITRE ATT&CK coverage: the techniques recce's findings map to,
    grouped by tactic along the kill chain. For client reports that want ATT&CK, not
    just CVEs/CWEs."""
    from .. import attack
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No engagement at {args.output_dir}. Run `recce run <targets>` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    cov = attack.coverage(_selected_hosts(store.all_hosts(), args))
    store.close()
    print(BANNER)
    if not cov["by_tactic"]:
        print("No findings map to an ATT&CK technique yet — enumerate first.")
        return 0
    print(f"MITRE ATT&CK coverage — {cov['technique_count']} technique(s) across "
          f"{cov['tactic_count']} tactic(s):\n")
    for tactic, techs in cov["by_tactic"].items():
        print(f"  {tactic}  ({attack.TACTICS.get(tactic, '')})")
        for t in techs:
            hosts = ", ".join(t["hosts"][:6]) + (" …" if len(t["hosts"]) > 6 else "")
            print(f"      {t['id']:<11} {t['name']:<44} {len(t['hosts'])} host(s): {hosts}")
        print()
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Active verification (verify-don't-infer): confirm or refute version-inference LEADS by
    running the SAFE (Tier-A/B) NSE check each one names, then re-correlating.

    Dry-run by default (prints the plan, sends nothing). `--run` executes the safe re-checks;
    the results fold into the store and the normal pipeline promotes a confirmed lead
    (NSE VULNERABLE -> CONFIRMED) or refutes a disproved one (NOT VULNERABLE, hidden by
    default). Only Tier-A/B (read-only / non-intrusive detection) - never a weaponizing PoC.
    See docs/design/ACTIVE-VERIFICATION.md."""
    from .. import verify, qod
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No engagement at {args.output_dir}. Run `recce run <targets> -o "
              f"{args.output_dir}` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    hosts = store.all_hosts()
    for h in hosts:
        qod.annotate(h)
    pending = [p for h in hosts for p in verify.confirm_plan(h) if not p["ran"]]
    if not pending:
        store.close()
        print("[*] Nothing to verify: no unconfirmed lead maps to a safe re-check "
              "(already checked, or no registry rule). See `recce next`.")
        return 0

    if not getattr(args, "run", False):
        print(f"[*] {len(pending)} lead(s) can be settled with a safe re-check "
              "(dry run - nothing sent):\n")
        for p in pending:
            tgt = f"{p['ip']}:{p['port']}" if p['port'] else p['ip']
            print(f"  {tgt}  {p['finding']}  [{p['cve']}]  (tier {p['tier']})")
            print(f"      {p['command']}")
        print(f"\n  Run them:  recce verify --run -o {args.output_dir}")
        store.close()
        return 0

    print(BANNER)
    print(f"[*] Verifying {len(pending)} lead(s) with safe (Tier-A/B) re-checks ...")
    profile = scanner.ScanProfile()
    by_host: dict[str, tuple] = {}
    for p in pending:
        ports, scripts = by_host.setdefault(p["ip"], (set(), set()))
        if p["port"]:
            ports.add(int(p["port"]))
        scripts.add(p["check"])
    n = 0
    for ip, (ports, scripts) in by_host.items():
        store.clear_issues(ip, "verify")
        xml = os.path.join(paths["raw"], f"{ip}_verify.xml")
        _, iss = scanner.nse_scan(ip, sorted(ports), xml, profile, sorted(scripts))
        if iss:
            _record_issues(store, paths, ip, [_mkissue(iss, "verify")])
        for ph in np.parse_nmap_xml(xml):
            if ph.ip == ip:
                store.upsert_host(ph, merge=True)   # folds the NSE result into the host
                n += 1
    print(f"[+] Re-checked {n} host(s); folding results and regenerating the report ...")
    _final_report(store, paths, store.get_meta("engagement") or args.title)
    store.close()
    _print_next(paths, args.output_dir, n=2)
    return 0


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
    new scan logic here - just the streamlined path and ambient next-step guidance."""
    args.deep = True                       # enum -> vulns -> credential-free deep sweep
    rc = cmd_scan(args)                     # (prints the banner; reports deferred inside)
    if rc != 0:
        # cmd_scan bailed early (e.g. store setup failed); don't run the
        # authenticated sweep / next-steps against a half-set-up engagement.
        return rc
    if getattr(args, "username", None):
        print("\n[*] Credentials supplied - running the authenticated modules "
              "(SMB/AD/mssql matrix) ...")
        _run_sweep(args, authenticated=True)
    paths = _open_paths(args.output_dir)
    print("\n[+] run complete.")
    _print_next(paths, args.output_dir, n=3)
    return rc
# The credential-free deep pass: recce's own stdlib probes. Order is foothold-ish -
# web + protocol posture first, then the heavier service dives. Each no-ops cleanly
# when the datastore has no matching host.
# The authenticated pass: the modules that DO something new once you have creds -
# the netexec/impacket phase plus the authenticated facets of the deep modules. The
# unauth-only modules (web/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/
# k8s) are intentionally absent; you run `sweep` for those. Each handler here keys its
# authenticated path off args.username.
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


def cmd_privesc(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        if args.scan:
            # _phase_privesc already set privesc_checked in the worker and cleared the
            # override via clear_step - no second full pass over every host needed.
            _phase_privesc(store, paths, args, profile)
        else:
            print("[*] Generating priv-esc playbook from existing data "
                  "(use --scan to also run remote privesc NSE checks).")
            # No worker ran, so mark the step + clear the override for selected hosts here.
            for h in _selected_hosts(store.all_hosts(), args):
                if not h.privesc_checked:
                    h.privesc_checked = True
                    store.upsert_host(h)
                store.delete_tracking(tr.step_key("privesc", h.ip))
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Priv-esc sheet updated.")
    return 0


def cmd_credenum(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    _, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_credenum(store, paths, args)
        # Note: the manual 'Creds' checklist box is the operator's own sign-off,
        # so credenum records findings but never ticks it automatically.
    except KeyboardInterrupt:
        print("\n[!] Interrupted - results collected so far are saved.")
        _recovery_hint(args.output_dir)
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Credentialed enum complete - see Users & Accounts / Vulnerabilities.")
    return 0


def cmd_writeups(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)   # honour any Excel edits first
    hosts = _selected_hosts(store.all_hosts(), args)
    out_dir = os.path.join(args.output_dir, "writeups")
    from ..report_docx import build_writeups
    from .. import screenshot

    shots: dict = {}
    if not args.no_screenshots and not screenshot.available():
        print("[!] No headless browser found; skipping auto-screenshots (add them "
              "by hand in Word). Install firefox or chromium to enable them.")
    elif not args.no_screenshots:
        web_hosts = [h for h in hosts
                     if any(screenshot._web_url(p) for p in h.open_ports)]
        if web_hosts:
            print(f"[*] Capturing web screenshots for {len(web_hosts)} host(s) "
                  f"(headless browser) ...")
            for h in web_hosts:
                grabbed = screenshot.capture_for_host(h)
                if grabbed:
                    shots[h.ip] = grabbed
                    print(f"    [+] {h.ip}: {len(grabbed)} screenshot(s)")
    summary = build_writeups(hosts, out_dir, min_severity=args.min_severity,
                             include_potential=args.include_potential,
                             screenshots=shots, overwrite=args.overwrite)
    title = store.get_meta("engagement") or args.title
    combined_path = None
    if not args.no_combined:
        from ..report_docx import build_combined
        combined_path = os.path.join(out_dir, "findings_report.docx")
        build_combined(hosts, combined_path, title=f"{title} - Findings Report",
                       min_severity=args.min_severity,
                       include_potential=args.include_potential, screenshots=shots)
    store.close()
    scope = "all" if args.include_potential else "real"
    print(f"\n[+] Finding write-ups: {len(summary['written'])} generated, "
          f"{len(summary['skipped'])} kept (already edited), "
          f"{summary['total']} {scope} finding(s) total.")
    print(f"    -> {out_dir}/  (open each .docx in Word to finish it)")
    if combined_path:
        print(f"[+] Combined report (summary table + all findings): {combined_path}")
    if summary.get("dropped_potential"):
        print(f"    ({summary['dropped_potential']} low-confidence 'potential' "
              f"finding(s) skipped; add --include-potential to write them up too)")
    if summary["skipped"]:
        print("    (use --overwrite to regenerate the kept ones - loses edits)")
    return 0


def cmd_writeup(args: argparse.Namespace) -> int:
    """Write up a SINGLE finding, pre-filled with looted/obtained evidence. With
    no selector, list the findings so the tester can pick one."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = store.all_hosts()
    from ..report_docx import list_findings, build_one_writeup

    if not args.selector:
        findings = list_findings(hosts, min_severity="info")
        if not findings:
            print("[!] No findings yet. Run `vulns` (or `import`/`ingest`) first.")
            store.close()
            return 0
        print(f"Findings ({len(findings)}) - pick one:  recce writeup <id|CVE|IP|word> "
              f"-o {args.output_dir}\n")
        for row in findings:
            tag = "" if row["real"] else "  (potential)"
            aff = ", ".join(row["affected"][:4]) + ("..." if len(row["affected"]) > 4 else "")
            cve = f"  {row['cves'][0]}" if row["cves"] else ""
            print(f"  {row['id']}  {row['severity'].upper():<8} {row['title']}{cve}")
            print(f"          affected: {aff}{tag}")
        store.close()
        return 0

    out_dir = os.path.join(args.output_dir, "writeups")
    shots: dict = {}
    if not args.no_screenshots:
        from .. import screenshot
        if screenshot.available():
            res = _match_one_host(hosts, args.selector)
            for h in res:
                grabbed = screenshot.capture_for_host(h)
                if grabbed:
                    shots[h.ip] = grabbed
    result = build_one_writeup(hosts, out_dir, args.selector,
                               screenshots=shots, overwrite=args.overwrite)
    store.close()
    if result["written"]:
        m = result["matched"][0]
        print(f"[+] Wrote {m['id']} ({m['severity'].upper()}): {m['title']}")
        print(f"    -> {result['written']}")
        if result.get("looted"):
            print(f"    pre-filled with {result['looted']} looted/obtained item(s) "
                  f"for the affected host(s).")
        if not result.get("real", True):
            print("    note: this is a low-confidence 'potential' (version-inferred) finding.")
        print("    Open it in Word to finish the narrative, impact, and screenshots.")
        return 0
    # No single match: help the tester narrow it.
    if result["reason"] == "exists":
        print(f"[!] Write-up already exists: {result['path']}")
        print("    Use --overwrite to regenerate it (loses any edits).")
        return 0
    cand = result["matched"]
    if not cand:
        print(f"[x] No finding matches '{args.selector}'. "
              f"Run `recce writeup -o {args.output_dir}` to list them.")
        return 1
    print(f"[!] '{args.selector}' matches {len(cand)} findings - be more specific:")
    for m in cand:
        print(f"    {m['id']}  {m['severity'].upper():<8} {m['title']}  "
              f"[{', '.join(m['affected'][:3])}]")
    return 1
def cmd_web(args: argparse.Namespace) -> int:
    """Deep-enumerate every web-facing endpoint: fingerprint the stack and run the
    non-intrusive checks (exposed .git/.env, server-status/actuator, directory
    listing, dangerous methods, cookie flags, headers/TLS). Findings fold into the
    workbook; each endpoint gets the exact Kali deep-scan commands."""
    from .. import web
    print(BANNER)
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    active = not getattr(args, "no_active", False)
    # The two side-effecting proofs are meaningless passively - they force active mode.
    if getattr(args, "upload_shell", False) or getattr(args, "smuggle", False):
        active = True
    # Optional authenticated scan: --cookie and/or repeated --header "K: V".
    auth: dict = {}
    if getattr(args, "cookie", None):
        auth["Cookie"] = args.cookie
    for hv in getattr(args, "header", None) or []:
        if ":" in hv:
            k, v = hv.split(":", 1)
            auth[k.strip()] = v.strip()
    auth = auth or None
    targets = [h for h in hosts if any(web.is_web(p) for p in h.open_ports)]
    if not targets:
        print("[!] No HTTP/HTTPS endpoints found. Run `enum` (services) first.")
        store.close()
        return 0
    workers = max(1, getattr(args, "workers", 6))
    n_ep = sum(1 for h in targets for p in h.open_ports if web.is_web(p))
    print(f"[*] Web-scanning {n_ep} endpoint(s) on {len(targets)} host(s) "
          f"with {workers} worker(s){'' if active else ' (passive)'}"
          f"{' (authenticated)' if auth else ''} ...")
    total_findings = 0
    creds = getattr(args, "creds", False)
    do_crawl = getattr(args, "crawl", False)
    sqli_time = getattr(args, "sqli_time", False)
    fuzz_risky = getattr(args, "fuzz_risky_forms", False)
    upload_shell = getattr(args, "upload_shell", False)
    smuggle = getattr(args, "smuggle", False)
    # Authenticated crawl: auto-login with the engagement's harvested credentials.
    autologin = getattr(args, "autologin", False) and not auth
    login_creds = _web_login_creds(args, store) if autologin else []

    def _scan(h):
        h_auth = auth
        if autologin and login_creds:
            sess = web.autologin(h, login_creds, active=active)
            if sess:
                h_auth = sess["auth"]
                h.vulns.append(web._mk(
                    h.ip, next(p for p in h.open_ports if p.portid == sess["port"]),
                    "web-auth-session", "high",
                    "Authenticated web session obtained with a harvested credential",
                    ["CWE-522", "CWE-287"],
                    f"A login form accepted the harvested credential '{sess['user']}' - "
                    "recce scanned the AUTHENTICATED attack surface (post-login pages, "
                    "forms and APIs) with the resulting session.",
                    "Rotate the credential; enforce MFA; monitor for credential reuse.",
                    confidence="confirmed"))
                print(f"    [{h.ip}] auto-login OK as '{sess['user']}' -> authenticated scan")
        profiles = web.scan_host(h, active, h_auth, creds,
                                 upload_shell=upload_shell, smuggle=smuggle)
        if do_crawl:
            pages, added = web.scan_crawl(h, h_auth, time_based=sqli_time,
                                          fuzz_risky=fuzz_risky)
            print(f"    [{h.ip}] crawled {pages} page(s), +{added} finding(s)")
        return profiles

    budget = getattr(args, "budget", None)
    started = time.monotonic()
    stopped_budget = False
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan, h): h for h in targets}
        for fut in as_completed(futures):
            # Wall-clock budget: stop scheduling more hosts (in-flight ones finish and
            # are persisted per host below, so partial coverage is kept).
            if budget is not None and not stopped_budget \
                    and time.monotonic() - started > budget:
                stopped_budget = True
                for pending in futures:
                    pending.cancel()
            h = futures[fut]
            try:
                profiles = fut.result()
            except CancelledError:
                continue
            except Exception as e:  # noqa: BLE001 - one host never aborts the sweep
                _record_issues(store, paths, h.ip, [{"phase": "web", "level": "warning",
                               "message": f"web scan failed: {e}"}])
                continue
            # clear_step so a re-run clears a stale manual "web" tick, matching
            # enum/vuln/db/privesc (previously the web override never self-healed).
            _persist_host(store, paths, h.ip, "web", h, clear_step="web")
            for pr in profiles:
                tech = f"  [{', '.join(pr['tech'])}]" if pr["tech"] else ""
                wv = sum(1 for v in h.vulns if v.port == pr["port"] and v.source == "web")
                total_findings += wv
                looted = 0
                for c in pr.get("credentials", []):
                    if store.add_credential(c):
                        looted += 1
                if looted:
                    print(f"    [+] looted {looted} cleartext credential(s) from "
                          f"{pr['url']} -> credential store (spray with `recce creds`)")
                print(f"    {pr['url']:<28} {pr.get('server', '') or '?':<20}"
                      f"{tech}  ({wv} finding(s))")
    if stopped_budget:
        print("    [!] Time budget (--budget) reached - stopped scheduling more hosts; "
              "results scanned so far were saved.")
    _final_report(store, paths, store.get_meta("engagement") or args.title)
    store.close()
    if getattr(args, "screenshots", False):
        _web_screenshots(targets, args.output_dir)
    print(f"\n[+] {total_findings} web finding(s) folded in. See the Web tab (endpoints "
          f"+ Kali deep-scan commands) and Vulnerabilities/Verification in "
          f"{paths['xlsx']}.")
    print("    Prove them: recce prove -o " + args.output_dir)
    return 0
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
    from .. import serviceenum

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
def cmd_poc(args: argparse.Namespace) -> int:
    """Assemble a per-CVE PoC dossier + Python harness skeleton from recce's OFFLINE
    intel (vulndb + KEV/EPSS + the local Exploit-DB + msf refs + build recipes), for the
    hosts affected in this engagement. With CVE args it targets exactly those; otherwise
    it uses the CVEs from the engagement's findings (`--confirmed` to gate to confirmed
    ones only). recce references published exploits and scaffolds a harness; it does not
    author weaponized exploit code."""
    from .. import pocgen
    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    hosts = store.all_hosts()
    if args.cves:
        cves, bad = [], []
        for c in args.cves:
            (cves if pocgen.valid_cve(c) else bad).append(c.upper())
        for b in bad:
            print(f"[!] skipping {b!r} - not a CVE id (expected CVE-YYYY-NNNN)")
    else:
        cves = _cves_from_findings(hosts, confirmed_only=args.confirmed)
    cves = sorted(set(cves))
    if not cves:
        if args.cves:                    # args were supplied but every one was rejected above
            print("[x] None of those look like CVE ids (expected CVE-YYYY-NNNN).")
        else:
            print("[x] No CVEs to build. Pass CVE ids (recce poc CVE-2021-44228 …) or run "
                  "enum/vulns first so findings carry CVEs" +
                  (" (none are CONFIRMED - drop --confirmed to include all)." if args.confirmed else "."))
        return 1
    if not exploits.available():
        print("[!] searchsploit not found - dossiers will omit Exploit-DB references "
              "(install exploitdb, or build the airgap bundle with RECCE_WITH_SEARCHSPLOIT=1).")
    results = pocgen.generate(cves, hosts, args.output_dir, with_exploits=args.with_exploits)
    outdir = os.path.join(args.output_dir, "poc")
    print(f"[+] Wrote {len(results)} PoC dossier(s) -> {outdir}/")
    for r in results:
        tags = []
        if r["kev"]:
            tags.append("🔥KEV")
        if r["epss"]:
            tags.append(f"EPSS {round(r['epss'] * 100)}%")
        if r["edb"]:
            tags.append(f"{r['edb']} EDB")
        if r["msf"]:
            tags.append("msf")
        if r["recipe"]:
            tags.append(f"recipe:{r['recipe']}")
        if r["exploits_copied"]:
            tags.append(f"+{r['exploits_copied']} exploit file(s)")
        aff = f"{r['affected']} host(s)" if r["affected"] else "not seen here"
        print(f"    {r['cve']:<18} {aff:<14} {'  '.join(tags)}")
    print("    Each dir has <CVE>.md (the dossier) + poc.py (the harness scaffold). "
          "Authorized testing only.")
    return 0


def cmd_exploitplan(args: argparse.Namespace) -> int:
    """Generate a per-finding exploitation PLAN: ready-to-run artifacts that drive
    EXISTING published tools/modules with the discovered parameters filled in.
    Confirmed findings only; safe by default (msf launch lines commented)."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from .. import exploitplan

    summary = exploitplan.build_plan(hosts, args.output_dir, lhost=args.lhost,
                                     lport=args.lport, run=args.run)
    if not summary["plans"]:
        print("[!] No confirmed findings map to a published exploit/tool yet.")
        print("    Plans cover CONFIRMED findings only (not 'potential' version "
              "guesses). Run `vulns` for deeper detection, or `ingest` on-target loot.")
        return 0
    print(f"[+] Exploitation plan -> {summary['dir']}/")
    print(f"    {summary['host_scripts']} per-host plan script(s), "
          f"{summary['rc_files']} Metasploit resource (.rc) file(s), "
          f"{summary.get('poc_files', 0)} PoC source file(s), "
          f"{summary['actions']} action(s) across {len(summary['plans'])} host(s).")
    print("    Each artifact configures an EXISTING published tool/module with the")
    print("    target's own parameters. PoC sources build a proof (marker file /")
    print("    throwaway account) - swap the ACTION for your ROE command.")
    if args.lhost == "<LHOST>":
        print("    ! Set your callback with --lhost <IP> (payloads currently show "
              "<LHOST>).")
    if args.run:
        print("    ! --run: Metasploit launch lines are ARMED. Rules of engagement only.")
    else:
        print("    Safe mode: .rc files run `check` only; edit them (or use --run) "
              "to launch.")
    print(f"    Review:  cat {summary['dir']}/README.txt")
    return 0
def cmd_prove(args: argparse.Namespace) -> int:
    """Prove out flagged findings: for the noisy types (ActiveMQ / SMB / MS17-010 /
    SeImpersonate / …) render a verdict - CONFIRMED, LIKELY, FALSE POSITIVE or
    INCONCLUSIVE - from the evidence recce already holds, plus the exact safe step
    to finish proving. Nothing here exploits anything."""
    from .. import proofs
    print(BANNER)
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    if getattr(args, "run", False):
        _prove_run_safe_checks(store, paths, hosts, args)
        hosts = _selected_hosts(store.all_hosts(), args)      # reload merged results
    results = proofs.verify_hosts(hosts)
    if not results:
        print("[!] No proof-able findings matched (ActiveMQ / SMB signing / MS17-010 / "
              "SeImpersonate / null-session / anon-FTP / weak-TLS).")
        store.close()
        return 0
    icon = {proofs.CONFIRMED: "[+]", proofs.LIKELY: "[~]",
            proofs.INCONCLUSIVE: "[?]", proofs.FALSE_POSITIVE: "[x]"}
    for r in results:
        print(f"\n  {icon.get(r['verdict'], '[?]')} {r['verdict']}  "
              f"{r['ip']}:{r['port'] or '-'}  {r['vuln']}")
        for e in r["evidence"]:
            print(f"        - {e}")
        if r["verdict"] in (proofs.CONFIRMED, proofs.LIKELY):
            print(f"        finish: {r['finish']}")
    c = proofs.summary(results)
    print(f"\n[+] {c[proofs.CONFIRMED]} confirmed · {c[proofs.LIKELY]} likely · "
          f"{c[proofs.INCONCLUSIVE]} inconclusive · {c[proofs.FALSE_POSITIVE]} false positive.")
    _final_report(store, paths, store.get_meta("engagement") or args.title)
    store.close()
    print(f"    Full detail on the Verification tab in {paths['xlsx']}.")
    return 0


def cmd_attackpath(args: argparse.Namespace) -> int:
    """Chain the confirmed findings into a prioritised attack path (foothold ->
    priv-esc -> creds -> lateral -> domain), grounded in what recce found."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from .. import attackpath as ap

    steps = ap.build(hosts)
    for line in ap.narrative(hosts, steps):
        print(line)
    if not steps:
        return 0
    print()
    cur = None
    for s in steps:
        if s["stage"] != cur:
            cur = s["stage"]
            print(f"== {cur} ==")
        tgt = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
        print(f"  [{tgt}] {s['title']}")
        print(f"       {s['tool']}:  {s['cmd']}")
    # Graph artifacts - Mermaid (paste anywhere) + Graphviz DOT (render to PNG).
    svg_path = os.path.join(args.output_dir, "attack-path.svg")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
        svg = ap.svg(hosts, steps).replace(
            "<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
        with open(svg_path, "w", encoding="utf-8") as fh:
            fh.write(svg)
        print(f"\n  Diagram: {svg_path}  (open in any browser — no tools, prints to PDF)")
    except OSError as exc:
        print(f"  [!] Could not write the diagram: {exc}")
    print("\n  Full table on the Attack Path sheet; runnable artifacts via "
          "`recce exploitplan`.")
    return 0
def cmd_creds(args: argparse.Namespace) -> int:
    """Stack credentials (auto-harvested + manually captured) and build/run a spray
    across the discovered SMB/WinRM/LDAP/MSSQL/RDP/SSH surface."""
    from .. import credentials as cr
    from ..models import Credential
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1

    # ADD captured credentials.
    added = False
    to_add = []
    for spec in (args.add or []):
        to_add.append(_parse_cred_spec(spec))
    if args.user:
        kind = "nthash" if args.hash else ("password" if getattr(args, "password", None) else "blank")
        to_add.append(Credential(username=args.user, secret=(args.hash or args.password or ""),
                                 kind=kind, domain=args.domain or "", source="manual"))
    if to_add:
        n = sum(1 for c in to_add if store.add_credential(c))
        print(f"[+] Added {n} credential(s)"
              + (f" ({len(to_add) - n} already stacked)" if n < len(to_add) else "") + ".")
        added = True

    hosts = _selected_hosts(store.all_hosts(), args)
    stored = store.all_credentials()
    stacked = cr.stack(hosts, stored)

    # PLAN: write files + print the spray commands.
    if args.plan:
        if not stacked:
            print("[!] No credentials to spray yet. Add one:  "
                  "recce creds --add 'CORP\\alice:Passw0rd!'")
            store.close()
            return 0
        summary = cr.build_spray(stacked, hosts, args.output_dir)
        print(f"[+] Spray plan for {len(stacked)} credential(s) -> files in "
              f"{summary['dir']}/")
        if summary["files"]:
            print("    " + ", ".join(sorted(summary["files"])))
        print()
        for line in summary["commands"] or ["  (no sprayable services in scope yet)"]:
            print("  " + line if not line.startswith("#") else "\n  " + line)
        print("\n  ! Check the account-lockout policy first. '--continue-on-success' "
              "keeps going after a hit;")
        print("    the paired (user<->pass) list avoids a cartesian brute. Rules of "
              "engagement only.")
        store.close()
        return 0

    # RUN: actually spray with netexec (lockout-safe by default) and fold the hits.
    if getattr(args, "run", False):
        spray_creds = _spray_cred_set(args, stacked)
        if not spray_creds:
            print("[!] No credentials/usernames to spray. Loot some (recce act --run), "
                  "add one (--add), or pass --user-list/--pass-list.")
            store.close()
            return 0
        safe = not getattr(args, "spray", False)
        n_ips = sum(len(v) for v in cr.spray_targets(hosts).values())
        print(f"[*] Spraying {len(spray_creds)} credential(s) across the {n_ips} "
              f"login-surface host(s) — {'lockout-safe (paired, one pass)' if safe else 'FULL user x pass (lockout risk)'} ...")
        res = cr.run_spray(hosts, spray_creds, args.output_dir, safe=safe)
        if not res["ok"]:
            print(f"[x] {res['error']}")
            store.close()
            return 1
        hits = res["hits"]
        if hits:
            print(f"\n[+] {len(hits)} VALID login(s):")
            for h in hits:
                tag = "  (ADMIN / Pwn3d!)" if h["admin"] else ""
                print(f"      {h['proto']:<6} {h['ip']:<16} {h['cred']}{tag}")
                store.add_credential(Credential(
                    username=h["user"], secret=h["secret"],
                    kind="password", source="spray-validated", origin_ip=h["ip"],
                    notes=f"validated over {h['proto']}" + (" (local admin)" if h["admin"] else "")))
            _generate_reports(store, paths, store.get_meta("engagement") or getattr(args, "title", "") or "Recce Engagement", quiet=True)
        else:
            print("\n[i] No valid logins from the spray "
                  "(creds rejected, or the surface needs a different protocol).")
        store.close()
        return 0

    # ADD then regenerate the workbook so the Credentials sheet reflects it.
    if added:
        title = store.get_meta("engagement") or getattr(args, "title", "") or "Recce Engagement"
        _generate_reports(store, paths, title, quiet=True)

    # LIST (default).
    if not stacked:
        print("No credentials stacked yet.")
        print("  Capture then add:  recce creds --add 'CORP\\alice:Passw0rd!'  "
              "(or --user alice --hash <nt> --domain CORP)")
        print("  Then:              recce creds --plan   # netexec/impacket spray plan")
        store.close()
        return 0
    print(f"Stacked credentials ({len(stacked)}):")
    for c in stacked:
        sec = c.secret or "(blank)"
        if c.kind == "nthash" and len(sec) > 16:
            sec = sec[:13] + "..."
        origin = f" @{c.origin_ip}" if c.origin_ip else ""
        print(f"  {c.label:<26} {c.kind:<8} {sec:<20} [{c.source}{origin}]")
    print("\n  recce creds --plan   # build the spray plan (writes users/passwords/"
          "hashes + commands)")
    store.close()
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check that this box can run the tool, and optionally prove it with a
    real localhost self-scan. Run this on any system before an engagement."""
    import platform
    import shutil

    print(BANNER)
    print("Environment")
    print(f"  Python           {sys.version.split()[0]}  ({platform.python_implementation()})")
    print(f"  Platform         {platform.system()} {platform.release()}")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    print(f"  Root / privileges {'yes' if is_root else 'NO'}"
          + ("" if is_root else "  -> falls back to TCP connect scan; no SYN/OS/UDP"))
    py_ok = sys.version_info >= (3, 9)
    if not py_ok:
        print("  ! Python 3.9+ recommended.")

    print("\nTools (which capabilities are available)")
    tools = [
        ("nmap", True, "core scanning / service+OS detection / NSE vuln+AD+DB"),
        ("masscan", False, "--fast network-wide sweep"),
        ("searchsploit", False, "offline exploit mapping (Exploits sheet)"),
        ("ldap", False, "credentialed AD LDAP enum (ldapsearch or the ldap3 package)"),
        ("netexec", False, "credentialed SMB/AD enum (credenum phase)"),
        ("smbclient", False, "SMB share spider + writable-share proof (cmd_smb --spider/--prove-write)"),
        ("ssh", False, "credentialed Linux local checks (credenum phase)"),
        ("browser", False, "auto web screenshots in write-ups (firefox/chromium)"),
        ("proxychains4", False, "pivot support: route the run through a proxy (--proxy)"),
    ]
    nmap_ok = False
    presence: dict[str, bool] = {}   # reused for the summary, so it can't disagree
    for name, required, desc in tools:
        present = shutil.which(name) is not None
        if name == "searchsploit":
            from .. import exploits
            present = exploits.available()               # mirror the runtime gate
        if name == "ldap":
            from .. import ad
            present = ad.ldap_available()                # ldapsearch OR ldap3 package
            if present:
                backend = "ldapsearch" if shutil.which("ldapsearch") else "ldap3 package"
                desc = f"credentialed AD LDAP enum (using {backend})"
        if name == "netexec":
            from .. import credenum
            present = credenum.smb_tool() is not None   # nxc / crackmapexec too
        if name == "browser":
            from .. import screenshot
            present = screenshot.available()             # firefox / chrome variants
            found = screenshot.browser_tool()
            if found:
                desc = f"auto web screenshots in write-ups (using {found})"
        if name == "proxychains4":
            from .. import proxy
            present = bool(proxy.proxychains_bin())       # proxychains4 OR proxychains
        if name == "nmap":
            nmap_ok = present
        presence[name] = present
        mark = "OK  " if present else ("MISSING (required)" if required else "-   (optional)")
        print(f"  {name:<15} {mark:<20} {desc}")
    from .. import credenum as _ce
    if _ce.impacket_tool("GetUserSPNs"):
        print(f"  {'impacket':<15} {'OK  ':<20} Kerberoast / AS-REP / secretsdump")
    # The MSSQL deep enum (linked servers, data-mine, xp_cmdshell) needs the
    # impacket-mssqlclient CLI specifically - it silently no-ops without it, so surface
    # it explicitly (GetUserSPNs being present does not imply mssqlclient is).
    from .. import mssql as _mssql
    _msc = "OK  " if _mssql.mssqlclient_tool() else "-   (deep MSSQL enum disabled)"
    print(f"  {'mssqlclient':<15} {_msc:<20} MSSQL deep enum (impacket-mssqlclient)")
    import importlib.util as _ilu
    print("\nBundled Python libraries (baked into the airgap package)")
    for lib, note in (
        ("impacket", "Kerberos / SMB / DCSync as a library (no CLI shell-out)"),
        ("ldap3", "credentialed LDAP enumeration"),
        ("openpyxl", "richer .xlsx workbooks (stdlib xlsx is the fallback)"),
    ):
        ok = _ilu.find_spec(lib) is not None
        mark = "OK  " if ok else "-   (native/CLI fallback)"
        print(f"  {lib:<15} {mark:<24} {note}")
    # Honesty about the library-vs-CLI split: a few features (AS-REP roast,
    # secretsdump, mssqlclient deep-enum) shell out to the impacket CLI scripts, which
    # are NOT the same as the importable library. On the airgap bundle the library is
    # frozen in but the CLIs aren't (there's no general python3 to run them), so those
    # features go dark even though 'impacket OK' above. Say so, so it isn't a surprise
    # mid-engagement. Kerberoast + SMB enum are library-based and keep working.
    if _ilu.find_spec("impacket") is not None and not _ce.impacket_tool("GetUserSPNs"):
        print("  [!] impacket library is present but its CLI scripts are not on PATH -> "
              "AS-REP roast, secretsdump, and mssqlclient deep-enum are UNAVAILABLE "
              "(they shell out to the CLI). Kerberoast + SMB enum still work (library).")

    # Optional real self-scan to prove the pipeline end-to-end on THIS box.
    scan_ok = None
    if nmap_ok and not args.no_self_scan:
        print("\nSelf-scan (real nmap against 127.0.0.1, top 100 ports) ...")
        scan_ok = _self_scan()
        print("  " + ("PASS - scanned, parsed, and wrote a workbook."
                      if scan_ok else "FAIL - see error above."))

    print("\nSummary")
    if not nmap_ok:
        print("  NOT READY - install nmap (the only hard requirement).")
        verdict = 1
    elif scan_ok is False:
        print("  NOT READY - nmap is present but the self-scan failed (see above).")
        verdict = 1
    else:
        degraded = [n for n, req, _ in tools if not req and not presence.get(n)]
        print("  READY." + (f"  Optional tools missing: {', '.join(degraded)}."
                            if degraded else "  All tools present."))
        # Tell the user HOW to get each missing optional tool, not just its name.
        _install = {
            "masscan": "apt install masscan",
            "searchsploit": "apt install exploitdb",
            "netexec": "pipx install netexec  (+ pipx install impacket)",
            "ssh": "apt install openssh-client",
        }
        for n in degraded:
            if n in _install:
                print(f"      - {n}: {_install[n]}")
        print("\nNext")
        print("  Solo, in the terminal:   recce run <targets> -o eng   (or: enum -> vulns -> sweep)")
        print("  Prefer a browser / working as a TEAM:")
        print("      recce serve -o eng      -> the web workbench at http://<this-box>:8008")
        print("      run scans, triage findings, collect + spray credentials, export the report;")
        print("      the whole team shares one live view over the LAN.")
        verdict = 0
    return verdict
def cmd_ingest(args: argparse.Namespace) -> int:
    from .. import ingest
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first so there's a "
              "workbook to fold findings into.")
        return 1
    if not os.path.exists(args.loot):
        print(f"[x] Loot file not found: {args.loot}")
        return 1
    with open(args.loot, "r", errors="replace") as fh:
        text = fh.read()
    parsed = ingest.parse_loot(text)
    if not parsed["is_recce"]:
        # Maybe it's per-service enumeration output (recce-service.sh) instead.
        svc = ingest.parse_service_output(text)
        if svc["is_service"] and svc["findings"]:
            return _ingest_service_output(svc, paths, args)
        print("[!] This doesn't look like recce-enum.sh/.ps1 output (no "
              "'recce-enum host=...' banner). Parsing [!] lines anyway.")
    topo = ingest.parse_topology(text)
    if not parsed["findings"] and not topo:
        print("[!] No [!] findings or NETWORK block in that loot - nothing to ingest.")
        return 0

    source = os.path.basename(args.loot)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    host, existed = _resolve_ingest_host(store, parsed, args, topo)
    added, total, promoted = _fold_loot(host, text, source)
    store.upsert_host(host)
    where = "existing host" if existed else "new host entry"
    hn = f" ({parsed['hostname']})" if parsed["hostname"] else ""
    print(f"[+] Ingested {added} finding(s) from {source} into {where} "
          f"{host.ip}{hn}"
          + (f"; {total - added} already present" if total != added else "")
          + ".")
    if topo:
        nn = len(topo.get("neighbors", [])); npeers = len(topo.get("peers", []))
        nif = len(topo.get("interfaces", []))
        print(f"    Folded on-target topology: {nif} interface(s), {nn} ARP "
              f"neighbour(s), {npeers} live peer(s) -> observed-reachability map.")
    if promoted:
        print(f"    Promoted {promoted} high-signal finding(s) to the "
              "Vulnerabilities sheet.")
    print(f"    OS: {host.os_family or 'unknown'}. See the Priv-Esc tab "
          "(rows tagged 'on-target finding').")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0
def cmd_deploy(args: argparse.Namespace) -> int:
    """Push + run recce's read-only local-enum / priv-esc scripts across every host
    we have credentials for (SSH / WinRM / SMB), then fold the results in."""
    from .. import deploy
    print(BANNER)
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first so there are "
              "hosts to deploy to.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    ssh_creds = _ssh_creds_of(args)
    win_creds = _creds_of(args)
    if win_creds and getattr(args, "hash", None):
        win_creds["hash"] = args.hash          # pass-the-hash for SMB/WinRM
    if not ssh_creds and not win_creds:
        print("\n" + "!" * 64)
        print("[x] deploy needs credentials. Give --ssh-user (+ --ssh-pass/--ssh-key) "
              "for Linux,")
        print("    and/or -u/-p (+ -d domain, or --hash) for Windows WinRM/SMB.")
        print("!" * 64)
        store.close()
        return 1

    hosts = _selected_hosts(store.all_hosts(), args)
    # nxc precheck: which protocols do these creds ACTUALLY authenticate to? Deploy
    # only where they truly work (and pick that transport), instead of guessing
    # from open ports. Skipped with --no-validate or when nxc isn't installed.
    authmap: dict = {}
    if not getattr(args, "no_validate", False):
        print("[*] Checking which hosts accept the creds (nxc smb/winrm/ssh) ...")
        authmap = deploy.validate([h.ip for h in hosts], ssh_creds, win_creds)
        if authmap:
            n_win = sum(1 for a in authmap.values() if a.get("winrm"))
            n_smb = sum(1 for a in authmap.values() if a.get("smb"))
            n_ssh = sum(1 for a in authmap.values() if a.get("ssh"))
            print(f"    creds valid on: {n_win} WinRM, {n_smb} SMB-admin, {n_ssh} SSH "
                  "host(s).")
        else:
            print("    (nxc unavailable or no results - falling back to open-port "
                  "selection.)")
    the_plan = deploy.plan(hosts, ssh_creds, win_creds, authmap or None)
    deployable = [(h, t) for h, t in the_plan if t]
    skipped = [h for h, t in the_plan if not t]
    if not deployable:
        print("[!] No hosts have a usable transport + matching credentials.")
        print("    Need an open SSH (22) / WinRM (5985) / SMB (445) port and the "
              "matching cred set. Run `enum` first, or widen your creds.")
        store.close()
        return 1

    by_t: dict[str, int] = {}
    for _h, t in deployable:
        by_t[t] = by_t.get(t, 0) + 1
    print(f"[*] Deploy plan: {len(deployable)} host(s) reachable "
          f"({', '.join(f'{n}×{t}' for t, n in sorted(by_t.items()))})"
          + (f"; {len(skipped)} skipped (no transport/creds)" if skipped else "") + ".")
    use_stager = getattr(args, "stager", False)
    if use_stager:
        print("    Windows hosts fetch + run recce-enum.ps1 IN MEMORY from a local "
              "HTTP stager (no temp file); falls back to the push path if a host "
              "can't route back to you.")
    else:
        print("    Scripts are READ-ONLY (recce-enum.sh/.ps1). SSH & WinRM run in "
              "memory (no artifact); SMB drops to %TEMP% and deletes after.")
    print("    Confirm this is within your rules of engagement.")
    if getattr(args, "dry_run", False):
        print(f"\n  WILL RUN ({len(deployable)}):")
        for h, t in sorted(deployable, key=lambda ht: _ip_key(ht[0].ip)):
            print(f"    {h.ip:<16} -> {t}" + ("  (+http stager if reachable)"
                                              if use_stager and t != "ssh" else ""))
        if skipped:
            print(f"\n  UNABLE / SKIPPED ({len(skipped)}):")
            for h in sorted(skipped, key=lambda x: _ip_key(x.ip)):
                print(f"    {h.ip:<16} -- {deploy.skip_reason(h, ssh_creds, win_creds, authmap or None)}")
        print("\n[*] Dry run - nothing was executed. Drop --dry-run to deploy.")
        store.close()
        return 0

    # Optional HTTP stager for in-memory Windows exec.
    stager = None
    if use_stager:
        from ..stager import Stager, detect_lhost
        lhost = getattr(args, "lhost", None) or detect_lhost()
        if not lhost:
            print("[x] --stager needs --lhost <your-ip that targets can reach>; "
                  "could not autodetect one.")
            store.close()
            return 1
        try:
            with open(deploy.WINDOWS_SCRIPT, "rb") as _wf:
                files = {"recce-enum.ps1": _wf.read()}
        except OSError as e:
            print(f"[x] Could not read the Windows script: {e}")
            store.close()
            return 1
        try:
            stager = Stager(lhost, files)
            stager.__enter__()
        except OSError as e:
            print(f"[x] Could not start the HTTP stager on {lhost}: {e}")
            store.close()
            return 1
        print(f"[*] HTTP stager on http://{lhost}:{stager.port}/ (serving "
              "recce-enum.ps1 to Windows hosts, torn down when done).")

    workers = max(1, args.workers)
    timeout = getattr(args, "timeout", None) or deploy.DEFAULT_TIMEOUT
    loot_dir = os.path.join(args.output_dir, "loot")
    try:
        os.makedirs(loot_dir, exist_ok=True)
    except OSError:
        loot_dir = paths["raw"]
    print(f"[*] Deploying to {len(deployable)} host(s) with {workers} worker(s); "
          f"loot -> {loot_dir}/ ...")
    completed = 0
    total = len(deployable)
    start = time.monotonic()
    errs: list[tuple[str, str]] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_deploy_worker, h, ssh_creds, win_creds, timeout,
                                 loot_dir, stager, authmap or None): h.ip
                       for h, _t in deployable}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    host, transport, added, promoted, err = fut.result()
                except Exception as e:  # noqa: BLE001
                    _record_issues(store, paths, ip, [{"phase": "deploy",
                                   "level": "error", "message": f"deploy crashed: {e}"}])
                    completed += 1
                    errs.append((ip, f"crashed: {e}"))
                    print(f"    [{completed}/{total}] {ip}: FAILED (crashed)"
                          f"{_progress(completed, total, start)}")
                    continue
                completed += 1
                if err:
                    _record_issues(store, paths, ip, [{"phase": "deploy",
                                   "level": "warning",
                                   "message": f"deploy via {transport or '?'}: {err}"}])
                    errs.append((ip, err))
                    print(f"    [{completed}/{total}] {ip}: {transport or '-'} FAILED "
                          f"- {err}{_progress(completed, total, start)}")
                    continue
                _persist_host(store, paths, ip, "deploy", host)
                bits = f"{added} finding(s)" + (f", {promoted} promoted" if promoted else "")
                print(f"    [{completed}/{total}] {ip}: {transport} OK ({bits})"
                      f"{_progress(completed, total, start)}")
    finally:
        if stager is not None:
            stager.__exit__(None, None, None)
    # Hosts we never attempted (no transport / creds didn't validate) are the
    # "unable to complete" bucket - write them to the workbook too, so the report
    # shows every host's outcome, not just the ones we reached.
    for h in skipped:
        _record_issues(store, paths, h.ip, [{"phase": "deploy", "level": "warning",
                       "message": "not deployed: "
                       + deploy.skip_reason(h, ssh_creds, win_creds, authmap or None)}])
    _final_report(store, paths, store.get_meta("engagement") or args.title)
    store.close()

    ok = total - len(errs)
    print(f"\n{'=' * 60}")
    print(f"  DEPLOY RESULTS: {ok} succeeded · {len(errs)} errored · "
          f"{len(skipped)} unable")
    print(f"{'=' * 60}")
    if errs:
        print(f"  ERRORED ({len(errs)}) - reached but did not complete:")
        for ip, msg in sorted(errs, key=lambda x: _ip_key(x[0])):
            print(f"    {ip:<16} -- {msg}")
    if skipped:
        print(f"  UNABLE ({len(skipped)}) - never attempted:")
        for h in sorted(skipped, key=lambda x: _ip_key(x.ip)):
            print(f"    {h.ip:<16} -- "
                  f"{deploy.skip_reason(h, ssh_creds, win_creds, authmap or None)}")
    print(f"\n[+] Loot saved in {loot_dir}/. Findings folded into local_findings "
          "+ the Priv-Esc tab.")
    if errs or skipped:
        print("    Errored / unable hosts are logged on the Overview issues tab.")
    print(f"    Next: recce attackpath -o {args.output_dir}  (or writeups).")
    return 0
def cmd_import(args: argparse.Namespace) -> int:
    """Import an already-completed nmap scan (XML -oX or grepable -oG) and build /
    update the workbook - no scanning, no network. Folds hosts into the datastore,
    runs the offline enrichment (version->CVE, AD roles, SMB signing), sets the
    checkmarks, and preserves any existing tracking."""
    from .. import vulndb
    files = _collect_scan_files(args.files)
    if not files:
        print("[x] No nmap scan files found. Point at .xml (-oX) or .gnmap (-oG) "
              "files, a directory, or a glob.")
        return 1
    parsed: list[Host] = []
    for f in files:
        hs = np.parse_nmap_file(f)
        print(f"    {os.path.basename(f)}: {len(hs)} host(s)")
        parsed.extend(hs)
    if not parsed:
        print("[x] Nothing parsed. Point at nmap XML (-oX, best), grepable "
              "(-oG), or normal (-oN, .nmap) output.")
        return 1

    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)          # honour existing ticks first
    if not store.get_meta("engagement"):
        store.set_meta("engagement", args.title)

    by_ip: dict[str, list[Host]] = {}
    for h in parsed:
        by_ip.setdefault(h.ip, []).append(h)
    use_ss = getattr(args, "searchsploit", False) and exploits.available()
    enum_only = getattr(args, "enum_only", False)
    n_hosts = n_ports = n_findings = n_scanned = 0
    # Net-new tracking: exactly which open ports this scan adds that recce did NOT
    # already have. This is the point of the manual-nmap fallback - "did my manual
    # nmap catch ports recce's own sweep missed?" - so we report it explicitly.
    new_host_ips: list[str] = []
    added_by_ip: dict[str, list[int]] = {}
    for ip, group in by_ip.items():
        subnet = ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else ""
        prior = store.get_host(ip)                 # pre-merge snapshot, for the diff
        prior_open = {(p.protocol, p.portid) for p in prior.open_ports} if prior else set()
        host = _fold_host(ip, group, {ip: subnet})
        host.enumerated = True
        if not enum_only:
            for p in host.ports:                  # scan ran scripts here -> vuln step done
                if p.scripts and not p.vuln_scanned:
                    p.vuln_scanned = True
                    n_scanned += 1
        ad.identify_roles(host)
        ad.parse_signing_and_ntlm(host)
        vulndb.assess_host_inplace(host)          # offline version->CVE/CWE findings
        if use_ss:
            exploits.enrich_hosts([host])
        added = [p.portid for p in host.open_ports
                 if (p.protocol, p.portid) not in prior_open]
        if prior is None:
            new_host_ips.append(ip)
        if added:
            added_by_ip[ip] = sorted(added)
        store.upsert_host(host)                    # merges with existing (tracking kept)
        n_hosts += 1
        n_ports += len(host.open_ports)
        n_findings += len(host.vulns)

    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print(f"\n[+] Imported {n_hosts} host(s) / {n_ports} open port(s) from "
          f"{len(files)} file(s): {n_findings} offline finding(s), "
          f"{n_scanned} port(s) marked vuln-scanned (had NSE output).")
    # Surface exactly what the imported scan ADDED over what recce already had - the
    # whole reason for the manual-nmap fallback.
    total_added = sum(len(v) for v in added_by_ip.values())
    if total_added:
        print(f"[+] This scan added {total_added} open port(s) recce did not already "
              f"have, across {len(added_by_ip)} host(s)"
              + (f" ({len(new_host_ips)} brand-new host(s))" if new_host_ips else "")
              + ":")
        for ip in sorted(added_by_ip, key=_ip_key)[:20]:
            tag = "  (NEW host)" if ip in new_host_ips else ""
            ports = added_by_ip[ip]
            shown = ", ".join(str(p) for p in ports[:15]) + ("  …" if len(ports) > 15 else "")
            print(f"      {ip}{tag}: {shown}")
        if len(added_by_ip) > 20:
            print(f"      … and {len(added_by_ip) - 20} more host(s)")
    else:
        print("[i] No new open ports vs. what recce already had (re-import is a safe "
              "no-op - hosts/ports/findings are merged by key, never duplicated).")
    print("    Checklist 'Enumerated'"
          + ("" if enum_only else " + 'Vuln-scan' (where scripts ran)")
          + " are ticked. Run `vulns` (recce's deeper detection on these ports), the "
          "service deep-scans, or `status` to see what's left.")
    return 0


def cmd_bloodhound(args: argparse.Namespace) -> int:
    """Import SharpHound and/or Certipy (ADCS) output, identify AD
    misconfigurations + vulnerabilities, map the shortest paths from YOUR account
    (or any authenticated user) to Domain Admin, and stage the follow-on actions.

    Simple credentialed run:  recce ad loot.zip -u alice -p 'Passw0rd' -d corp.local
    Add ADCS:                 recce ad loot.zip certipy.json -u alice -p ... -d corp.local
    Airgapped, stdlib-only; every command is pre-filled with your credentials."""
    from .. import bloodhound as bh
    from .. import adcs

    srcs = args.paths if isinstance(args.paths, list) else [args.paths]
    for s in srcs:
        if not os.path.exists(s):
            print(f"[x] Not found: {s}")
            return 1

    # Credentials: prefer the simple -u/-p/-d; fall back to --creds 'DOM/user:secret'.
    creds = None
    if args.username:
        user, domain = _split_userdomain(args.username, args.domain)
        secret = args.password or ""
        is_hash = bool(re.fullmatch(r"[0-9a-fA-F]{32}", secret or ""))
        creds = {"domain": domain, "user": user, "secret": secret,
                 "is_hash": is_hash, "dc_ip": args.dc_ip or ""}
    elif args.creds:
        c = _parse_cred_spec(args.creds)
        creds = {"domain": c.domain, "user": c.username, "secret": c.secret,
                 "is_hash": c.kind == "nthash", "dc_ip": args.dc_ip or ""}

    # Where attack paths start: explicit --owned, else YOUR account (simple default),
    # else any authenticated user.
    owned = set()
    if args.owned:
        for chunk in args.owned:
            owned.update(o.strip() for o in chunk.split(",") if o.strip())
    elif creds and creds["user"]:
        owned = {creds["user"]}
        if creds["domain"]:
            owned.add(f"{creds['user']}@{creds['domain']}")

    # Classify each input: SharpHound graph vs Certipy ADCS JSON.
    sh_paths = [s for s in srcs if bh.is_sharphound(s)]
    certipy_paths = [s for s in srcs if adcs.is_certipy(s)]
    unknown = [s for s in srcs if s not in sh_paths and s not in certipy_paths]
    for u in unknown:
        print(f"[!] {u} isn't recognised as SharpHound or Certipy output - skipped.")

    if sh_paths:
        print(f"[*] Parsing SharpHound: {', '.join(os.path.basename(p) for p in sh_paths)}")
        analysis = bh.analyze(sh_paths[0], owned=owned, creds=creds)
        for extra in sh_paths[1:]:                       # merge extra collections' findings
            more = bh.analyze(extra, owned=owned, creds=creds)
            analysis["findings"].extend(more["findings"])
            analysis["domains"].extend(more["domains"])
    else:
        analysis = bh.empty_analysis()

    if certipy_paths:
        print(f"[*] Parsing Certipy ADCS: {', '.join(os.path.basename(p) for p in certipy_paths)}")
        for cp in certipy_paths:
            analysis["findings"].extend(adcs.findings(cp))

    # Optional LIVE Kerberos capture (roast / AS-REP / DCSync): run the published
    # impacket tools to grab the real hashes and fold each capture in as a proven
    # finding before we sort + fold into the totals.
    _ad_live_kerberos(args, bh, creds, sh_paths, analysis)

    # Re-sort merged findings, fill in the operator's credentials, refresh stats.
    analysis["findings"].sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    bh.fill_creds(analysis, creds)
    analysis["stats"]["findings"] = len(analysis["findings"])

    st = analysis["stats"]
    if st.get("nodes"):
        print(f"[+] Graph: {st['nodes']} node(s), {st['edges']} edge(s) "
              f"({', '.join(f'{k}={v}' for k, v in sorted(st['by_type'].items()))})")

    fs = analysis["findings"]
    if fs:
        by_sev: dict[str, int] = {}
        for f in fs:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        adcs_n = sum(1 for f in fs if f["category"].startswith("adcs-"))
        print(f"[+] {len(fs)} AD finding(s)"
              + (f" ({adcs_n} ADCS/ESC)" if adcs_n else "") + ": "
              + ", ".join(f"{by_sev[s]} {s}" for s in
                          ("critical", "high", "medium", "low") if by_sev.get(s)))
        for f in fs[:10]:
            print(f"      [{f['severity'].upper():8}] {f['title']} - {f['principal']}")
        if len(fs) > 10:
            print(f"      ... and {len(fs) - 10} more (see the AD Findings sheet)")

    paths_found = analysis["paths"]
    if paths_found:
        print(f"[+] {len(paths_found)} attack path(s) to a high-value target:")
        for p in paths_found[:5]:
            who = "ANY user" if p.get("any_user") else p["start"]
            print(f"      {who} -> {p['target']}  ({p['length']} hop): {p['chain']}")
    elif sh_paths:
        print("[!] No path to a high-value target from "
              + (f"{', '.join(sorted(owned))}" if owned else "any authenticated user")
              + " in this collection.")
    if analysis["kerberos"]:
        print(f"[+] {len(analysis['kerberos'])} Kerberos action(s) staged "
              "(see the AD Attack Paths sheet).")

    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    if not store.get_meta("engagement"):
        store.set_meta("engagement", args.title)
    store.set_meta("ad_bloodhound", json.dumps(analysis))
    # Merge domain facts (trusts, functional level, MachineAccountQuota) so the
    # Active Directory sheet reflects the import even without a network scan.
    from ..models import Domain
    for dom in analysis["domains"]:
        name = (dom.get("name") or "").lower()
        if not name:
            continue
        existing = store.get_domain(name)
        d = existing or Domain(name=name)
        d.functional_level = d.functional_level or str(dom.get("functionallevel") or "")
        d.machine_account_quota = d.machine_account_quota or str(
            dom.get("machineaccountquota") or "")
        d.trusts = d.trusts or [
            {"name": t.get("TargetDomainName"), "direction": t.get("TrustDirection"),
             "type": t.get("TrustType")} for t in dom.get("trusts") or []]
        if "bloodhound" not in d.sources:
            d.sources.append("bloodhound")
        store.upsert_domain(d)

    # Feed the AD findings into the MAIN totals + writeups by attaching them as
    # Vulns on the DC / domain host (keyed by --dc-ip when given, so they merge
    # onto the scanned DC rather than creating a duplicate).
    if analysis["findings"]:
        from ..models import Host
        dom_name = analysis["domains"][0]["name"] if analysis["domains"] else ""
        ad_ip = (creds and creds.get("dc_ip")) or dom_name or "active-directory"
        vulns = bh.findings_to_vulns(analysis, ad_ip, dom_name)
        replace = getattr(args, "replace_ad", False)
        host = store.get_host(ad_ip)
        removed = 0
        if host is None:
            host = Host(ip=ad_ip, hostnames=[dom_name] if dom_name else [],
                        os_family="Windows")
            if creds and creds.get("dc_ip"):
                host.roles = ["Domain Controller"]
        elif replace:
            # Drop the previously-imported AD/ADCS findings so a re-import reflects
            # the CURRENT state (fixed items disappear); other host data is kept.
            before = len(host.vulns)
            host.vulns = [v for v in host.vulns
                          if v.source not in ("bloodhound", "adcs")]
            removed = before - len(host.vulns)
        host.enumerated = True
        have = {v.key for v in host.vulns}
        for v in vulns:
            if v.key not in have:
                have.add(v.key)
                host.vulns.append(v)
        # merge=False on replace so the old AD vulns aren't re-introduced by the
        # union-merge (we've already loaded and rewritten the full host).
        store.upsert_host(host, merge=not replace)
        msg = (f"    -> {len(vulns)} AD finding(s) folded into the main severity "
               f"totals + writeups (host {ad_ip})")
        if replace:
            msg += f"; replaced {removed} prior AD finding(s)"
        print(msg + ".")

    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    written = []
    if analysis["findings"]:
        written.append("AD Findings")
    if analysis["paths"] or analysis["kerberos"]:
        written.append("AD Attack Paths")
    if written:
        print(f"    -> {' + '.join(written)} sheet(s) written to the workbook.")
    else:
        print("    -> Nothing to import (no AD findings or paths in the input).")
    return 0
def cmd_mssql(args: argparse.Namespace) -> int:
    """MSSQL offensive enumeration: credential-free pre-auth probes (SQL Browser +
    TDS pre-login), then - with credentials - the nxc access/privilege matrix and
    the full MSSQLPwner-style runbook + attack chain, pre-filled with your creds."""
    from .. import mssql
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
    ran_impacket = False
    if creds and not args.no_run and not mssql.mssqlclient_tool():
        print("      [!] impacket-mssqlclient not installed - MSSQL deep enumeration "
              "(linked servers, data-mine, xp_cmdshell, write-proof) SKIPPED; the sheet "
              "shows commands only. `recce doctor` flags this; install impacket to run it.")
    if creds and not args.no_run and mssql.mssqlclient_tool():
        for t in tgts:
            if t.get("access") is False:            # nxc already said the creds fail
                continue
            enum, err = mssql.run_mssqlclient(t["ip"], creds, port=t["port"],
                                              windows_auth=not args.local_auth)
            if enum is None:
                print(f"      [!] mssqlclient {t['ip']}: {err}")
                continue
            ran_impacket = True
            runner = mssql.link_runner(t["ip"], creds, port=t["port"],
                                       windows_auth=not args.local_auth)
            # Verify db_owner on the TRUSTWORTHY candidates so a chain is CONFIRMED.
            dbo_map = mssql.verify_dbowner(mssql.trustworthy_sysadmin_dbs(enum), runner)
            live_fs, live_chain, summary = mssql.chains_from_enum(t, enum, creds,
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
def cmd_smb(args: argparse.Namespace) -> int:
    """SMB offensive enumeration: credential-free stdlib negotiate probes (dialect /
    signing / SMBv1), then anonymous & credentialed share enumeration, a reversible
    writable-share proof, and the full runbook - folded into the main totals."""
    from .. import smb
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts run SMB.")
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
    analysis = smb.analyze(hosts, creds=creds, active=active, **_probe_kwargs(args, "smb"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No SMB endpoints in the datastore (no port 445/139). Run `enum` "
              "against the SMB hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} SMB endpoint(s):")
    for t in tgts:
        bits = [t.get("dialect") or ""]
        if t.get("signing_required") is False:
            bits.append("signing NOT REQUIRED")
        if t.get("smbv1"):
            bits.append("SMBv1 ENABLED")
        print(f"      {t['ip']}:{t['port']}  " + "  ".join(b for b in bits if b))

    # A missing smbclient makes --spider / --prove-write return "nothing found"
    # silently (they no-op without the tool) - warn ONCE up front so an empty result
    # isn't mistaken for a clean host. `recce doctor` also flags it.
    if (getattr(args, "spider", False) or getattr(args, "prove_write", False)) \
            and not smb.smbclient_tool():
        print("[!] smbclient not installed - --spider and --prove-write will be SKIPPED "
              "(an empty result here means 'not checked', not 'nothing there'). "
              "Install smbclient to run them.")

    # Record the directly-observed signing posture on each host so the prove engine
    # (_v_smb_signing) can adjudicate a relay finding as CONFIRMED, not a guess.
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        req = t.get("signing_required")
        if req is None:
            continue
        host = host_by_ip.get(t["ip"])
        if host is not None:
            host.smb_signing = "required" if req else "not required"

    # Live layer: anonymous (null/guest) share enumeration + reversible write proof.
    rb_by_ip = {rb["ip"]: rb for rb in analysis["runbooks"]}
    ran_live = False
    if not args.no_run:
        for t in tgts:
            ip, port = t["ip"], t["port"]
            # Enumerate with the strongest session that works: null -> guest -> creds.
            session, level = smb.enum_best_session(ip, port=port, creds=creds)
            if level == "error":
                print("      [i] nxc/netexec not installed - writing the commands to "
                      "run instead (see the SMB sheet).")
                break
            ran_live = True
            shares = session.get("shares") or []
            nusers = len(session.get("users") or [])
            if level == "creds":
                # An authenticated inventory - NOT an anonymous-access finding.
                label = (f"credentialed session (as {creds.get('user')}): "
                         f"{len(shares)} share(s), {nusers} user(s)")
                cmd_shown = (f"nxc smb {ip} -u {creds.get('user')} -p *** "
                             + (f"-d {creds['domain']} " if creds.get("domain") else "--local-auth ")
                             + "--shares --users")
            else:
                label = (f"anonymous session ({level}): {len(shares)} share(s), "
                         f"{nusers} user(s)")
                cmd_shown = f"nxc smb {ip} -u '' -p '' --shares --users --pass-pol"
                # Anonymous access to shares/users is itself a finding.
                analysis["findings"].extend(smb.null_session_findings(ip, port, session))
            live = {"shares": shares, "writable": [], "session": label}
            if session.get("output"):
                _smb_shot(args, ip, "enum", cmd_shown, session["output"])
            # Prove writable shares (reversible) when requested.
            if args.prove_write:
                for s in shares:
                    perms = (s.get("perms") or "").upper()
                    name = s.get("name", "")
                    if "WRITE" not in perms or name.upper() in ("IPC$", "PRINT$"):
                        continue
                    proof = smb.prove_writable(ip, name, creds, port=port)
                    if proof.get("writable"):
                        live["writable"].append({"share": name,
                                                 "evidence": proof.get("evidence", "")})
                        f = smb.write_proof_finding(ip, port, name, proof, creds)
                        if f:
                            analysis["findings"].insert(0, f)
                        _smb_shot(args, ip, f"write_{name}",
                                  proof.get("command", ""), proof.get("evidence", ""))
            # Spider readable shares for secret-looking files (opt-in, read-only).
            if getattr(args, "spider", False) and shares:
                spider_hits = smb.spider_shares(ip, shares, creds, port=port)
                for f in spider_hits:
                    analysis["findings"].insert(0, f)
                if spider_hits:
                    live["secrets"] = len(spider_hits)      # shares with secrets found
            rb_by_ip[ip]["live"] = live

    # De-duplicate (offline + live can overlap) by (title, target).
    seen: set = set()
    uniq = []
    for f in analysis["findings"]:
        k = (f["title"], f["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    analysis["findings"] = uniq

    by_ip = _fold_service_findings(store, hosts, analysis, "smb",
                                   smb.findings_to_vulns, "SMB")
    # Persist the signing posture we observed (upsert any host we touched but that
    # produced no vulns, so host.smb_signing still lands).
    for t in tgts:
        if t["ip"] not in by_ip:
            host = host_by_ip.get(t["ip"])
            if host is not None and t.get("signing_required") is not None:
                store.upsert_host(host, merge=False)
    if active or ran_live:           # assessed the SMB port(s) -> auto-tick vuln-scan
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    hint = "live enum" if ran_live else "commands-only"
    print(f"    -> SMB sheet written ({hint}); findings folded into the main totals.")
    return 0
def cmd_ftp(args: argparse.Namespace) -> int:
    """FTP offensive enumeration: credential-free stdlib probe (banner / anonymous /
    AUTH-TLS + known-backdoor match), then a reversible writable-directory proof -
    folded into the main totals."""
    from .. import ftp
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts run FTP.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    creds = None
    if args.username:
        creds = {"user": args.username, "secret": args.password or ""}

    active = not args.no_probe
    analysis = ftp.analyze(hosts, creds=creds, active=active, **_probe_kwargs(args, "ftp"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No FTP endpoints in the datastore (no port 21 / ftp service). Run "
              "`enum` against the FTP hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} FTP endpoint(s):")
    for t in tgts:
        bits = [t.get("banner") or t.get("product") or ""]
        if t.get("anonymous"):
            bits.append("ANONYMOUS")
        if t.get("auth_tls") is False:
            bits.append("cleartext (no AUTH TLS)")
        print(f"      {t['ip']}:{t['port']}  " + "  ".join(b for b in bits if b))

    rb_by_ip = {rb["ip"]: rb for rb in analysis["runbooks"]}
    ran_live = False
    if not args.no_run and args.prove_write:
        for t in tgts:
            # Only attempt a write when a session is actually reachable (anonymous or
            # supplied creds), so we don't hammer a login we can't make.
            if not (t.get("anonymous") or creds):
                continue
            proof = ftp.prove_writable(t["ip"], t["port"], creds)
            ran_live = True
            if proof.get("writable"):
                rb_by_ip[t["ip"]]["live"] = {"writable": True,
                                             "evidence": proof.get("evidence", "")}
                f = ftp.write_proof_finding(t["ip"], t["port"], proof, creds)
                if f:
                    analysis["findings"].insert(0, f)
                _ftp_shot(args, t["ip"], "write",
                          f"ftp {t['ip']}  (STOR/DELE marker)", proof.get("evidence", ""))
            elif proof.get("error"):
                print(f"      [!] {t['ip']}: write proof - {proof['error']}")

    seen: set = set()
    uniq = []
    for f in analysis["findings"]:
        k = (f["title"], f["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    analysis["findings"] = uniq

    _fold_service_findings(store, hosts, analysis, "ftp",
                           ftp.findings_to_vulns, "FTP")
    if active or ran_live:           # assessed the FTP port -> auto-tick vuln-scan
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    hint = "write proof" if ran_live else "commands-only"
    print(f"    -> FTP sheet written ({hint}); findings folded into the main totals.")
    return 0


def cmd_docker(args: argparse.Namespace) -> int:
    """Docker Engine API enumeration: read the API unauthenticated (stdlib HTTP) and,
    if it answers, report the CONFIRMED critical exposure (remote root RCE on the
    host). recce reads the API to prove it - it never creates a container."""
    from .. import docker
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose the Docker API.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = docker.analyze(hosts, active=active)
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No Docker API endpoints in the datastore (no port 2375/2376). Run "
              "`enum` against the Docker hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} Docker endpoint(s):")
    for t in tgts:
        if t.get("exposed"):
            state = "EXPOSED (unauth)"
        elif t.get("probed"):
            state = "locked (mutual-TLS / authenticated)"
        else:
            state = "not probed"
        extra = f"  {t.get('version', '')}" if t.get("version") else ""
        print(f"      {t['ip']}:{t['port']}  {state}{extra}")

    # Optional proof screenshot of the (synthesised) `docker info` for exposed hosts.
    if getattr(args, "screenshots", False):
        for t in tgts:
            pr = analysis["probes"].get(f"{t['ip']}:{t['port']}")
            if pr and pr.get("exposed"):
                out = (f"Server Version: {pr.get('server_version', '')}\n"
                       f"Name: {pr.get('name', '')}\n"
                       f"Containers: {pr.get('containers', '?')}  "
                       f"Images: {pr.get('images', '?')}\n"
                       f"Kernel Version: {pr.get('kernel', '')}")
                _docker_shot(args, t["ip"],
                             f"docker -H {docker._scheme(t['port'])}://{t['ip']}:"
                             f"{t['port']} info", out)

    _fold_service_findings(store, hosts, analysis, "docker",
                           docker.findings_to_vulns, "Docker")
    if active:                       # read the Docker API port -> auto-tick vuln-scan
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> Docker sheet written; findings folded into the main totals.")
    return 0
def cmd_kubernetes(args: argparse.Namespace) -> int:
    """Kubernetes attack-surface enumeration: unauthenticated reads of the kubelet
    (10250/10255), kube-apiserver (6443/8443) and etcd (2379). recce only READS to
    prove exposure - it never execs into a pod or writes to etcd."""
    from .. import kubernetes as k8s
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts run Kubernetes.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = k8s.analyze(hosts, active=active, **_probe_kwargs(args, "kubernetes"))
    _report_partial(analysis["stats"])
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No Kubernetes endpoints in the datastore (no kubelet/apiserver/etcd "
              "port). Run `enum` against the cluster hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} Kubernetes surface(s):")
    for t in tgts:
        exposed = (t.get("anon_pods") or t.get("anon_list")
                   or t.get("v2_readable") or t.get("v3_readable"))
        state = "EXPOSED (unauth)" if exposed else \
            ("reachable" if t.get("reachable") else "not probed")
        print(f"      {t['ip']}:{t['port']}  {t.get('role', '')}  {state}")

    _fold_service_findings(store, hosts, analysis, "kubernetes",
                           k8s.findings_to_vulns, "Kubernetes")
    if active:                       # probed the kubelet/API/etcd ports -> vuln-scan
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> Kubernetes sheet written; findings folded into the main totals.")
    return 0


def cmd_ldap(args: argparse.Namespace) -> int:
    """Deep LDAP / AD directory enumeration: a stdlib BER/ASN.1 client anonymously
    binds, reads the RootDSE (domain/forest/DC/functional level), and tests whether
    the directory is anonymously readable. Read-only - it never writes to the
    directory. Credentialed follow-on commands are staged, not run."""
    from .. import ldap as _ldap
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose LDAP.")
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
                 "hash": getattr(args, "hash", None) or ""}   # --hash -> NTLM pass-the-hash

    active = not args.no_probe
    analysis = _ldap.analyze(hosts, creds=creds, active=active, **_probe_kwargs(args, "ldap"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No LDAP endpoints in the datastore (no port 389/636/3268/3269). "
              "Run `enum` against the domain controllers first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} LDAP endpoint(s):")
    for t in tgts:
        flags = []
        if t.get("anon_read"):
            flags.append("ANON-READ")
        elif t.get("anon_bind"):
            flags.append("anon-bind")
        if t.get("auth_ok"):
            flags.append(f"AUTH: {t.get('auth_users', 0)} users / "
                         f"{t.get('kerberoastable', 0)} kerb / {t.get('asrep', 0)} asrep")
        elif t.get("auth_error"):
            flags.append(f"auth failed ({t['auth_error']})")
        dom = f"  {t.get('domain', '')}" if t.get("domain") else ""
        dc = f" ({t.get('dc_dns')})" if t.get("dc_dns") else ""
        state = "  ".join(flags) or "probed"
        print(f"      {t['ip']}:{t['port']}  {state}{dom}{dc}")

    if getattr(args, "screenshots", False):
        for t in tgts:
            pr = analysis["probes"].get(f"{t['ip']}:{t['port']}")
            if pr and pr.get("rootdse_ok"):
                out = "\n".join(filter(None, [
                    f"domain: {pr.get('domain', '')}",
                    f"forest: {pr.get('forest', '')}",
                    f"dnsHostName: {pr.get('dc_dns', '')}",
                    f"functional level: Server {pr.get('dc_level', '')}",
                    f"anonymous read: {'YES' if pr.get('anon_read') else 'no'}"]))
                _ldap_shot(args, t["ip"], f"ldapsearch -x -H ldap://{t['ip']}:{t['port']} "
                           "-s base -b '' '(objectClass=*)'", out)

    # analyze() attached authenticated-enum Account objects onto the DC hosts in place.
    by_ip = _fold_service_findings(store, hosts, analysis, "ldap",
                                   _ldap.findings_to_vulns, "LDAP")
    # Persist any DC that gained LDAP accounts but produced no LDAP vuln row (e.g. an
    # LDAPS host with authenticated enum but no anonymous/cleartext finding).
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        if t.get("auth_ok") and t["ip"] not in by_ip and t["ip"] in host_by_ip:
            store.upsert_host(host_by_ip[t["ip"]], merge=False)
    if active:                       # bound/read the LDAP port -> auto-tick vuln-scan
        _mark_capability_scanned(store, tgts)
    total_accts = sum(t.get("auth_users", 0) for t in tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    extra = (f" ({total_accts} account(s) enumerated -> Users & Accounts / AD Quick Wins)"
             if total_accts else "")
    print(f"    -> LDAP sheet written{extra}; findings folded into the main totals.")
    return 0
def cmd_api(args: argparse.Namespace) -> int:
    """API enumeration over the web services enum found: OpenAPI/Swagger specs,
    interactive API docs (Swagger UI / ReDoc / GraphiQL), and GraphQL introspection.
    Read-only GETs plus one GraphQL introspection POST."""
    from .. import api
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    active = not getattr(args, "no_probe", False)
    analysis = api.analyze(hosts, active=active, **_probe_kwargs(args, "api"))
    _report_partial(analysis["stats"])
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No web services to enumerate for APIs. Run `enum`/`vulns` first, or "
              "target hosts with HTTP/S ports.")
        store.close()
        return 0
    print(f"[+] Probed {len(tgts)} web endpoint(s) for API surface; "
          f"{len(analysis['findings'])} finding(s).")
    for f in analysis["findings"]:
        print(f"      {f['target']}  {f['title']}  ({f['severity']})")
    looted = 0
    for c in analysis.get("credentials", []):
        if store.add_credential(c):
            looted += 1
    if looted:
        print(f"      [+] {looted} credential(s) harvested from API specs -> store.")
    _fold_service_findings(store, hosts, analysis, "api", api.findings_to_vulns, "API")
    _mark_capability_scanned(store, tgts)
    _final_report(store, paths, store.get_meta("engagement")
                  or getattr(args, "title", "Recce Engagement"))
    store.close()
    _print_next(paths, args.output_dir, n=2)
    return 0
def cmd_snmp(args: argparse.Namespace) -> int:
    """Deep SNMP enumeration: brute common community strings over UDP 161, then read
    the system group + walk Windows users / processes / software. Read-only - recce
    never sends a SET (a read-write community is flagged by name, not exercised)."""
    return _run_service_scan(
        args, module="snmp", source="snmp", label="SNMP", noun="SNMP endpoint(s)",
        no_targets="[!] No SNMP-responsive hosts. (SNMP is UDP 161; recce probes it "
                   "directly, so target the hosts you expect to run it.)",
        fmt=_fmt_snmp, extra=_snmp_persist_accounts, udp=True)


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
def cmd_smtp(args: argparse.Namespace) -> int:
    """Deep SMTP enumeration: EHLO + envelope-only open-relay test (never sends DATA),
    VRFY user-enum, and STARTTLS posture (stdlib). Read-only - nothing is delivered."""
    return _run_service_scan(
        args, module="smtp", source="smtp", label="SMTP", noun="SMTP endpoint(s)",
        no_targets="[!] No SMTP endpoints in the datastore (no port 25/465/587). Run "
                   "`enum` against the mail hosts first.",
        fmt=_fmt_smtp)
def cmd_dns(args: argparse.Namespace) -> int:
    """Deep DNS enumeration: attempt a zone transfer (AXFR) for each domain recce has
    already discovered from hostnames (no brute force), + version.bind (stdlib). AXFR
    leaks the whole internal zone - an instant network map."""
    return _run_service_scan(
        args, module="dns", source="dns", label="DNS", noun="DNS endpoint(s)",
        no_targets="[!] No DNS endpoints in the datastore (no port 53 / domain service). "
                   "Run `enum` against the DNS hosts first.",
        fmt=_fmt_dns)


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


def cmd_rsync(args: argparse.Namespace) -> int:
    """Deep rsync-daemon enumeration: speak the rsync daemon protocol (stdlib), list
    the modules, and test each for anonymous access - an @RSYNCD: OK module is a
    CONFIRMED unauthenticated file exposure. Read-only (never transfers a file)."""
    return _run_service_scan(
        args, module="rsync", source="rsync", label="rsync", noun="rsync endpoint(s)",
        no_targets="[!] No rsync endpoints in the datastore (no port 873). Run `enum` "
                   "against the file hosts first.",
        fmt=_fmt_rsync)


def cmd_nfs(args: argparse.Namespace) -> int:
    """Deep NFS enumeration: speak ONC RPC (stdlib) to the portmapper + mountd, list
    the exports (showmount -e), and flag any shared to every host - a world-mountable
    export is a CONFIRMED exposure. Read-only (never mounts)."""
    return _run_service_scan(
        args, module="nfs", source="nfs", label="NFS", noun="NFS host(s)",
        no_targets="[!] No NFS endpoints in the datastore (no port 2049/111). Run "
                   "`enum` against the file hosts first.",
        fmt=_fmt_nfs)


def cmd_kerberos(args: argparse.Namespace) -> int:
    """Credential-less AD roasting: speak Kerberos (stdlib) to the DC, AS-REP roast
    every pre-auth-disabled account (capture a crackable hash with NO credential), and
    validate usernames via the KDC's pre-auth response. Read-only - no logon, no
    lockouts."""
    from .. import kerberos as _krb
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` (and, for the "
              "user list, `ldap`/`ad`) first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    # Candidate users: --user / --userlist override the enumerated account names.
    users = None
    if getattr(args, "user", None):
        users = list(args.user)
    elif getattr(args, "userlist", None):
        try:
            with open(args.userlist, encoding="utf-8", errors="replace") as fh:
                users = [ln.strip() for ln in fh if ln.strip()
                         and not ln.startswith("#")]
        except OSError as e:
            print(f"[x] Could not read --userlist {args.userlist!r}: {e}")
            store.close()
            return 1
    # Privileged names (for critical severity) from admin-flagged accounts.
    privileged = {(a.name or "").lower() for h in hosts for a in (h.accounts or [])
                  if (a.name and (str((a.attrs or {}).get("admincount", "")).lower()
                                  in ("1", "true")
                                  or a.name.lower() in ("administrator", "admin")))}

    active = not args.no_probe
    realm = getattr(args, "domain", "") or store.get_meta("domain") or ""
    # AS-REQ is one TCP connection to the DC per user, sequentially. Warn before a
    # large, slow, and network-noisy run so it isn't mistaken for a hang.
    n_users = len(users) if users is not None else len(_krb.candidate_users(hosts))
    if active and n_users > 200:
        print(f"[*] Testing {n_users} username(s) against the DC - one AS-REQ each, "
              f"sequentially ({n_users} connections to a single DC). This can take a "
              "while and is network-noisy; narrow with --userlist / --user if needed.")
    analysis = _krb.analyze(hosts, users=users, realm=realm,
                            dc_ip=getattr(args, "dc_ip", "") or "",
                            privileged=privileged, active=active,
                            **_probe_kwargs(args, "kerberos"))
    if not analysis["dc_ip"]:
        print("[!] No Kerberos DC found (no host with port 88). Pass --dc-ip, or run "
              "`enum` against the domain controller first.")
        store.close()
        return 0
    if not analysis["realm"]:
        print("[!] No realm/domain known. Pass --domain <REALM> (e.g. CORP.LOCAL).")
        store.close()
        return 0
    st = analysis["stats"]
    if not analysis["results"]:
        print(f"[!] No candidate usernames to test against {analysis['dc_ip']} "
              f"({analysis['realm']}). Enumerate users (ldap/ad) or pass --userlist.")
        store.close()
        return 0
    # If every AS-REQ came back "no_reply", the DC never answered - don't present
    # that as "0 valid" (which reads like a clean, complete test).
    if active and all(r["state"] == "no_reply" for r in analysis["results"]):
        print(f"[!] The DC {analysis['dc_ip']}:88 did not answer any AS-REQ "
              f"({st['users_tested']} attempted). Check the DC IP / that TCP 88 is "
              "reachable, then re-run. Nothing was concluded about these accounts.")
        store.close()
        return 0
    print(f"[+] Kerberos {analysis['realm']} @ {analysis['dc_ip']}: tested "
          f"{st['users_tested']} user(s) -> {st['valid']} valid, "
          f"{st['roastable']} AS-REP roastable.")
    for r in analysis["results"]:
        if r["state"] == "roastable":
            print(f"      [ROASTABLE] {r['user']}")

    _fold_service_findings(store, hosts, analysis, "kerberos",
                           _krb.findings_to_vulns, "Kerberos")
    if active:
        _mark_capability_scanned(store, [{"ip": analysis["dc_ip"], "port": 88}])
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> Kerberos sheet written; findings folded into the main totals.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # honor Excel edits before regenerating
    # Persist the QoD noise floor so every later regeneration honors it too. 0 shows all;
    # 70 (MIN_QOD_VISIBLE) hides banner/version leads; higher shows only verified findings.
    min_qod = getattr(args, "min_qod", None)
    if min_qod is not None:
        store.set_meta("min_qod", str(max(0, min_qod)))
        if min_qod > 0:
            print(f"[*] Filtering the report to findings with QoD >= {min_qod} "
                  "(--min-qod 0 to show all).")
    show_refuted = getattr(args, "show_refuted", None)
    if show_refuted is not None:
        store.set_meta("show_refuted", "1" if show_refuted else "0")
        if show_refuted:
            print("[*] Including refuted findings (an NSE check reported NOT VULNERABLE) "
                  "in the report.")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0


def cmd_fieldkit_export(args: argparse.Namespace) -> int:
    """Export the engagement as a seed for the fieldkit exploitation kit."""
    from .. import fieldkit
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']} - run `enum` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    hosts = [h for h in hosts if h.is_up]
    if not hosts:
        print("[!] No live hosts to export. Run `enum`/`vulns` first.")
        store.close()
        return 1
    title = store.get_meta("engagement") or args.title
    creds = store.all_credentials()
    out_dir = os.path.join(args.output_dir, "fieldkit")
    os.makedirs(out_dir, exist_ok=True)
    bridge = fieldkit.build_bridge(hosts, engagement=title, generated=_now(), creds=creds)

    users = fieldkit.collect_users(hosts, creds)
    cred_lines = fieldkit.collect_creds(creds)
    files = {
        "ports.gnmap": fieldkit.build_gnmap(hosts),
        "smb-null.txt": fieldkit.build_smb_null(hosts),
        "recce-bridge.json": json.dumps(bridge, indent=2) + "\n",
        "FIELDKIT.md": fieldkit.build_plan_md(bridge),
        "users.txt": ("\n".join(users) + "\n") if users
                     else "# (recce enumerated no usernames yet — run credenum / ldap)\n",
        "creds.txt": ("# known credentials (reference for gen_shell.py) — "
                      "domain/user:secret\n" + "\n".join(cred_lines) + "\n") if cred_lines
                     else "# (recce holds no captured credentials yet)\n",
    }
    for name, content in files.items():
        # Explicit UTF-8: FIELDKIT.md/ports.gnmap/etc. embed real finding text and
        # captured usernames/credentials (creds.txt's own boilerplate even has an
        # em-dash) - the platform default is locale-dependent (e.g. cp1252 on
        # Windows) and would raise UnicodeEncodeError there.
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            fh.write(content)
    _relax_perms(out_dir)

    actionable = sum(1 for h in bridge["hosts"]
                     if h["suggested"] or h["findings"] or h["exploit_cmds"])
    print(f"[+] fieldkit seed written to {out_dir}/ "
          f"({len(bridge['hosts'])} live host(s), {actionable} with a fieldkit route, "
          f"{len(users)} user(s), {len(creds)} cred(s)):")
    print("    ports.gnmap        -> sweep.py triage --nmap ports.gnmap")
    print("    smb-null.txt       -> sweep.py triage --nxc smb-null.txt")
    print("    recce-bridge.json  -> sweep.py triage --recce recce-bridge.json  (richest)")
    print("    FIELDKIT.md        -> human, severity-ranked attack plan")
    print("    users.txt/creds.txt-> gen_spray.py --users / gen_shell.py")
    print(f"    Next (in the fieldkit checkout): "
          f"python3 access/network/sweep.py triage --recce {out_dir}/recce-bridge.json")
    store.close()
    return 0


def cmd_fieldkit_import(args: argparse.Namespace) -> int:
    """Fold a fieldkit findings.json (proven exploitation) back into the workbook + report."""
    from .. import fieldkit
    from ..models import Host
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']} - run `enum` first, or `import` a scan.")
        return 1
    if not os.path.exists(args.findings):
        print(f"[x] No such file: {args.findings}")
        return 1
    try:
        from .. import importers
        with open(args.findings, "rb") as fh:
            data = json.loads(importers.decode_bytes(fh.read()))   # UTF-16/BOM-safe (Windows tooling)
    except (OSError, ValueError) as e:
        print(f"[x] Cannot read {args.findings}: {e}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)

    by_host = fieldkit.findings_to_hosts(data)
    if not by_host:
        print("[!] No usable findings in the file (need affected_host + steps).")
        store.close()
        return 1
    all_hosts = store.all_hosts()
    hosts_by_ip = {h.ip: h for h in all_hosts}
    # Resolve a hostname-only finding (affected_host had no IP) onto the host recce
    # already enumerated under that name, so it merges instead of forking a synthetic
    # `fieldkit:<name>` entry. First hostname wins on a collision.
    hosts_by_name = {}
    for h in all_hosts:
        for hn in h.hostnames:
            hosts_by_name.setdefault(hn.lower(), h)
    added_total = created = touched = 0
    for key, bucket in by_host.items():
        h = hosts_by_ip.get(key)
        if h is None and not bucket["ip"] and bucket["hostname"]:
            h = hosts_by_name.get(bucket["hostname"].lower())   # match by hostname
        if h is None:
            subnet = (".".join(key.split(".")[:3]) + ".0/24") if bucket["ip"] else ""
            h = Host(ip=key, subnet=subnet, enumerated=True)
            if bucket["hostname"]:
                h.hostnames = [bucket["hostname"]]
            created += 1
        elif bucket["hostname"] and bucket["hostname"] not in h.hostnames:
            h.hostnames.append(bucket["hostname"])
        have = {(v.title, v.port) for v in h.vulns}
        new = [v for v in bucket["vulns"] if (v.title, v.port) not in have]
        if not new:
            continue
        for v in new:
            v.ip = h.ip                        # keep Vuln.ip aligned with the host it lands on
        h.vulns.extend(new)
        # A proven fieldkit finding is a confirmed foothold on the host.
        if not h.access_gained:
            h.access_gained = True
            h.access_detail = h.access_detail or "fieldkit: proven exploitation (imported findings)"
        store.upsert_host(h)
        added_total += len(new)
        touched += 1

    print(f"[+] Imported {added_total} fieldkit finding(s) across {touched} host(s)"
          + (f" ({created} new host entry/entries)" if created else "") + ".")
    print("    Source 'fieldkit' (confidence 'confirmed') -> Vulnerabilities sheet, "
          "report, and write-ups. Hosts marked access-gained.")
    if added_total:
        title = store.get_meta("engagement") or args.title
        _generate_reports(store, paths, title)
    store.close()
    return 0
def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the web workbench for this engagement. One recce instance hosts it; the
    team opens http://<this-box>:<port> in a browser over the LAN. Run scans from the
    UI, work the Hosts/Findings/Act/Credentials tabs, import tool output, collaborate
    (claim/assign, presence, activity, chat), and export reports. Unauthenticated -
    run only on a trusted engagement network."""
    _open_paths(args.output_dir)          # ensure the engagement dir exists (scan from UI)
    try:
        import uvicorn
        from .webui.app import create_app
    except Exception:
        print("[x] The web workbench needs fastapi + uvicorn (bundled in the airgap "
              "package). For a dev install: pip install 'recce[bundle]'.")
        return 1
    app = create_app(args.output_dir)
    print(f"[+] recce workbench -> http://{args.host}:{args.port}   "
          f"(engagement: {args.output_dir})")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("    ⚠ UNAUTHENTICATED and reachable on this network: anyone who can reach "
              "the URL gets\n      full access (findings, credentials, scans). Run only on a "
              "TRUSTED engagement\n      network - or use --host 127.0.0.1 to keep it local.")
    print("    Open it in a browser; share the URL with your team on the LAN. Ctrl-C to stop.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # pick up latest Excel edits
    tracking = store.get_tracking()
    hosts = store.all_hosts()
    cov = tr.compute_coverage(hosts, tracking)
    labels = {"hosts": "Hosts", "services": "Services", "vulns": "Vulnerabilities",
              "web": "Web", "exploits": "Exploits", "quick_wins": "AD Quick Wins",
              "accounts": "Users & Accounts"}

    def bar(pct):
        f = round(pct / 5)
        return "#" * f + "-" * (20 - f)

    title = store.get_meta("engagement") or "engagement"
    print(f"\n== Coverage: {title} ==\n")

    # Scan issues first - the operator needs to know if anything failed/incomplete.
    counts = store.count_issues()
    if counts.get("total"):
        print(f"  ⚠ {counts['total']} scan issue(s): {counts.get('error', 0)} error, "
              f"{counts.get('warning', 0)} incomplete "
              f"(Overview tab / {paths['log']})")
        for i in store.get_issues()[:8]:
            print(f"      [{i['level'].upper()}] {i['ip']} {i['message']}")
        if counts["total"] > 8:
            print(f"      ... and {counts['total'] - 8} more")
        print()

    o = cov["overall"]
    print(f"  OVERALL      [{bar(o['pct'])}] {o['pct']:3d}%  {o['done']}/{o['total']}")
    print()
    for cat in tr.COVERAGE_CATEGORIES:
        c = cov[cat]
        print(f"  {labels[cat]:<13}[{bar(c['pct'])}] {c['pct']:3d}%  {c['done']}/{c['total']}")

    # Per-step completion, counting only hosts the step applies to.
    def phase_count(step):
        applic = [h for h in hosts if tr.step_applies(h, step)]
        return sum(1 for h in applic if tr.step_auto(h, step)), len(applic)

    def manual_count(step):
        applic = [h for h in hosts if tr.step_applies(h, step)]
        done = sum(1 for h in applic
                   if tracking.get(tr.step_key(step, h.ip), (False, ""))[0])
        return done, len(applic)

    def merged_count(step):
        # Matches the Checklist cell: operator tick if set, else the auto/derived state.
        applic = [h for h in hosts if tr.step_applies(h, step)]
        done = 0
        for h in applic:
            k = tr.step_key(step, h.ip)
            done += 1 if (tracking[k][0] if k in tracking
                          else tr.step_auto(h, step)) else 0
        return done, len(applic)

    en_d, en_t = phase_count("enum")
    vs_d, vs_t = phase_count("vuln")
    web_d, web_t = phase_count("web")
    db_d, db_t = phase_count("db")
    open_ports = [p for h in hosts for p in h.open_ports]
    scanned_ports = sum(1 for p in open_ports if p.vuln_scanned)
    print("\n  Tool progress (auto) - per step, hosts complete / applicable:")
    print(f"    Enumerated    {en_d}/{en_t}")
    print(f"    Vuln-scanned  {vs_d}/{vs_t}"
          + (f"   ({scanned_ports}/{len(open_ports)} open ports)" if open_ports else ""))
    print(f"    Web           {web_d}/{web_t}   (hosts serving HTTP/HTTPS)")
    print(f"    DB-scanned    {db_d}/{db_t}   (hosts with DB services)")
    ac_d, ac_t = merged_count("access")
    print(f"    Access gained {ac_d}/{ac_t}   (foothold: creds/admin/SSH/MSSQL "
          "- see `recce access`)")

    # Deep service-module coverage (mssql / smb / ftp / docker / kubernetes): for each
    # module, how many hosts with an applicable service have actually had it run.
    svc_cov = _service_module_coverage(store, hosts)
    shown = [m for m in svc_cov if m["applicable"]]
    if shown:
        print("\n  Service deep-dives (per applicable service) - hosts run / applicable:")
        for m in shown:
            flag = "" if m["covered"] >= m["applicable"] else f"   ! run: {m['command']}"
            print(f"    {m['name']:<13} {m['covered']}/{m['applicable']}{flag}")

    # Manual sign-offs (from your ticks): AD review + the kill-chain.
    ad_d, ad_t = manual_count("ad")
    cr_d, cr_t = manual_count("creds")
    lat_d, lat_t = manual_count("lateral")
    pe_done = sum(1 for h in hosts if h.privesc_checked)
    print("\n  Manual sign-offs (from your ticks) - hosts done / applicable:")
    print(f"    AD reviewed   {ad_d}/{ad_t}   (domain controllers / directory hosts)")
    print(f"    Priv-esc      {pe_done}/{len(hosts)}   (post-exploitation performed)")
    print(f"    Creds got     {cr_d}/{cr_t}")
    print(f"    Lateral       {lat_d}/{lat_t}")
    pending = [h.ip for h in hosts if h.enumerated
               and any(not p.vuln_scanned for p in h.open_ports)]
    if pending:
        print(f"    ! still to vuln-scan: {', '.join(pending[:15])}"
              + (" ..." if len(pending) > 15 else ""))

    print("\n  By subnet (hosts reviewed):")
    for subnet, s in sorted(tr.subnet_coverage(hosts, tracking).items()):
        print(f"    {subnet:<20} {s['pct']:3d}%  {s['done']}/{s['total']}")

    # Outstanding high-value items.
    unreviewed_dc = [h for h in ad.domain_controllers(hosts)
                     if not tracking.get(tr.host_key(h.ip), (False, ""))[0]]
    unreviewed_vuln_hosts = [
        h for h in hosts
        if any(v.severity in ("critical", "high") for v in h.vulns)
        and not tracking.get(tr.host_key(h.ip), (False, ""))[0]
    ]
    scope = store.get_meta("port_scope")
    if scope:
        full = "65535" in scope
        print(f"\n  {'·' if full else '!!'} Port scope: {scope}"
              + ("" if full else " - PARTIAL (not a full scan; re-run with --all-ports)"))
    incomplete = [h for h in hosts if getattr(h, "incomplete_scan", False)]
    if incomplete:
        print("\n  !! INCOMPLETE port sweeps (host-timeout) - these port lists are "
              "PARTIAL, so downstream phases may be missing services:")
        print("     " + ", ".join(h.ip for h in sorted(incomplete, key=lambda x: _ip_key(x.ip))))
        print("     Re-scan with a larger --host-timeout (or --top-ports to narrow "
              "scope) to complete them.")
    if unreviewed_dc:
        print("\n  ! Unreviewed Domain Controllers: "
              + ", ".join(h.ip for h in unreviewed_dc))
    if unreviewed_vuln_hosts:
        print("  ! Unreviewed hosts with high/critical findings: "
              + ", ".join(h.ip for h in sorted(unreviewed_vuln_hosts, key=lambda x: _ip_key(x.ip))))

    # Suggested next step, so you always know what to run.
    o = args.output_dir
    if not hosts:
        nxt = f"recce enum <targets> -o {o}   # nothing scanned yet"
    elif en_d < en_t or vs_d < vs_t:
        nxt = f"recce vulns --unscanned -o {o}   # vuln-scan the rest"
    elif db_t and db_d < db_t:
        nxt = f"recce db -o {o}   # enumerate the databases"
    elif any(m["applicable"] > m["covered"] for m in svc_cov):
        pend = [m for m in svc_cov if m["applicable"] > m["covered"]]
        if len(pend) == 1:
            m = pend[0]
            gap = m["applicable"] - m["covered"]
            nxt = (f"{m['command']} -o {o}   # deep-enum {m['name']} "
                   f"({gap} applicable host(s) not yet run)")
        else:
            names = ", ".join(m["name"] for m in pend)
            nxt = (f"recce sweep -o {o}   # run the deep modules in one shot "
                   f"({names} pending; add creds via `recce credsweep`)")
    elif pe_done < len(hosts):
        nxt = f"recce privesc -o {o}   # build the priv-esc playbook"
    else:
        nxt = "all phases complete - review the workbook and tick Reviewed."
    print(f"\n  Next: {nxt}")
    print()
    store.close()
    return 0


def cmd_access(args: argparse.Namespace) -> int:
    """Record and review initial access (footholds) per host. recce auto-derives
    access as the credentialed phases run (valid creds / local admin / SSH / MSSQL);
    use this to see the picture across the engagement, or to record a foothold you
    gained by other means so the Checklist Access step ticks."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    changed: list = []

    if args.host:
        targeted = set(args.host)
        for h in hosts:
            if h.ip not in targeted:
                continue
            if args.undo:
                if h.access_gained:
                    h.access_gained, h.access_detail = False, ""
                    changed.append(h)
            else:
                h.access_gained = True
                h.access_detail = (args.note or h.access_detail
                                   or "manual: operator-recorded foothold")
                changed.append(h)
        for h in changed:
            store.upsert_host(h, merge=False)
        print(f"[+] Access {'cleared on' if args.undo else 'recorded on'} "
              f"{len(changed)} host(s).")
    else:
        # Re-derive from the stable credentialed findings (credenum / SSH); never
        # clears a flag a module already set (e.g. MSSQL access).
        for h in hosts:
            if h.access_gained:
                continue
            detail = tr.access_from_findings(h)
            if detail:
                h.access_gained, h.access_detail = True, detail
                changed.append(h)
        for h in changed:
            store.upsert_host(h, merge=False)
        if changed:
            print(f"[+] Derived access on {len(changed)} host(s) from existing findings.")

    applicable = [h for h in hosts if h.open_ports]
    gained = [h for h in sorted(hosts, key=lambda x: _ip_key(x.ip)) if h.access_gained]
    print(f"\n  Access gained: {len(gained)}/{len(applicable)} host(s) with a foothold\n")
    for h in gained:
        name = f" ({h.hostname})" if h.hostname else ""
        print(f"    {h.ip}{name}  -  {h.access_detail}")
    if not gained:
        print("    (none yet - gain access via `credsweep` / `credenum` / `mssql`, or "
              "record one: `recce access --host IP --note '...'`)")
    print()

    if changed:
        _generate_reports(store, paths, store.get_meta("engagement") or args.title)

    # --act: cap the pipeline with the Act phase - auto-run the read-only links (loot the
    # flagged unauth services, refresh the spray plan) and print the ranked action plan.
    if getattr(args, "act", False):
        from .. import act
        print("\n" + "=" * 60)
        print("[*] Act phase - what to do with what was found")
        print("=" * 60)
        summary = act.execute_auto(store, args.output_dir)
        if summary["looted"]:
            print(f"[+] Auto-looted {len(summary['looted'])} credential(s) (read-only); "
                  "spray plan refreshed.")
        cards = act.action_plan(_selected_hosts(store.all_hosts(), args),
                                store.all_credentials(), args.output_dir)
        for c in act.top_moves(cards, 3):
            where = "" if c.target == "engagement" else f" @ {c.target}"
            print(f"  ★ [{c.archetype}] {c.title}{where}  ->  {c.yields}")
            print(f"        $ {c.command}")
        print(f"\n  Full ranked plan:  recce act -o {args.output_dir}")
    store.close()
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # capture pending Excel edits first
    reviewed = not args.undo
    keys: list[str] = []

    for ip in args.host or []:
        keys.append(tr.host_key(ip))
        if args.cascade:  # also mark all that host's services
            h = store.get_host(ip)
            if h:
                keys += [tr.svc_key(ip, p.protocol, p.portid) for p in h.open_ports]
    for spec in args.service or []:
        ip, _, port = spec.partition(":")
        if not port.isdigit():
            print(f"[!] Skipping --service {spec!r}: expected IP:PORT (numeric port).")
            continue
        portid = int(port)
        # Resolve the real protocol from the stored host so a UDP service ticks the
        # right coverage key (hardcoding tcp silently no-ops for UDP items).
        proto = "tcp"
        h = store.get_host(ip)
        if h:
            match = next((p for p in h.open_ports if p.portid == portid), None)
            if match:
                proto = match.protocol
        keys.append(tr.svc_key(ip, proto, portid))
    keys += args.key or []

    if not keys:
        print("[x] Nothing to mark. Use --host, --service ip:port, or --key.")
        store.close()
        return 1
    for k in keys:
        store.set_reviewed(k, reviewed, notes=args.note)
    print(f"[+] Marked {len(keys)} item(s) as {'reviewed' if reviewed else 'not reviewed'}.")
    _generate_reports(store, paths, store.get_meta("engagement") or args.title, quiet=True)
    store.close()
    return 0


# --- demo command ----------------------------------------------------------------

def cmd_demo(args: argparse.Namespace) -> int:
    sample = os.path.join(os.path.dirname(__file__), "sample_scan.xml")
    if not os.path.exists(sample):
        print("[x] Sample XML missing.")
        return 1
    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    store.set_meta("engagement", "DEMO engagement")
    store.set_scope("10.0.10.0/24", 254)   # demo scope: three /24s
    store.set_scope("10.0.20.0/24", 254)
    store.set_scope("10.0.30.0/24", 254)   # in scope but no live hosts found
    from ..models import Exploit
    from ..targets import _subnet_of
    # Stand-in for searchsploit output (unavailable offline in the demo).
    demo_exploits = {
        "10.0.20.6": [Exploit(ip="10.0.20.6", port=21, product="vsftpd", version="2.3.4",
                              edb_id="17491", title="vsftpd 2.3.4 - Backdoor Command Execution",
                              type="remote", path="unix/remote/17491.rb",
                              cves=["CVE-2011-2523"])],
        "10.0.20.5": [Exploit(ip="10.0.20.5", port=80, product="Apache httpd", version="2.4.41",
                              edb_id="50383", title="Apache 2.4.49/2.4.50 - Path Traversal & RCE",
                              type="webapps", path="multiple/webapps/50383.sh",
                              cves=["CVE-2021-41773", "CVE-2021-42013"])],
    }
    for h in np.parse_nmap_xml(sample):
        h.subnet = _subnet_of(h.ip)
        ad.identify_roles(h)
        ad.parse_signing_and_ntlm(h)
        h.exploits = demo_exploits.get(h.ip, [])
        from .. import vulndb
        vulndb.assess_host_inplace(h)   # offline version->CVE findings
        h.enumerated = True
        # Confirmed footholds, so the map's access overlay has something to show.
        if h.ip == "10.0.20.6":
            h.access_gained = True
            h.access_detail = "vsftpd 2.3.4 backdoor (RCE) → shell"
        elif h.ip == "10.0.10.25":
            h.access_gained = True
            h.access_detail = "SMB admin via reused local Administrator hash"
        # Leave one host enumerated-only to show the Checklist's mixed states.
        if h.ip != "10.0.20.6":
            for p in h.ports:
                p.vuln_scanned = True
            h.db_scanned = True
            h.privesc_checked = True
        store.upsert_host(h)
    _demo_bloodhound(store)
    _demo_credentials(store)
    _generate_reports(store, paths, "DEMO engagement")
    store.close()
    print("[+] Demo reports generated from bundled sample scan.")
    return 0
def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if getattr(args, "command", None) is None:
        # Bare `recce` (no subcommand): a friendly quickstart beats an argparse error.
        return _print_quickstart()
    _rc = _setup_proxy(args)
    if _rc is not None:
        return _rc
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # A scan phase catches this internally to save partial results; this is the
        # backstop for any command that doesn't, so Ctrl-C is never an ugly crash.
        print("\n[!] Interrupted. Results collected so far were saved; re-run "
              "(with --resume on a scan) to continue.")
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for field use
        # Never dump a raw traceback at a tester mid-engagement. Per-host scan work
        # is already persisted crash-safe, so their data survives; give a clean
        # message and a way to get the details for a bug report.
        print(f"\n[x] recce hit an unexpected error: {type(e).__name__}: {e}")
        if os.environ.get("RECCE_DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            print("    Any data collected so far is saved. Re-run to continue; "
                  "set RECCE_DEBUG=1 to see the full traceback for a bug report.")
        return 1
    finally:
        # Hand the engagement folder back to the sudo-invoking operator on every exit
        # path (success, Ctrl-C, or crash) so a sudo run never leaves them locked out of
        # outputs. _relax_perms restores ownership + OWNER-ONLY perms (dirs 0700, files
        # 0600) - never group/world-readable, since the tree holds captured creds/hashes.
        out_dir = getattr(args, "output_dir", None)
        if out_dir:
            _relax_perms(out_dir)
