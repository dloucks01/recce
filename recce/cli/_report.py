"""Command handlers for the `report` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_writeups` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import os

from .. import ad
from ..core import tracking as tr

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_writeups', 'cmd_writeup', 'cmd_report', 'cmd_retest', 'cmd_status', 'cmd_review']




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
    from ..report.docx import build_writeups
    from ..report import screenshot

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
        from ..report.docx import build_combined
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
    from ..report.docx import list_findings, build_one_writeup

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
        from ..report import screenshot
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




def cmd_retest(args: argparse.Namespace) -> int:
    """Compare THIS engagement against a prior one, emit a retest report.

    The current engagement's DB is the "curr" side; --against points at the
    previous engagement's directory or DB path. Verdicts are computed on the
    fly; nothing is written to either DB. The retest .docx lands in -o and
    includes: cover with counts (fixed / still-open / regressed / new),
    per-verdict finding lists (still-open first — those are the ones the
    client still owes you)."""
    from ..core.store import Store
    from ..report import retest as _retest
    from ..report.retest_docx import build_retest_report
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']} — retest needs the current engagement's DB.")
        return 1
    prev = args.prev
    if os.path.isdir(prev):
        prev_db = os.path.join(prev, "results.sqlite")
    else:
        prev_db = prev
    if not os.path.exists(prev_db):
        print(f"[x] No previous datastore at {prev_db}")
        return 1
    print(f"[*] Comparing {paths['db']} (current) vs {prev_db} (previous)…")
    with Store(prev_db) as prev_store, Store(paths["db"]) as curr_store:
        prev_hosts = prev_store.all_hosts()
        curr_hosts = curr_store.all_hosts()
    verdicts = _retest.compare(prev_hosts, curr_hosts)
    summary = _retest.summary(verdicts)
    print(f"[+] {summary['total']} finding(s) across the two engagements:")
    for k in ("still-open", "regressed", "new", "fixed"):
        print(f"    {k:12s} {summary['counts'].get(k, 0)}")
    out_path = os.path.join(args.output_dir, args.out_name)
    with Store(paths["db"]) as st:
        title = st.get_meta("engagement") or args.title or "Retest report"
        meta = {k: (st.get_meta(k) or "") for k in
                ("client", "start_date", "end_date", "testers", "tester", "roe_notes", "client_logo")}
    build_retest_report(verdicts, summary, out_path, title=title,
                        meta=meta, eng_dir=args.output_dir)
    print(f"[+] Retest report written to {out_path}")
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
