"""Command handlers for the `creds` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_privesc` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core import tracking as tr

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_privesc', 'cmd_credenum', 'cmd_creds', 'cmd_deploy', 'cmd_access']




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


def cmd_creds(args: argparse.Namespace) -> int:
    """Stack credentials (auto-harvested + manually captured) and build/run a spray
    across the discovered SMB/WinRM/LDAP/MSSQL/RDP/SSH surface."""
    from ..creds import credentials as cr
    from ..core.models import Credential
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

    # POTFILE: fold cracked plaintexts back in. Runs before the stack is read so
    # a --potfile --plan in one invocation sprays what was just cracked.
    if getattr(args, "potfile", None):
        try:
            with open(args.potfile, encoding="utf-8", errors="replace") as fh:
                pot = fh.read()
        except OSError as e:
            print(f"[x] Could not read --potfile {args.potfile!r}: {e}")
            store.close()
            return 1
        cracked = cr.parse_potfile(pot, store.all_credentials(),
                                   os.path.join(args.output_dir, "loot"))
        if not cracked:
            print(f"[!] No cracked hashes in {args.potfile} matched anything recce holds.")
            print("    recce matches on the NT hashes it captured and the roasted "
                  "Kerberos hashes in loot/ - crack those and the plaintexts land here.")
        else:
            n = sum(1 for c in cracked if store.add_credential(c))
            print(f"[+] Folded in {n} cracked password(s)"
                  + (f" ({len(cracked) - n} already stacked)" if n < len(cracked) else "")
                  + f" from {os.path.basename(args.potfile)}.")
            for c in cracked:
                print(f"      {c.label}")
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
        # Show what came from the cross-service enum fold-in so the operator
        # sees the spray reach the accounts recce enumerated but never had
        # creds for — the whole point of the wire-up.
        enum_only = summary.get("enum_only_users") or []
        if enum_only:
            sources = summary.get("enum_only_sources") or []
            sample = ", ".join(enum_only[:8])
            print(f"    [+] {len(enum_only)} additional username(s) from "
                  f"engagement enum ({', '.join(sources) or 'unknown'}) folded "
                  f"into users.txt: {sample}"
                  + (" …" if len(enum_only) > 8 else ""))
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
        # Same enum-only summary --plan prints — after --run so the operator
        # sees which extra accounts actually got tested vs which came from
        # the credential store.
        enum_only = res.get("enum_only_users") or []
        if enum_only:
            sources = res.get("enum_only_sources") or []
            sample = ", ".join(enum_only[:8])
            print(f"    [+] {len(enum_only)} additional username(s) from "
                  f"engagement enum ({', '.join(sources) or 'unknown'}) "
                  f"included in the spray: {sample}"
                  + (" …" if len(enum_only) > 8 else ""))
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


def cmd_deploy(args: argparse.Namespace) -> int:
    """Push + run recce's read-only local-enum / priv-esc scripts across every host
    we have credentials for (SSH / WinRM / SMB), then fold the results in."""
    from ..creds import deploy
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
        from ..creds.stager import Stager, detect_lhost
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
