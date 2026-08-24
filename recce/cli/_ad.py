"""Command handlers for the `ad` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_bloodhound` still works and the
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
from .. import exploits
from .. import parser as np
from .. import scanner
from .. import tracking as tr
from ..models import Host
from ..report_excel import read_workbook_edits, update_workbook
from ..report_markdown import build_csv, build_markdown
from ..store import Store, StoreError
from ..targets import expand_excludes, explicit_targets, ip_matcher, load_targets

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_bloodhound', 'cmd_kerberos']




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
