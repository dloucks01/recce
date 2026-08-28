"""Command handlers for the `act` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_next` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import os

from ..vuln import exploits
from ..core import parser as np
from ..core import scanner

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_next', 'cmd_act', 'cmd_attack', 'cmd_verify', 'cmd_poc', 'cmd_exploitplan', 'cmd_prove', 'cmd_attackpath']


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
    from ..act import workflow
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
    from ..act import attack
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
    from ..core import qod
    from ..vuln import verify
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


def cmd_poc(args: argparse.Namespace) -> int:
    """Assemble a per-CVE PoC dossier + Python harness skeleton from recce's OFFLINE
    intel (vulndb + KEV/EPSS + the local Exploit-DB + msf refs + build recipes), for the
    hosts affected in this engagement. With CVE args it targets exactly those; otherwise
    it uses the CVEs from the engagement's findings (`--confirmed` to gate to confirmed
    ones only). recce references published exploits and scaffolds a harness; it does not
    author weaponized exploit code."""
    from ..act import pocgen
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
    from ..act import exploitplan

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
    from ..vuln import proofs
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
    # Fold verdicts back onto the vuln records so the WebUI Findings tab and
    # every downstream report (exploit-plan / attack-path / writeups) can
    # filter by verdict. Match on (ip, port, vuln title) — proof results
    # carry the finding's actual title in the `finding` field (`vuln` is
    # the proof rule name, not the finding title). A stale prove run gets
    # overwritten — the newest verdict wins. Touched hosts are upserted
    # once at the end (not per-vuln) to keep the writes cheap.
    touched: set = set()
    by_key: dict = {}
    for r in results:
        by_key[(r['ip'], r['port'], r['finding'])] = r
    for host in hosts:
        for v in host.vulns:
            r = by_key.get((v.ip, v.port, v.title))
            if not r:
                continue
            v.verdict = r['verdict']
            v.verdict_evidence = list(r.get('evidence') or [])
            v.verdict_finish = r.get('finish', '')
            touched.add(host.ip)
    for host in hosts:
        if host.ip in touched:
            # merge=False because we're mutating already-loaded vulns
            # in-place. Default merge dedups by Vuln.key and KEEPS the
            # stored copy on collision — which would drop our updated
            # verdict fields silently. Overwriting with the loaded host
            # is safe here: prove doesn't add/remove vulns, only annotates.
            store.upsert_host(host, merge=False)
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
    from ..act import attackpath as ap

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
