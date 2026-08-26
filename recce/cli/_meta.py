"""Command handlers for the `meta` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_doctor` still works and the
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


__all__ = ['cmd_doctor', 'cmd_serve', 'cmd_demo', 'cmd_encdec',
           'cmd_loot_scan', 'cmd_sqli']




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


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the web workbench for this engagement. One recce instance hosts it; the
    team opens http://<this-box>:<port> in a browser over the LAN. Run scans from the
    UI, work the Hosts/Findings/Act/Credentials tabs, import tool output, collaborate
    (claim/assign, presence, activity, chat), and export reports. Unauthenticated -
    run only on a trusted engagement network."""
    _open_paths(args.output_dir)          # ensure the engagement dir exists (scan from UI)
    try:
        import uvicorn
        from ..webui.app import create_app
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



def cmd_encdec(args: argparse.Namespace) -> int:
    """Apply an encoder/decoder operation to input, or list the catalogue.

    Examples:
      recce encdec base64-decode 'aGVsbG8='
      echo 'https://ex.com/?q=hi world' | recce encdec url-encode
      recce encdec jwt-decode eyJhbGciOi...
      recce encdec hmac-sha256 -k mysecret 'payload text'
      recce encdec --chain url-decode json-pretty
      recce encdec --list
    """
    from .. import encdec

    if args.list:
        ops = encdec.list_ops()
        print(f"{'operation':<26}  key?  description")
        print(f"{'-' * 26}  ----  {'-' * 40}")
        for op in ops:
            k = "yes" if op["requires_key"] else "no "
            print(f"{op['name']:<26}  {k}   {op['description']}")
        return 0

    # Resolve the input: positional arg or stdin.
    if args.input is not None:
        input_text = args.input
    else:
        if sys.stdin.isatty() and not args.chain:
            # No stdin, no positional — that's a usage error.
            print("[!] provide an input string, pipe via stdin, or use --list.")
            return 2
        input_text = sys.stdin.read()
        # Trim the trailing newline that a pipe from `echo` always adds — most
        # ops treat it as data, and it silently breaks base64 padding.
        if input_text.endswith("\n"):
            input_text = input_text[:-1]

    try:
        if args.chain:
            steps: list = []
            for op in args.chain:
                _fn, _desc, needs_key = encdec.OPERATIONS.get(op, (None, "", False))
                if needs_key:
                    steps.append((op, args.key))
                else:
                    steps.append(op)
            out = encdec.chain(steps, input_text)
        else:
            if not args.op:
                print("[!] operation required (or use --list / --chain)")
                return 2
            out = encdec.apply(args.op, input_text, key=args.key)
    except encdec.EncDecError as e:
        print(f"[x] {e}")
        return 1
    # Print without adding a trailing newline if the output already has one —
    # keeps `recce encdec base64-decode` pipeable cleanly.
    if out.endswith("\n"):
        sys.stdout.write(out)
    else:
        print(out)
    return 0


def cmd_loot_scan(args: argparse.Namespace) -> int:
    """Walk the engagement's evidence tree and add loot findings for
    Kerberos ticket files, credential-bearing files (.aws/credentials,
    .netrc, id_rsa, browser saved logins), .git repository dumps, and
    configs with embedded secrets (API keys, DB URLs, private keys,
    JWTs). Read-only — never mutates evidence files.

    Newly-discovered findings persist to the datastore and show up in
    the Findings tab / report. Idempotent: re-runs dedup against
    existing loot findings on the same host by (script_id, title).
    """
    from ..intake.loot import scan_evidence
    from ..store import Store
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    new_vulns = scan_evidence(args.output_dir)
    if not new_vulns:
        print("[+] Evidence scanned — no loot findings surfaced. Check that "
              f"files exist under {args.output_dir}/evidence/<ip>/.")
        return 0
    print(f"[+] {len(new_vulns)} loot candidate(s) surfaced from the evidence tree:")
    by_cat: dict = {}
    for v in new_vulns:
        by_cat.setdefault(v.script_id, []).append(v)
    for sid, vs in sorted(by_cat.items()):
        print(f"      [{sid}] {len(vs)}")
        for v in vs[:5]:
            print(f"        · {v.ip:15}  [{v.severity}]  {v.title[:80]}")
        if len(vs) > 5:
            print(f"        · … (+{len(vs)-5} more)")
    if getattr(args, "dry_run", False):
        print("[*] --dry-run: findings NOT persisted.")
        return 0
    store = _open_store(paths["db"])
    if store is None:
        return 1
    try:
        hosts_by_ip = {h.ip: h for h in store.all_hosts()}
        added = 0
        skipped_dup = 0
        skipped_noip = 0
        for v in new_vulns:
            h = hosts_by_ip.get(v.ip)
            if not h:
                skipped_noip += 1
                continue
            if any(x.script_id == v.script_id and x.title == v.title
                   for x in h.vulns):
                skipped_dup += 1
                continue
            h.vulns.append(v)
            store.upsert_host(h)
            added += 1
        print(f"[+] persisted {added} new finding(s) "
              f"(skipped {skipped_dup} dup, {skipped_noip} on unknown hosts).")
    finally:
        store.close()
    return 0


def cmd_sqli(args: argparse.Namespace) -> int:
    """Active SQL injection tester (C5, gated attack tier). Refuses to run
    unless --active-attacks is passed OR RECCE_ACTIVE_ATTACKS=1 is set,
    matching the module's own gate. Runs error-based / boolean-blind /
    time-based checks against each URL supplied as a target. Optional
    --sqlmap hands off to sqlmap for deeper testing.

    Usage:
      recce sqli --active-attacks 'http://target/vuln?id=1'
      recce sqli --active-attacks --sqlmap 'http://target/vuln?id=1'
    """
    from ..services import sqli as sqli_svc
    active = getattr(args, "active_attacks", False)
    use_sqlmap = getattr(args, "sqlmap", False)
    urls = args.targets or []
    if not urls:
        print("[x] sqli requires at least one URL to test.")
        return 1
    total_hits = 0
    for url in urls:
        print(f"\n[*] Testing {url}")
        try:
            if use_sqlmap:
                r = sqli_svc.run_sqlmap(url, active_attacks=active)
                print(f"    sqlmap: ok={r['ok']} injected={r['injected_params']}")
                total_hits += len(r["injected_params"])
            else:
                hits = sqli_svc.test_url_param(url, active_attacks=active)
                for h in hits:
                    print(f"    [{h['technique']:14}] param={h.get('param'):15}  "
                          f"{h.get('evidence','')[:60]}")
                total_hits += len(hits)
        except sqli_svc.ActiveAttacksDisabled as e:
            print(f"[x] {e}")
            return 2
        except Exception as e:  # noqa: BLE001
            print(f"[!] {url} failed: {e}")
    print(f"\n[+] {total_hits} injection point(s) confirmed across {len(urls)} URL(s).")
    return 0 if total_hits >= 0 else 1


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
