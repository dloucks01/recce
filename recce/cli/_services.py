"""Command handlers for the `services` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_web` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import os
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed


from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_web', 'cmd_smb', 'cmd_ftp', 'cmd_docker', 'cmd_kubernetes', 'cmd_ldap',
           'cmd_api', 'cmd_snmp', 'cmd_smtp', 'cmd_dns', 'cmd_rsync', 'cmd_nfs',
           # T4 scanner-expansion additions:
           'cmd_zookeeper', 'cmd_kafka', 'cmd_etcd', 'cmd_consul', 'cmd_nomad',
           'cmd_prometheus', 'cmd_docker_registry', 'cmd_vnc', 'cmd_modbus',
           'cmd_rdp', 'cmd_ipmi', 'cmd_ntp', 'cmd_msrpc', 'cmd_winrm',
           'cmd_netbios', 'cmd_tftp', 'cmd_ipp', 'cmd_x11', 'cmd_sip', 'cmd_rservices']


def cmd_web(args: argparse.Namespace) -> int:
    """Deep-enumerate every web-facing endpoint: fingerprint the stack and run the
    non-intrusive checks (exposed .git/.env, server-status/actuator, directory
    listing, dangerous methods, cookie flags, headers/TLS). Findings fold into the
    workbook; each endpoint gets the exact Kali deep-scan commands."""
    from ..services import web
    print(BANNER)
    # --wordlist FILE augments the bundled 110-path HTTP list. The deep probe
    # layer (services.http._resolve_extra_paths) reads RECCE_HTTP_WORDLIST at
    # scan time; setting the env var here is cleaner than threading a param
    # through web.scan_host -> probes.http_findings -> enum_findings.
    wl = getattr(args, "wordlist", None)
    if wl:
        os.environ["RECCE_HTTP_WORDLIST"] = wl
        print(f"[*] HTTP path enum will augment bundled list with {wl!r}")
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


def cmd_smb(args: argparse.Namespace) -> int:
    """SMB offensive enumeration: credential-free stdlib negotiate probes (dialect /
    signing / SMBv1), then anonymous & credentialed share enumeration, a reversible
    writable-share proof, and the full runbook - folded into the main totals."""
    from ..services import smb
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
    from ..services import ftp
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
    from ..services import docker
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
    from ..services import kubernetes as k8s
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
    from ..services import ldap as _ldap
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
    from ..services import api
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


# ─── T4 scanner-expansion service handlers ────────────────────────────────
# All share _run_service_scan(). The formatters are simple `ip:port [tags]`
# strings — matches the shape helpers.py's other _fmt_* functions produce.

def _fmt_simple(label_extra):
    """Build a formatter that prints `ip:port · <label_extra>(t, active)`.
    Each T4 service passes a lambda that extracts its most-interesting probe
    fields (broker count, KEV flags, etc.) for the tester-visible summary."""
    def _fmt(t, active):
        core = f"{t['ip']}:{t['port']}"
        extra = label_extra(t, active) if callable(label_extra) else ""
        return f"{core}  {extra}".rstrip() if extra else core
    return _fmt


def cmd_zookeeper(args: argparse.Namespace) -> int:
    """Zookeeper 4-letter-word probe: ruok/stat baseline + dumping (dump/conf/
    cons/envi) + admin (wchc/wchp). Read-only."""
    return _run_service_scan(
        args, module="zookeeper", source="zookeeper", label="Zookeeper",
        noun="Zookeeper endpoint(s)",
        no_targets="[!] No Zookeeper endpoints in the datastore (port 2181). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: f"v{t.get('version','?')}" if a else ""))


def cmd_kafka(args: argparse.Namespace) -> int:
    """Kafka native MetadataRequest v1 probe: broker list + topic names.
    Read-only. Modern Kafka's ApiVersions handshake is done automatically."""
    return _run_service_scan(
        args, module="kafka", source="kafka", label="Kafka",
        noun="Kafka broker(s)",
        no_targets="[!] No Kafka endpoints in the datastore (port 9092). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: f"{t.get('brokers',0)} broker(s), {t.get('topics',0)} topic(s)"))


def cmd_etcd(args: argparse.Namespace) -> int:
    """etcd v2 + v3 unauthenticated read probe. TLS auto-fallback."""
    return _run_service_scan(
        args, module="etcd", source="etcd", label="etcd",
        noun="etcd endpoint(s)",
        no_targets="[!] No etcd endpoints in the datastore (port 2379). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: (t.get('version','?') +
                                       (' UNAUTH' if t.get('unauth_read') else ''))))


def cmd_consul(args: argparse.Namespace) -> int:
    """Consul HTTP API probe: services + KV + nodes, ACL disabled detection."""
    return _run_service_scan(
        args, module="consul", source="consul", label="Consul",
        noun="Consul endpoint(s)",
        no_targets="[!] No Consul endpoints in the datastore (port 8500). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: (t.get('version','?') +
                                       (' UNAUTH' if t.get('unauth') else ''))))


def cmd_nomad(args: argparse.Namespace) -> int:
    """Nomad HTTP API probe: jobs + allocations + nodes, ACL detection."""
    return _run_service_scan(
        args, module="nomad", source="nomad", label="Nomad",
        noun="Nomad endpoint(s)",
        no_targets="[!] No Nomad endpoints in the datastore (port 4646). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: (t.get('version','?') +
                                       (' UNAUTH' if t.get('unauth') else ''))))


def cmd_prometheus(args: argparse.Namespace) -> int:
    """Prometheus HTTP API probe: /-/healthy + /api/v1/status/config +
    /api/v1/query + /-/reload (admin write)."""
    return _run_service_scan(
        args, module="prometheus", source="prometheus", label="Prometheus",
        noun="Prometheus endpoint(s)",
        no_targets="[!] No Prometheus endpoints in the datastore (port 9090). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: 'v' + (t.get('version','?') or '?') +
                                       (' config-readable' if t.get('config_readable') else '')))


def cmd_docker_registry(args: argparse.Namespace) -> int:
    """Docker Registry v2 anonymous catalog probe (5000/tcp).
    Distinct from `docker` — that's the Engine API on 2375."""
    return _run_service_scan(
        args, module="docker_registry", source="docker-registry",
        label="Docker Registry", noun="Docker Registry endpoint(s)",
        no_targets="[!] No Docker Registry endpoints (port 5000). "
                   "Run `enum` against the registry hosts first.",
        fmt=_fmt_simple(lambda t, a: f"{t.get('repositories',0)} repo(s)"))


def cmd_vnc(args: argparse.Namespace) -> int:
    """VNC RFB handshake + security-type list. Detects no-auth (type 1) and
    DES-only (type 2). Read-only."""
    return _run_service_scan(
        args, module="vnc", source="vnc", label="VNC",
        noun="VNC endpoint(s)",
        no_targets="[!] No VNC endpoints in the datastore (port 5900-5906). "
                   "Run `enum` against the workstation targets first.",
        fmt=_fmt_simple(lambda t, a: 'NO-AUTH' if t.get('no_auth') else 'password-gated'))


def cmd_modbus(args: argparse.Namespace) -> int:
    """Modbus/TCP probe: Function 0x03 (Read Holding Registers) + Function
    0x2B (Read Device Identification). Read-only, no writes."""
    return _run_service_scan(
        args, module="modbus", source="modbus", label="Modbus",
        noun="Modbus/TCP device(s)",
        no_targets="[!] No Modbus endpoints in the datastore (port 502). "
                   "Run `enum` against the OT segment first.",
        fmt=_fmt_simple(lambda t, a: (t.get('vendor','?') + ' ' +
                                       t.get('product','?')).strip()))


def cmd_rdp(args: argparse.Namespace) -> int:
    """RDP X.224 Connection Request probe: negotiates security mode, detects
    NLA (Network Level Authentication) off vs. required."""
    return _run_service_scan(
        args, module="rdp", source="rdp", label="RDP",
        noun="RDP endpoint(s)",
        no_targets="[!] No RDP endpoints in the datastore (port 3389). "
                   "Run `enum` against the Windows targets first.",
        fmt=_fmt_simple(lambda t, a: 'NLA OFF' if t.get('standard_rdp_accepted')
                                     else ('NLA required' if t.get('nla_required') else '?')))


def cmd_ipmi(args: argparse.Namespace) -> int:
    """IPMI UDP 623 Get Channel Auth Capabilities probe: cipher-zero
    (CVE-2013-4786), null-user, anonymous logon, weak MD2/MD5 auth."""
    return _run_service_scan(
        args, module="ipmi", source="ipmi", label="IPMI",
        noun="IPMI/BMC endpoint(s)",
        no_targets="[!] No IPMI endpoints in the datastore (port 623/udp). "
                   "Run `enum -U` (UDP) against the BMC targets first.",
        fmt=_fmt_simple(lambda t, a: 'cipher-zero' if t.get('cipher_zero')
                                     else ('anon' if t.get('anonymous') else '?')),
        udp=True)


def cmd_ntp(args: argparse.Namespace) -> int:
    """NTP 123/udp: monlist amplification + client disclosure (CVE-2013-5211),
    mode-6 readvar version/OS disclosure, peer list, and Kerberos-breaking skew."""
    return _run_service_scan(
        args, module="ntp", source="ntp", label="NTP",
        noun="NTP server(s)",
        no_targets="[!] No NTP servers in the datastore (port 123/udp). "
                   "Run `enum -U` (UDP) first — 123 is UDP-only.",
        fmt=_fmt_simple(lambda t, a: 'monlist' if t.get('monlist')
                                     else ('mode6' if t.get('mode6') else '?')),
        udp=True)


def cmd_msrpc(args: argparse.Namespace) -> int:
    """MSRPC 135/tcp: endpoint mapper dump + IOXIDResolver ServerAlive2 —
    interface leak, coercion targets (PetitPotam / PrinterBug / DFSCoerce)."""
    return _run_service_scan(
        args, module="msrpc", source="msrpc", label="MSRPC",
        noun="MSRPC endpoint(s)",
        no_targets="[!] No MSRPC endpoints in the datastore (port 135/tcp). "
                   "Run `enum` against the Windows hosts first.",
        fmt=_fmt_simple(lambda t, a: (f"{t.get('coercion',0)} coercion" if t.get('coercion')
                                       else (f"{t.get('interfaces',0)} interfaces"
                                             if t.get('interfaces') else '?'))))


def cmd_winrm(args: argparse.Namespace) -> int:
    """WinRM 5985/5986: unauth WSMan Identify (version + product), Basic/
    Kerberos/Negotiate auth advertisement, TLS posture on 5986."""
    return _run_service_scan(
        args, module="winrm", source="winrm", label="WinRM",
        noun="WinRM endpoint(s)",
        no_targets="[!] No WinRM endpoints in the datastore (5985/5986). "
                   "Run `enum` against the Windows hosts first.",
        fmt=_fmt_simple(lambda t, a: (','.join(t.get('auth') or []) or '?')))


def cmd_netbios(args: argparse.Namespace) -> int:
    """NBNS 137/udp: node-status query — hostname / workgroup / domain / MAC
    disclosure without authentication."""
    return _run_service_scan(
        args, module="netbios", source="netbios", label="NetBIOS",
        noun="NetBIOS name service(s)",
        no_targets="[!] No NetBIOS endpoints in the datastore (port 137/udp). "
                   "Run `enum -U` (UDP sweep) first.",
        fmt=_fmt_simple(lambda t, a: t.get('hostname') or ('dc' if t.get('is_dc') else '?')),
        udp=True)


def cmd_tftp(args: argparse.Namespace) -> int:
    """TFTP 69/udp: unauth file read of common vendor config filenames
    (Cisco running-config, IOS images, phone provisioning bundles)."""
    return _run_service_scan(
        args, module="tftp", source="tftp", label="TFTP",
        noun="TFTP server(s)",
        no_targets="[!] No TFTP endpoints in the datastore (port 69/udp). "
                   "Run `enum -U` (UDP sweep) first.",
        fmt=_fmt_simple(lambda t, a: f"{t.get('readable',0)} readable"),
        udp=True)


def cmd_ipp(args: argparse.Namespace) -> int:
    """IPP / CUPS 631/tcp: unauth printer enumeration + CVE-2024-47176
    (foomatic RCE chain) reachability check."""
    return _run_service_scan(
        args, module="ipp", source="ipp", label="IPP",
        noun="IPP/CUPS endpoint(s)",
        no_targets="[!] No IPP endpoints in the datastore (port 631). Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: ('cups' if t.get('is_cups') else '?') +
                                     f" {t.get('printers',0)} printers"))


def cmd_x11(args: argparse.Namespace) -> int:
    """X11 6000-6009/tcp: unauthenticated display handshake — screenshot /
    keylog / input-injection surface when open."""
    return _run_service_scan(
        args, module="x11", source="x11", label="X11",
        noun="X11 display(s)",
        no_targets="[!] No X11 displays in the datastore (6000-6009). Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: 'OPEN' if t.get('accepted') else 'auth-required'))


def cmd_sip(args: argparse.Namespace) -> int:
    """SIP 5060: OPTIONS fingerprint — Server/User-Agent + realm disclosure,
    entry point for extension enumeration + toll-fraud audit."""
    return _run_service_scan(
        args, module="sip", source="sip", label="SIP",
        noun="SIP endpoint(s)",
        no_targets="[!] No SIP endpoints in the datastore (port 5060). "
                   "Run `enum` (and/or `enum -U`) first — SIP runs on both UDP and TCP.",
        fmt=_fmt_simple(lambda t, a: t.get('server') or '?'))


def cmd_rservices(args: argparse.Namespace) -> int:
    """Legacy r-services (512/rexec, 513/rlogin, 514/rsh): cleartext IP-trust
    authentication — flagged categorically when present in 2025."""
    return _run_service_scan(
        args, module="rservices", source="rservices", label="r-services",
        noun="legacy r-service(s)",
        no_targets="[!] No r-services in the datastore (ports 512/513/514). "
                   "Run `enum` first.",
        fmt=_fmt_simple(lambda t, a: t.get('service') or '?'))
