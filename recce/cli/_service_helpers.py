"""Service-scan helpers: proof shots, format functions, run_service_scan.

Extracted from helpers.py. Used primarily by _services.py and _db.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re

from .. import ad
from ..core import parser as np
from ..core import scanner
from ..core.models import Host
from ..core.store import Store

from ._common import (
    _SEV_ORDER,
    _fold_host,
    _generate_reports,
    _import_excel_tracking,
    _open_paths,
    _open_store,
    _persist_host,
    _ports_for_host,
    _record_issues,
)
from ._phases import _db_login_creds, _merge_vuln_results, _mkissue, _selected_hosts

__all__ = ['_MODULE_PATH', '_match_one_host', '_web_screenshots', '_cves_from_findings', '_prove_run_safe_checks', '_parse_cred_spec', '_self_scan', '_run_ldap_enum', '_resolve_ingest_host', '_tag_host_os', '_ingest_service_output', '_fold_loot', '_deploy_worker', '_collect_scan_files', '_proof_shot', '_ad_shot', '_ad_live_kerberos', '_mssql_shot', '_smb_shot', '_ftp_shot', '_docker_shot', '_ldap_shot', '_run_service_scan', '_fmt_snmp', '_snmp_persist_accounts', '_fmt_mongodb', '_fmt_redis', '_fmt_elasticsearch', '_fmt_rsync', '_fmt_nfs', '_fmt_mysql', '_fmt_postgres', '_fmt_smtp', '_fmt_dns', '_fmt_memcached', '_fmt_couchdb', '_fmt_influxdb', '_fmt_cassandra', '_fmt_oracle', '_fmt_db2', '_probe_progress', '_probe_kwargs', '_report_partial', '_fold_service_findings', '_mark_capability_scanned', '_service_module_coverage', '_demo_credentials', '_demo_bloodhound']

_MODULE_PATH = {
    "snmp": "recce.services.snmp", "smtp": "recce.services.smtp",
    "dns": "recce.services.dns", "rsync": "recce.services.rsync",
    "nfs": "recce.services.nfs", "ftp": "recce.services.ftp",
    "docker": "recce.services.docker", "kubernetes": "recce.services.kubernetes",
    "ldap": "recce.services.ldap", "smb": "recce.services.smb",
    "mongodb": "recce.services.db.mongodb", "redis": "recce.services.db.redis",
    "elasticsearch": "recce.services.db.elasticsearch", "mssql": "recce.services.db.mssql",
    "mysql": "recce.services.db.mysql", "postgres": "recce.services.db.postgres",
    "cassandra": "recce.services.db.cassandra", "couchdb": "recce.services.db.couchdb",
    "influxdb": "recce.services.db.influxdb", "memcached": "recce.services.db.memcached",
    "oracle": "recce.services.db.oracle", "db2": "recce.services.db.db2",
    "zookeeper": "recce.services.zookeeper", "kafka": "recce.services.kafka",
    "etcd": "recce.services.etcd", "consul": "recce.services.consul",
    "nomad": "recce.services.nomad", "modbus": "recce.services.modbus",
    "ipmi": "recce.services.ipmi", "ntp": "recce.services.ntp",
    "msrpc": "recce.services.msrpc", "winrm": "recce.services.winrm",
    "netbios": "recce.services.netbios", "tftp": "recce.services.tftp",
    "ipp": "recce.services.ipp", "x11": "recce.services.x11",
    "sip": "recce.services.sip", "rservices": "recce.services.rservices", "prometheus": "recce.services.prometheus",
    "rdp": "recce.services.rdp", "vnc": "recce.services.vnc",
    "docker_registry": "recce.services.docker_registry",
    "gitlab": "recce.services.gitlab",
    "grafana": "recce.services.grafana",
    "jupyterhub": "recce.services.jupyterhub",
    "api": "recce.services.api", "web": "recce.services.web",
    # T5+ scanner-expansion additions (SSH/mail/OT/monitoring/storage/etc.):
    "ssh": "recce.services.ssh", "telnet": "recce.services.telnet",
    "imap": "recce.services.imap", "pop3": "recce.services.pop3",
    "webdav": "recce.services.webdav", "iscsi": "recce.services.iscsi",
    "bacnet": "recce.services.bacnet", "s7": "recce.services.s7",
    "opcua": "recce.services.opcua", "dnp3": "recce.services.dnp3",
    "iec104": "recce.services.iec104", "enip": "recce.services.enip",
    "mqtt": "recce.services.mqtt", "rtsp": "recce.services.rtsp",
    "nrpe": "recce.services.nrpe", "zabbix": "recce.services.zabbix",
    "vault": "recce.services.vault", "vsphere": "recce.services.vsphere",
    "jenkins-jnlp": "recce.services.jenkins_jnlp",
    "cups_lpd": "recce.services.cups_lpd", "nbd_ndmp": "recce.services.nbd_ndmp",
    "slp": "recce.services.slp", "bgp": "recce.services.bgp",
    "stun": "recce.services.stun_turn", "xmpp": "recce.services.xmpp",
    "guacamole": "recce.services.guacamole", "minecraft": "recce.services.minecraft",
    "nisyp": "recce.services.nisyp", "coap": "recce.services.coap",
    "ollama": "recce.services.ollama",
    "minio": "recce.services.minio",
    "cloud_metadata": "recce.services.cloud_metadata",
}

def _match_one_host(hosts, selector):
    """Best-effort: the host(s) an IP/IP:port selector points at (for screenshots)."""
    sel = (selector or "").split(":")[0].strip()
    return [h for h in hosts if h.ip == sel] if sel else []




def _web_screenshots(targets, output_dir) -> None:
    """Headless-browser screenshot per web endpoint -> engagement/screenshots/."""
    from ..report import screenshot
    from ..services import web
    if not screenshot.available():
        print("    [!] --screenshots: no headless browser found (chromium/firefox); "
              "skipping. `recce doctor` shows what's missing.")
        return
    shot_dir = os.path.join(output_dir, "screenshots")
    try:
        os.makedirs(shot_dir, exist_ok=True)
    except OSError:
        return
    n = 0
    for h in targets:
        for p in h.open_ports:
            if not web.is_web(p):
                continue
            png = screenshot.capture(web.url_for(h.ip, p))
            if png:
                fn = os.path.join(shot_dir, f"web_{h.ip}_{p.portid}.png")
                try:
                    with open(fn, "wb") as fh:
                        fh.write(png)
                    n += 1
                except OSError:
                    pass
    print(f"    {n} screenshot(s) -> {shot_dir}/")




def _cves_from_findings(hosts, confirmed_only: bool = False) -> list[str]:
    cves: set[str] = set()
    for h in hosts:
        for v in getattr(h, "vulns", []):
            if confirmed_only and (v.confidence or "").lower() != "confirmed":
                continue
            for c in (v.ids or []):
                if c.upper().startswith("CVE-"):
                    cves.add(c.upper())
    return sorted(cves)




def _prove_run_safe_checks(store, paths, hosts, args) -> None:
    """--run: re-run the NON-INTRUSIVE detection NSE for SMB findings so a verdict
    can move from LIKELY to CONFIRMED / FALSE POSITIVE on real evidence. These are
    detection scripts (smb-security-mode, smb-vuln-ms17-010), not exploits."""
    from ..vuln import proofs
    profile = scanner.PROFILES.get(getattr(args, "profile", "standard"),
                                   scanner.PROFILES["standard"])
    smb_scripts = ["smb-security-mode", "smb2-security-mode",
                   "smb-vuln-ms17-010", "smb-enum-shares"]
    smb_recipes = {"smb-signing-relay", "ms17-010", "smb-null-session"}
    for h in hosts:
        # One recipe_for() call per vuln (was two), guarding a recipe with no "id".
        rids = set()
        for v in h.vulns:
            r = proofs.recipe_for(v)
            if r and r.get("id"):
                rids.add(r["id"])
        if not (rids & smb_recipes) or not any(p.portid in (139, 445) for p in h.open_ports):
            continue
        print(f"[*] {h.ip}: re-running safe SMB detection NSE to prove/disprove ...")
        out = os.path.join(paths["raw"], f"{h.ip}_prove.xml")
        try:
            _, iss = scanner.nse_scan(h.ip, [445], out, profile, smb_scripts)
            if iss:
                _record_issues(store, paths, h.ip, [_mkissue(iss, "prove")])
            _merge_vuln_results(h, np.parse_nmap_xml(out))
            ad.parse_signing_and_ntlm(h)          # refresh smb_signing from the NSE
            _persist_host(store, paths, h.ip, "prove", h)
        except Exception as e:  # noqa: BLE001 - one host's re-scan never aborts prove
            print(f"    [!] {h.ip}: prove re-scan failed: {e}")




def _parse_cred_spec(spec: str):
    """Parse 'user:secret', 'DOMAIN\\user:secret', or 'domain/user:secret'."""
    from ..core.models import Credential
    idpart, secret = (spec.split(":", 1) + [""])[:2] if ":" in spec else (spec, "")
    domain = ""
    if "\\" in idpart:
        domain, user = idpart.split("\\", 1)
    elif "/" in idpart:
        domain, user = idpart.split("/", 1)
    else:
        user = idpart
    kind = "nthash" if re.fullmatch(r"[0-9a-fA-F]{32}", secret or "") else \
        ("password" if secret else "blank")
    return Credential(username=user, secret=secret, kind=kind, domain=domain,
                      source="manual")








def _self_scan() -> bool:
    import tempfile
    try:
        from ..core import scanner
        profile = scanner.PROFILES["quick"]
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "p.xml")
            scanner.full_port_scan("127.0.0.1", fp, profile)
            ports = _ports_for_host(fp, "127.0.0.1")
            deep = os.path.join(d, "e.xml")
            scanner.enum_scan("127.0.0.1", ports or [80], deep, profile)  # (xml, issue)
            host = _fold_host("127.0.0.1", np.parse_nmap_xml(deep), {"127.0.0.1": "local"})
            host.enumerated = True
            from ..report.excel import build_workbook, read_workbook_tracking
            out = os.path.join(d, "wb.xlsx")
            build_workbook([host], out)
            read_workbook_tracking(out)  # prove read-back parses too
            print(f"  found {len(host.open_ports)} open port(s) on 127.0.0.1; "
                  f"report + read-back OK.")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"  error: {e}")
        return False




def _run_ldap_enum(store: Store, args: argparse.Namespace) -> None:
    if not ad.ldap_available():
        print("[!] --ldap-enum requested but no LDAP client found; skipping. "
              "Install ldap-utils (ldapsearch) for airgapped use, or ldap3.")
        return
    all_hosts = store.all_hosts()
    dc_ips = [args.dc_ip] if args.dc_ip else [h.ip for h in ad.domain_controllers(all_hosts)]
    if not dc_ips:
        print("[!] No Domain Controllers found for LDAP enumeration "
              "(use --dc-ip to target one directly).")
        return
    for dc_ip in dc_ips:
        anon = args.ldap_anon and not args.username
        label = "anonymous" if anon else f"as {args.domain}\\{args.username}"
        print(f"[*] LDAP enumeration of {dc_ip} ({label}) ...")
        try:
            domain, accounts = ad.ldap_enumerate(
                dc_ip, domain=args.domain or "", username=args.username or "",
                password=args.password or "", use_ssl=args.ldap_ssl, anonymous=anon)
        except Exception as e:  # noqa: BLE001
            print(f"[!] LDAP enumeration failed for {dc_ip}: {e}")
            continue
        host = store.get_host(dc_ip)
        if host is not None:
            existing = {(a.source, a.kind, a.name) for a in host.accounts}
            host.accounts.extend(a for a in accounts
                                 if (a.source, a.kind, a.name) not in existing)
            store.upsert_host(host)
        store.upsert_domain(domain)
        n_users = sum(1 for a in accounts if a.kind == "user")
        n_spn = sum(1 for a in accounts if a.attrs.get("spn"))
        n_asrep = sum(1 for a in accounts if a.attrs.get("asrep_roastable") == "yes")
        print(f"    +{len(accounts)} objects ({n_users} users, {n_spn} with SPN, "
              f"{n_asrep} AS-REP roastable) for domain {domain.name or '?'}.")








# --- report / status / review ---------------------------------------------------

def _resolve_ingest_host(store, parsed, args, topo=None):
    """Pick (or create) the Host that on-target loot belongs to.

    Priority: an explicit --host, else an IP parsed from the loot that already
    exists, else a synthetic host keyed by the loot's hostname/filename so the
    findings still land somewhere on the Priv-Esc sheet."""
    hosts = {h.ip: h for h in store.all_hosts()}
    hn = parsed.get("hostname", "")
    if getattr(args, "host", None):
        ip = args.host
        host = hosts.get(ip) or Host(ip=ip)
        # Record the loot's hostname so a later no --host ingest of the same box
        # matches this entry instead of synthesizing a second local:<host> one.
        if hn and hn not in host.hostnames:
            host.hostnames.append(hn)
        _tag_host_os(host, parsed)
        return host, (ip in hosts)
    # No --host: resolve from the host's OWN interface IPs in the ingested NETWORK
    # block (so `recce ingest enum.txt` lands on the real enumerated host with no
    # --host needed), then by hostname, else synthesize.
    iface_ips = [i.get("ip") for i in (topo or {}).get("interfaces", []) if i.get("ip")]
    for ip in iface_ips:
        if ip in hosts:
            if hn and hn not in hosts[ip].hostnames:
                hosts[ip].hostnames.append(hn)
            _tag_host_os(hosts[ip], parsed)
            return hosts[ip], True
    if hn:
        for h in hosts.values():
            if hn.lower() in [x.lower() for x in h.hostnames] or \
               hn.lower() == (h.hostname or "").lower():
                _tag_host_os(h, parsed)
                return h, True
    if iface_ips:                              # a real IP from the enum, just not in scope yet
        host = hosts.get(iface_ips[0]) or Host(
            ip=iface_ips[0],
            subnet=".".join(iface_ips[0].split(".")[:3]) + ".0/24", enumerated=True)
        if hn and hn not in host.hostnames:
            host.hostnames.append(hn)
        _tag_host_os(host, parsed)
        return host, (iface_ips[0] in hosts)
    key = hn or os.path.splitext(os.path.basename(args.loot))[0]
    host = hosts.get(f"local:{key}") or Host(ip=f"local:{key}")
    if hn and hn not in host.hostnames:
        host.hostnames.append(hn)
    _tag_host_os(host, parsed)
    return host, (host.ip in hosts)




def _tag_host_os(host, parsed) -> None:
    if not host.os_family and parsed.get("os"):
        host.os_family = parsed["os"].capitalize()




def _ingest_service_output(svc: dict, paths: dict, args) -> int:
    """Fold recce-service.sh per-service findings into the datastore as confirmed
    service-enum Vulns on the matching host:port (creating a host entry if needed)."""
    from ..intake import ingest
    from ..core.models import Host, Port
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    vulns = ingest.service_findings_to_vulns(svc)
    by_ip: dict[str, list] = {}
    for v in vulns:
        by_ip.setdefault(v.ip, []).append(v)
    hosts_by_ip = {h.ip: h for h in store.all_hosts()}
    added_total = created = touched = 0
    for ip, vs in by_ip.items():
        h = hosts_by_ip.get(ip)
        if h is None:
            h = Host(ip=ip, subnet=".".join(ip.split(".")[:3]) + ".0/24",
                     enumerated=True)
            for pnum in sorted({v.port for v in vs if v.port}):
                h.ports.append(Port(portid=pnum, protocol="tcp", state="open",
                                    vuln_scanned=True))
            created += 1
        have = {(x.title, x.port) for x in h.vulns}
        added = [v for v in vs if (v.title, v.port) not in have]
        if not added:
            continue
        h.vulns.extend(added)
        aff = {v.port for v in added}
        for p in h.ports:
            if p.portid in aff:
                p.vuln_scanned = True
        store.upsert_host(h)
        added_total += len(added)
        touched += 1
    print(f"[+] Ingested {added_total} service finding(s) across {touched} host(s)"
          + (f" ({created} new host entry/entries)" if created else "") + ".")
    print("    Source: recce-service.sh output -> Vulnerabilities sheet "
          "(source 'service-enum'; advisory 'test X' lines kept as 'potential').")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0




def _fold_loot(host, text: str, source: str) -> tuple[int, int, int]:
    """Fold recce-enum.sh/.ps1 output text into a host: local findings (deduped by
    category/vector), AV/EDR defenses, and high-signal findings promoted to Vulns.
    Sets privesc_checked. Returns (added, total_rows, promoted). Shared by the
    `ingest` command and the `deploy` orchestrator so both fold identically."""
    from ..intake import ingest
    parsed = ingest.parse_loot(text)
    new_rows = ingest.to_local_findings(parsed, source)
    have = {(f.get("category"), f.get("vector")) for f in host.local_findings}
    added = []
    for r in new_rows:
        key = (r["category"], r["vector"])
        if key not in have:
            have.add(key)
            added.append(r)
    host.local_findings.extend(added)
    known = set(host.defenses)
    for d in ingest.extract_defenses(text):
        if d not in known:
            known.add(d)
            host.defenses.append(d)
    have_v = {v.key for v in host.vulns}
    promoted = [v for v in ingest.promote_to_vulns(host.ip, host.local_findings)
                if v.key not in have_v]
    host.vulns.extend(promoted)
    # Backfill listening-service ground truth (binary path, owning service,
    # loopback-only listeners) from the on-target scripts onto the host's ports.
    ingest.backfill_ports(host, ingest.parse_listeners(text))
    # Observed network topology (own interfaces/routes/ARP/peers) -> reachability map.
    topo = ingest.parse_topology(text)
    if topo:
        host.topology = topo
    host.privesc_checked = True
    return len(added), len(new_rows), len(promoted)




def _deploy_worker(host, ssh_creds, win_creds, timeout, loot_dir,
                   stager=None, authmap=None):
    """Run the on-target enum script on one host remotely, save the raw loot, fold
    it into the host. Returns (host, transport, added, promoted, error)."""
    from ..creds import deploy
    transport, out, err = deploy.deploy_one(host, ssh_creds, win_creds, timeout,
                                            stager=stager, authmap=authmap)
    if not out:
        return host, transport, 0, 0, (err or "no output returned")
    try:
        with open(os.path.join(loot_dir, f"{host.ip}.txt"), "w", errors="replace") as fh:
            fh.write(out)
    except OSError:
        pass
    added, _total, promoted = _fold_loot(host, out, f"deploy:{transport or 'remote'}")
    return host, transport, added, promoted, None




def _collect_scan_files(paths: list[str]) -> list[str]:
    """Expand files / directories / globs into a list of nmap scan files. For a
    same-basename -oA set (base.xml + base.gnmap + base.nmap) keep only the richest
    format (xml > grepable > normal) so one scan isn't imported three times."""
    import glob
    found: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for pat in ("*.xml", "*.gnmap", "*.grep", "*.nmap"):
                found += sorted(glob.glob(os.path.join(p, pat)))
        elif os.path.exists(p):
            found.append(p)
        else:
            found += sorted(glob.glob(p))          # maybe a glob pattern
    rank = {".xml": 0, ".gnmap": 1, ".grep": 1, ".nmap": 2}
    best: dict[str, tuple[int, str]] = {}
    order: list[str] = []
    for f in found:
        base, ext = os.path.splitext(f)
        r = rank.get(ext.lower(), 3)
        if base not in best:
            best[base] = (r, f)
            order.append(base)
        elif r < best[base][0]:
            best[base] = (r, f)
    return [best[b][1] for b in order]




def _proof_shot(args, module: str, filename: str, command: str, output: str,
                *, ip: str | None = None, **proof_kwargs):
    """Shared 'capture a terminal-output proof screenshot' helper behind the live
    service actions (mssql/smb/ftp/docker/ldap/AD). Guarded by --screenshots, needs
    the screenshot tool available, writes engagement/screenshots/<filename>.png, and
    returns the path (or None). `ip`, when given, prefixes the console line;
    proof_kwargs (banner= / prompt=) pass through to the module's proof_html(). Six
    byte-identical copies used to drift on exactly these small differences."""
    if not getattr(args, "screenshots", False):
        return None
    from importlib import import_module
    from ..report import screenshot
    if not screenshot.available():
        return None
    mod = import_module(_MODULE_PATH.get(module, f"recce.{module}"))
    png = screenshot.capture_html(mod.proof_html(command, output, **proof_kwargs))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"{filename}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {f'{ip}: ' if ip else ''}proof screenshot -> {path}")
    return path




def _ad_shot(args, name, command, output):
    """Terminal-output proof screenshot of a live Kerberos capture."""
    return _proof_shot(args, "mssql", f"ad_{name}", command, output, prompt="# ")




def _ad_live_kerberos(args, bh, creds, sh_paths, analysis):
    """Run the opted-in live Kerberos captures, fold the proven findings into the
    analysis, write the captured hashes to engagement/loot/, and screenshot each."""
    do_roast = getattr(args, "roast", False)
    do_asrep = getattr(args, "asrep", False)
    do_dcsync = getattr(args, "dcsync", False)
    if not (do_roast or do_asrep or do_dcsync):
        return
    if not (creds and creds.get("secret")):
        print("[!] --roast/--asrep/--dcsync need credentials (-u/-p or --creds) - skipped.")
        return
    if not creds.get("dc_ip"):
        print("[!] --roast/--asrep/--dcsync need --dc-ip (airgapped: no DNS) - skipped.")
        return
    graph = None
    if sh_paths:
        try:
            graph = bh.load_graph(sh_paths[0])
        except Exception:  # noqa: BLE001 - a bad graph never blocks the live run
            graph = None
    print("[*] Live Kerberos capture (read-only ticket requests / replication)...")
    live = bh.live_kerberos(creds, graph, do_roast=do_roast,
                            do_asrep=do_asrep, do_dcsync=do_dcsync)
    loot_dir = os.path.join(args.output_dir, "loot")
    for kind, fname, mode in (("kerberoast", "kerberoast.hash", 13100),
                              ("asrep", "asrep.hash", 18200),
                              ("dcsync", "secretsdump.txt", None)):
        run = live["runs"].get(kind)
        if not run:
            continue
        if run.get("error"):
            print(f"      [!] {kind}: {run['error']}")
            continue
        n = len(run.get("hashes", []))
        if kind == "dcsync":
            print(f"      [+] DCSync replicated {n} account hash(es)")
            if run.get("output"):
                os.makedirs(loot_dir, exist_ok=True)
                # Explicit UTF-8: secretsdump output can carry non-ASCII account names.
                with open(os.path.join(loot_dir, fname), "w", encoding="utf-8") as fh:
                    fh.write(run["output"])
                print(f"          loot -> {os.path.join(loot_dir, fname)}")
        else:
            print(f"      [+] {kind}: captured {n} hash(es) (hashcat -m {mode})")
            if run.get("hashes"):
                os.makedirs(loot_dir, exist_ok=True)
                # Explicit UTF-8: a $krb5tgs$/$krb5asrep$ hash embeds the account name.
                with open(os.path.join(loot_dir, fname), "w", encoding="utf-8") as fh:
                    fh.write("\n".join(h["hash"] for h in run["hashes"]) + "\n")
                print(f"          loot -> {os.path.join(loot_dir, fname)}")
        if run.get("output"):
            _ad_shot(args, kind, run.get("command", kind), run["output"])
    if live["findings"]:
        analysis["findings"].extend(live["findings"])
        analysis["stats"]["findings"] = len(analysis["findings"])
        print(f"    -> {len(live['findings'])} proven capture(s) folded into the "
              "findings + main totals.")




def _mssql_shot(args, ip, name, banner, command, output):
    """Faithful terminal screenshot of an executed MSSQL action."""
    return _proof_shot(args, "mssql", f"mssql_{ip.replace(':', '_')}_{name}",
                       command, output, ip=ip, banner=banner)




def _smb_shot(args, ip, name, command, output):
    """Terminal-output proof screenshot of a live SMB action."""
    return _proof_shot(args, "smb", f"smb_{ip.replace(':', '_')}_{name}",
                       command, output, ip=ip)




def _ftp_shot(args, ip, name, command, output):
    """Terminal-output proof screenshot of a live FTP action."""
    return _proof_shot(args, "ftp", f"ftp_{ip.replace(':', '_')}_{name}",
                       command, output, ip=ip)




def _docker_shot(args, ip, command, output):
    """Terminal-output proof screenshot of an exposed Docker API."""
    return _proof_shot(args, "docker", f"docker_{ip.replace(':', '_')}",
                       command, output, ip=ip)




def _ldap_shot(args, ip, command, output):
    """Terminal-output proof screenshot of an anonymous LDAP RootDSE read."""
    return _proof_shot(args, "ldap", f"ldap_{ip.replace(':', '_')}",
                       command, output, ip=ip)




def _run_service_scan(args, *, module: str, source: str, label: str, noun: str,
                      no_targets: str, fmt, extra=None, udp: bool = False) -> int:
    """Shared driver for the single-service deep-enum commands (snmp/mongodb/redis/
    elasticsearch/rsync/nfs). They differ only in the module they call, the hint shown
    when no endpoints are present, and how each target line is formatted - everything
    else (open the store, select hosts, analyze, print targets, fold findings, mark
    scanned, regenerate the report) was byte-for-byte identical across six copies.
    One implementation kills the drift that let the same step quietly diverge between
    them. `fmt(t, active)` returns the display text for one target; optional
    `extra(store, hosts, tgts, by_ip)` runs a per-service post-fold step."""
    from importlib import import_module
    from ..core import proxy
    if udp and proxy.is_active():
        # A UDP-only service can't be reached through a TCP proxy, and a datagram would
        # leak from the operator's real IP. Say so loudly instead of returning a clean,
        # misleading "0 findings" (north star: never a silent false negative).
        print(f"[!] {label} is UDP-only and can't traverse the proxy ({proxy.describe()}) "
              f"- skipped. Run it from the pivot host directly, or without --proxy.")
        return 0
    mod = import_module(_MODULE_PATH.get(module, f"recce.{module}"))
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    active = not args.no_probe
    # DB engines that support credentialed follow-through spray -u/-p plus the looted
    # password credentials from the datastore against auth-required instances.
    db_creds = _db_login_creds(args, store) if source in ("postgres", "mongodb", "mysql") else None
    extra_kw = {"prove": True} if source == "postgres" and getattr(args, "prove_rce", False) else {}
    analysis = mod.analyze(hosts, active=active, creds=db_creds,
                           **extra_kw, **_probe_kwargs(args, source))
    tgts = analysis["targets"]
    if not tgts:
        print(no_targets)
        store.close()
        return 0
    print(f"[+] {len(tgts)} {noun}:")
    for t in tgts:
        print(f"      {fmt(t, active)}")
    # Pull out any LOOT credentials the module captured BEFORE _fold serializes the
    # analysis blob (Credential objects aren't JSON) - persist them to the credential
    # store so they feed the credentialed spray / attack path.
    service_creds = analysis.pop("credentials", [])
    by_ip = _fold_service_findings(store, hosts, analysis, source,
                                   mod.findings_to_vulns, label)
    looted = 0
    for c in service_creds:
        if store.add_credential(c):
            looted += 1
    if looted:
        print(f"    [+] captured {looted} credential(s)/hash(es) -> credential store "
              f"(recce creds -o {args.output_dir} to view; feeds credsweep)")
    if extra:
        extra(store, hosts, tgts, by_ip)
    if active:
        _mark_capability_scanned(store, tgts)
    # Hashcat-format loot files. Each DB module already puts the "hashcat -m X"
    # command in the finding text, so writing the file it wants is the only
    # missing half — before this the tester had to grep the report to
    # reconstruct the hash list. Deduped + appended, so a repeat scan grows
    # loot/<source>.hash rather than overwriting.
    try:
        from ..creds import hashloot
        loot_dir = os.path.join(args.output_dir, "loot")
        by_cat: dict[str, list[str]] = {}
        for _tgt_key, pr in (analysis.get("probes") or {}).items():
            for category, line in hashloot.collect_from_probe(pr, source):
                by_cat.setdefault(category, []).append(line)
        for category, lines in by_cat.items():
            n = hashloot.write_hashcat_file(loot_dir, category, lines)
            if n:
                fname, mode, _blurb = hashloot.CATEGORIES[category]
                print(f"    -> {n} new hash(es) captured -> loot/{fname} "
                      f"(hashcat -m {mode})")
    except Exception:  # noqa: BLE001 — hashloot writing must never break the scan
        pass
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print(f"    -> {label} sheet written; findings folded into the main totals.")
    return 0




def _fmt_snmp(t, active) -> str:
    c = t.get("community")
    state = (f"community '{c}'" + ("  [RW-likely]" if t.get("rw_likely") else "")
             if c else "no readable community")
    name = f"  {t.get('sys_name')}" if t.get("sys_name") else ""
    users = f"  {t.get('users')} users" if t.get("users") else ""
    return f"{t['ip']}:{t['port']}  {state}{name}{users}"




def _snmp_persist_accounts(store, hosts, tgts, by_ip) -> None:
    # analyze() attached SNMP Account rows in place; persist hosts that gained them
    # but produced no SNMP vuln (rare) so the accounts still land.
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        if t.get("users") and t["ip"] not in by_ip and t["ip"] in host_by_ip:
            store.upsert_host(host_by_ip[t["ip"]], merge=False)




def _fmt_mongodb(t, active) -> str:
    if t.get("unauth"):
        state = f"EXPOSED (unauth, {t.get('databases', 0)} db)"
    else:
        state = "auth required" if t.get("version") else "probed"
    ver = f"  {t.get('version', '')}" if t.get("version") else ""
    return f"{t['ip']}:{t['port']}  {state}{ver}"




def _fmt_redis(t, active) -> str:
    if t.get("unauth"):
        state = f"EXPOSED (unauth, {t.get('keys', 0)} keys)"
    elif t.get("auth_required"):
        state = "auth required"
    else:
        state = "probed" if t.get("version") else "reachable"
    ver = f"  {t.get('version', '')}" if t.get("version") else ""
    return f"{t['ip']}:{t['port']}  {state}{ver}"




def _fmt_elasticsearch(t, active) -> str:
    if t.get("unauth"):
        state = f"EXPOSED (unauth, {t.get('indices', 0)} indices)"
    elif t.get("secured"):
        state = "security enforced"
    else:
        state = "probed" if t.get("version") else "reachable"
    ver = f"  {t.get('version', '')}" if t.get("version") else ""
    return f"{t['ip']}:{t['port']}  {state}{ver}"




def _fmt_rsync(t, active) -> str:
    mods = t.get("modules", 0)
    state = (f"{t.get('open', 0)}/{mods} module(s) open" if mods
             else "probed" if active else "reachable")
    return f"{t['ip']}:{t['port']}  {state}"




def _fmt_nfs(t, active) -> str:
    exp = t.get("exports", 0)
    if t.get("world"):
        state = f"{t['world']}/{exp} export(s) WORLD-mountable"
    elif exp:
        state = f"{exp} export(s) listed"
    else:
        state = "probed" if active else "reachable"
    return f"{t['ip']}  {state}"




def _fmt_mysql(t, active) -> str:
    if t.get("unauth"):
        state = "EMPTY-PASSWORD LOGIN (unauth)"
    elif t.get("auth_required"):
        state = "auth required"
    else:
        state = "probed" if t.get("version") else "reachable"
    return f"{t['ip']}:{t['port']}  {t.get('version') or 'mysql'}  {state}"




def _fmt_postgres(t, active) -> str:
    if t.get("unauth"):
        state = "TRUST AUTH (no password)"
    elif t.get("auth_required"):
        state = "auth required"
    else:
        state = "probed" if t.get("version") else "reachable"
    return f"{t['ip']}:{t['port']}  {t.get('version') or 'postgres'}  {state}"




def _fmt_smtp(t, active) -> str:
    flags = []
    if t.get("open_relay"):
        flags.append("OPEN RELAY")
    if t.get("vrfy"):
        flags.append("VRFY enum")
    state = ", ".join(flags) if flags else ("probed" if t.get("version") else "reachable")
    return f"{t['ip']}:{t['port']}  {state}"




def _fmt_dns(t, active) -> str:
    state = "ZONE TRANSFER ALLOWED" if t.get("axfr") else \
            ("probed" if t.get("version") else "reachable")
    return f"{t['ip']}:{t['port']}  {state}"




def _fmt_memcached(t, active) -> str:
    state = "UNAUTH (data readable)" if t.get("unauth") else (
        "probed" if t.get("version") else "reachable")
    items = f"  {t.get('items')} items" if t.get("items") else ""
    return f"{t['ip']}:{t['port']}  {t.get('version') or 'memcached'}  {state}{items}"




def _fmt_couchdb(t, active) -> str:
    if t.get("admin_party"):
        state = "ADMIN PARTY (no auth = RCE)"
    elif t.get("unauth"):
        state = "UNAUTH (dbs readable)"
    else:
        state = "probed" if t.get("version") else "reachable"
    return f"{t['ip']}:{t['port']}  couchdb {t.get('version') or '?'}  {state}"




def _fmt_influxdb(t, active) -> str:
    state = "UNAUTH query API" if t.get("unauth") else (
        "probed" if t.get("version") else "reachable")
    return f"{t['ip']}:{t['port']}  influxdb {t.get('version') or '?'}  {state}"




def _fmt_cassandra(t, active) -> str:
    state = "NO AUTH (AllowAll)" if t.get("unauth") else (
        "probed" if t.get("version") else "reachable")
    cl = f"  cluster '{t.get('cluster')}'" if t.get("cluster") else ""
    return f"{t['ip']}:{t['port']}  cassandra {t.get('version') or '?'}  {state}{cl}"




def _fmt_oracle(t, active) -> str:
    state = "TNS listener" if t.get("is_oracle") else (
        "probed" if t.get("version") else "reachable")
    ver = f"  {t.get('version')}" if t.get("version") else ""
    return f"{t['ip']}:{t['port']}  oracle{ver}  {state}"




def _fmt_db2(t, active) -> str:
    state = "DRDA endpoint" if t.get("is_db2") else (
        "probed" if t.get("version") else "reachable")
    ver = f"  {t.get('version')}" if t.get("version") else ""
    return f"{t['ip']}:{t['port']}  db2{ver}  {state}"






def _probe_progress(label: str):
    """A throttled per-target progress printer for the sequential deep-module loops,
    so a long run reads as 'working' rather than 'hung'. Quiet on tiny runs."""
    import time
    last = [0.0]

    def cb(i, n, t):
        if n < 8:
            return                                     # small runs: the summary suffices
        now = time.monotonic()
        if now - last[0] >= 2.0 or i == n:
            last[0] = now
            who = t.get("ip", "") if isinstance(t, dict) else str(t)
            print(f"    [{i}/{n}] {label} {who} ...", flush=True)
    return cb




def _probe_kwargs(args, label: str) -> dict:
    """budget + progress + optional wordlist kwargs for a deep module's
    analyze(). `wordlist` only gets forwarded when the CLI subparser
    actually declared --wordlist (postgres/mssql/smtp today); analyze()
    signatures without that param accept **_ignored so the extra key
    never breaks the call."""
    kw: dict = {"budget": getattr(args, "budget", None),
                "progress": _probe_progress(label)}
    wl = getattr(args, "wordlist", None)
    if wl:
        kw["wordlist"] = wl
    # IPMI --rakp-users: accept comma-separated inline OR @file. Parsed here
    # so the analyzer receives a clean list. `analyze()` signatures that
    # don't take rakp_users accept **_ignored, so a stray key does not break.
    rakp = getattr(args, "rakp_users", None)
    if rakp:
        kw["rakp_users"] = _parse_user_list(rakp)
    return kw


def _parse_user_list(spec: str) -> list[str]:
    """`user1,user2,user3` OR `@file.txt` (one per line). Blanks + comments
    dropped, whitespace stripped, order preserved so priority stays
    predictable."""
    spec = str(spec or "").strip()
    if not spec:
        return []
    if spec.startswith("@"):
        try:
            with open(spec[1:], encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return []
    else:
        lines = spec.split(",")
    out: list[str] = []
    for raw in lines:
        s = raw.strip()
        if s and not s.startswith("#") and s not in out:
            out.append(s)
    return out




def _report_partial(stats) -> None:
    """Tell the operator when a probe loop stopped early (budget / Ctrl-C) so partial
    results are never mistaken for a complete, clean assessment."""
    stopped = (stats or {}).get("stopped")
    if stopped == "budget":
        print("    [!] Time budget (--budget) reached - stopped early; partial results "
              "saved. Raise --budget or narrow the targets to finish the rest.")
    elif stopped == "interrupt":
        print("    [!] Interrupted - stopped early; results probed so far were saved.")




def _fold_service_findings(store, hosts, analysis, source, to_vulns, label):
    """Shared tail for the deep-service commands (smb/ftp/docker/kubernetes/mssql):
    sort findings by severity, fold them into their hosts (replacing this source's
    prior vulns, deduped by key), persist the analysis blob under `source`, and print
    a per-severity summary. Capability marking stays with each command (its gating
    differs). Returns {ip: [Vuln]} so a caller can post-process the touched hosts."""
    analysis["findings"].sort(key=lambda x: _SEV_ORDER.get(x["severity"], 5))
    analysis["stats"]["findings"] = len(analysis["findings"])
    by_ip = to_vulns(analysis["findings"])
    host_by_ip = {h.ip: h for h in hosts}
    # A deep module speaks the real protocol, so it reads the TRUE version. Adopt it
    # onto the port when nmap left the version empty or OPEN-ENDED ("9.6.0 or later")
    # - so the report shows the real build (a PostgreSQL 18 reads "18.1", not nmap's
    # vague fingerprint). Never clobbers a concrete nmap version.
    probes = analysis.get("probes") or {}
    for ip, vulns in by_ip.items():
        host = host_by_ip.get(ip) or store.get_host(ip)
        if host is None:
            continue
        for p in host.ports:
            mv = (probes.get(f"{ip}:{p.portid}") or {}).get("version")
            if mv and (not p.version or re.search(r"\b(?:or|and)\s+later\b", p.version, re.I)):
                p.version = mv
        have = {v.key for v in host.vulns if v.source != source}
        host.vulns = [v for v in host.vulns if v.source != source]   # refresh this source
        for v in vulns:
            if v.key not in have:
                have.add(v.key)
                host.vulns.append(v)
        store.upsert_host(host, merge=False)
    # default=str: per-host vulns are already committed above; a stray non-JSON object
    # left in `analysis` by a module must not raise here and abort report generation.
    store.set_meta(source, json.dumps(analysis, default=str))
    fs = analysis["findings"]
    if fs:
        by_sev: dict = {}
        for f in fs:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        print(f"[+] {len(fs)} {label} finding(s): "
              + ", ".join(f"{by_sev[s]} {s}" for s in
                          ("critical", "high", "medium", "low") if by_sev.get(s)))
    _report_partial(analysis.get("stats"))
    return by_ip




def _mark_capability_scanned(store, targets, db: bool = False) -> None:
    """After a deep-service capability runs (smb/ftp/docker/kubernetes/mssql), mark
    each port it actually assessed as vuln-scanned - and the host as db-scanned for a
    database service - so the Checklist auto-checkboxes and coverage reflect the work
    without the tester ticking anything by hand. `targets` is the module's list of
    {ip, port} it probed (including clean ones, so a 'nothing found' probe still counts)."""
    per_host: dict[str, set] = {}
    for t in targets:
        if t.get("ip") and t.get("port"):
            per_host.setdefault(t["ip"], set()).add(int(t["port"]))
    for ip, ports in per_host.items():
        h = store.get_host(ip)
        if h is None:
            continue
        changed = False
        for p in h.ports:
            if p.portid in ports and not p.vuln_scanned:
                p.vuln_scanned = True
                changed = True
        if db and not h.db_scanned:
            h.db_scanned = True
            changed = True
        if changed:
            store.upsert_host(h, merge=False)     # full host loaded -> safe rewrite




def _service_module_coverage(store, hosts) -> list[dict]:
    """Per deep-service-module (mssql/smb/ftp/docker/kubernetes): how many hosts with
    an applicable open port have actually had the module run. 'Run' = the host appears
    in the module's stored analysis targets, or it carries a finding from that source.
    Ordered highest-impact first so `status` surfaces the critical exposures."""
    from ..ad import kerberos as _krb
    from ..services import (smb, ftp, docker, kubernetes as k8s, ldap as _ldap,
                            snmp as _snmp, rsync as _rsync, nfs as _nfs)
    from ..services.db import mssql, mongodb as _mongo, redis as _redis, elasticsearch as _es
    mods = [
        ("MongoDB", "mongodb", _mongo.is_mongodb, "recce mongodb"),
        ("Redis", "redis", _redis.is_redis, "recce redis"),
        ("Elasticsearch", "elasticsearch", _es.is_elasticsearch, "recce elasticsearch"),
        ("rsync", "rsync", _rsync.is_rsync, "recce rsync"),
        ("NFS", "nfs", _nfs.is_nfs, "recce nfs"),
        ("Kerberos", "kerberos", _krb.is_kerberos, "recce kerberos -d DOMAIN"),
        ("Docker", "docker", docker.is_docker, "recce docker"),
        ("Kubernetes", "kubernetes", k8s.is_k8s, "recce k8s"),
        ("MSSQL", "mssql", mssql.is_mssql, "recce mssql -u USER -p PASS -d DOM"),
        ("LDAP", "ldap", _ldap.is_ldap, "recce ldap"),
        ("SNMP", "snmp", _snmp.is_snmp, "recce snmp"),
        ("SMB", "smb", smb.is_smb, "recce smb"),
        ("FTP", "ftp", ftp.is_ftp, "recce ftp"),
    ]
    out = []
    for name, key, pred, command in mods:
        applicable = [h for h in hosts if any(pred(p) for p in h.open_ports)]
        covered_ips: set = set()
        blob = store.get_meta(key)
        if blob:
            try:
                for t in (json.loads(blob).get("targets") or []):
                    if t.get("ip"):
                        covered_ips.add(t["ip"])
            except ValueError:
                pass
        for h in hosts:
            if any(v.source == key for v in h.vulns):
                covered_ips.add(h.ip)
        out.append({"name": name, "key": key, "command": command,
                    "applicable": len(applicable),
                    "covered": sum(1 for h in applicable if h.ip in covered_ips)})
    return out




def _demo_credentials(store: Store) -> None:
    """Seed a few captured credentials so the demo report's Credentials section
    renders. Secrets are masked in the shareable HTML; the workbook keeps the full
    values. Offline and deterministic."""
    from ..core.models import Credential
    for c in (
        Credential(username="jsmith", secret="Summer2024!", kind="password",
                   domain="corp.local", source="cracked",
                   origin_ip="10.0.10.10",
                   notes="Kerberoast TGS cracked offline (hashcat -m 13100)."),
        Credential(username="Administrator", secret="aad3b435b51404eeaad3b435b51404ee",
                   kind="nthash", domain="", source="secretsdump",
                   origin_ip="10.0.20.6",
                   notes="Local SAM hash dumped after the vsftpd backdoor shell."),
        Credential(username="admin", secret="admin", kind="password",
                   domain="", source="default", origin_ip="10.0.20.5",
                   notes="Default web-app login accepted on 10.0.20.5:80."),
    ):
        try:
            store.add_credential(c)
        except (ValueError, OSError):
            pass




def _demo_bloodhound(store: Store) -> None:
    """Seed a small synthetic SharpHound collection so the demo report showcases the
    AD findings, attack paths and the tier-0 **AD architecture diagram**. Offline and
    deterministic — analysed exactly like a real collection."""
    from ..ad import bloodhound as bh
    B = "S-1-5-21-4242-4242-4242"
    users = {"meta": {"type": "users"}, "data": [
        {"ObjectIdentifier": f"{B}-1104",
         "Properties": {"name": "JSMITH@CORP.LOCAL", "domain": "CORP.LOCAL",
                        "enabled": True, "hasspn": True,
                        "serviceprincipalnames": ["MSSQL/db01.corp.local"]}, "Aces": []},
        {"ObjectIdentifier": f"{B}-500",
         "Properties": {"name": "ADMINISTRATOR@CORP.LOCAL", "domain": "CORP.LOCAL",
                        "enabled": True}, "Aces": []},
    ]}
    computers = {"meta": {"type": "computers"}, "data": [
        {"ObjectIdentifier": f"{B}-1000",
         "Properties": {"name": "DC01.CORP.LOCAL", "domain": "CORP.LOCAL",
                        "enabled": True, "isdc": True}, "Aces": []},
    ]}
    groups = {"meta": {"type": "groups"}, "data": [
        {"ObjectIdentifier": f"{B}-512",
         "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": True},
         "Members": [{"ObjectIdentifier": f"{B}-500", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{B}-516",
         "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL", "highvalue": True},
         "Members": [{"ObjectIdentifier": f"{B}-1000", "ObjectType": "Computer"}], "Aces": []},
        {"ObjectIdentifier": f"{B}-513",
         "Properties": {"name": "DOMAIN USERS@CORP.LOCAL"},
         "Members": [{"ObjectIdentifier": f"{B}-1104", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{B}-1150",
         "Properties": {"name": "IT SUPPORT@CORP.LOCAL"},
         "Members": [{"ObjectIdentifier": f"{B}-1104", "ObjectType": "User"}],
         "Aces": [{"PrincipalSID": f"{B}-513", "RightName": "GenericWrite"}]},
    ]}
    domains = {"meta": {"type": "domains"}, "data": [
        {"ObjectIdentifier": B,
         "Properties": {"name": "CORP.LOCAL", "functionallevel": "2016",
                        "machineaccountquota": 10},
         "Trusts": [], "Aces": [
             {"PrincipalSID": f"{B}-1150", "RightName": "GetChanges"},
             {"PrincipalSID": f"{B}-1150", "RightName": "GetChangesAll"}]},
    ]}
    import tempfile as _tf
    try:
        with _tf.TemporaryDirectory() as d:
            for name, blob in (("users", users), ("computers", computers),
                               ("groups", groups), ("domains", domains)):
                with open(os.path.join(d, f"demo_{name}.json"), "w",
                          encoding="utf-8") as fh:
                    fh.write(json.dumps(blob))
            analysis = bh.analyze(d, owned={"JSMITH@CORP.LOCAL"})
        store.set_meta("ad_bloodhound", json.dumps(analysis))
    except (OSError, ValueError):
        pass


# a congestion-adaptive re-scan whose results are UNIONED in.
# When `sweep` chains several deep-module commands, each one would otherwise
# regenerate the whole workbook on the way out (N rebuilds for N modules). This flag
# lets sweep suppress those intermediate rebuilds and regenerate exactly once at the
# end - the datastore is the source of truth, so nothing is lost by deferring.
