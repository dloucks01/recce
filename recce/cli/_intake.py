"""Command handlers for the `intake` command group.

Extracted from cli/__init__.py. Helpers (the `_*` functions and _Refresher)
live in cli/helpers.py and are wildcard-re-imported so every helper name
resolves without needing an explicit import per callsite. Public re-exports
come from cli/__init__.py so `recce.cli.cmd_ingest` still works and the
parser's `_h(...)` lookup finds every handler."""
from __future__ import annotations

import argparse
import json
import os

from .. import ad
from ..vuln import exploits
from ..core import parser as np
from ..core.models import Host

from .helpers import *  # noqa: F401,F403 — wildcard so private _* helpers resolve


__all__ = ['cmd_ingest', 'cmd_import', 'cmd_fieldkit_export', 'cmd_fieldkit_import']


def cmd_ingest(args: argparse.Namespace) -> int:
    from ..intake import ingest
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


def cmd_import(args: argparse.Namespace) -> int:
    """Import an already-completed nmap scan (XML -oX or grepable -oG) and build /
    update the workbook - no scanning, no network. Folds hosts into the datastore,
    runs the offline enrichment (version->CVE, AD roles, SMB signing), sets the
    checkmarks, and preserves any existing tracking."""
    from ..vuln import vulndb
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




def cmd_fieldkit_export(args: argparse.Namespace) -> int:
    """Export the engagement as a seed for the fieldkit exploitation kit."""
    from ..intake import fieldkit
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
    from ..intake import fieldkit
    from ..core.models import Host
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']} - run `enum` first, or `import` a scan.")
        return 1
    if not os.path.exists(args.findings):
        print(f"[x] No such file: {args.findings}")
        return 1
    try:
        from ..intake import importers
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
