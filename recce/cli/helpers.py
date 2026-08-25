"""Private helper functions for the recce CLI.

Extracted from cli/__init__.py to keep the command dispatcher small.
These are utility helpers — filesystem, engagement layout, report
generation, port folding, host persistence, permission fixups — used
by many command handlers and by webui/routes callers via re-export
from `recce.cli`.

Nothing in this module should reference a `cmd_*` function; the flow
of dependencies is one-way: cmd_ -> helpers, never the other direction.
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
from .. import tracking as tr
from ..models import Host
from ..report_excel import read_workbook_edits, update_workbook
from ..report_markdown import build_csv, build_markdown
from ..store import Store, StoreError
from ..targets import expand_excludes, explicit_targets, ip_matcher, load_targets


__all__ = ['BANNER', '_Refresher', '_SEV_ORDER', '_fmt_dur', '_progress', '_summarize_failures', '_ports_for_host', '_swept_ports_for_host', '_RETRY_HOST_TIMEOUT_CAP_MIN', '_union_swept', '_fold_swept_ports', '_disproved_ports_in_xml', '_open_store', '_sudo_owner', '_reown', '_relax_perms', '_open_paths', '_now', '_record_issues', '_persist_host', '_resolve_domains', '_reconcile_steps', '_import_excel_tracking', '_safe_refresh', '_DEFER_REPORTS', '_generate_reports', '_apply_profile_overrides', '_split_userdomain', '_creds_of', '_db_login_creds', '_web_login_creds', '_admin_creds_of', '_final_report', '_mkissue', '_enum_worker', '_reconfirm_missed', '_seed_targets', '_discover', '_phase_enum', '_merge_vuln_results', '_vuln_worker', '_selected_hosts', '_vuln_targets', '_phase_vulns', '_db_worker', '_phase_db', '_privesc_worker', '_phase_privesc', '_ssh_creds_of', '_credenum_worker', '_auth_cell', '_print_auth_table', '_phase_credenum', '_setup_scan', '_print_next', '_recovery_hint', '_sweep_defaults', '_UNAUTH_SWEEP', '_AUTH_SWEEP', '_run_sweep', '_match_one_host', '_web_screenshots', '_cves_from_findings', '_prove_run_safe_checks', '_parse_cred_spec', '_spray_cred_set', '_self_scan', '_run_ldap_enum', '_ip_key', '_fold_host', '_resolve_ingest_host', '_tag_host_os', '_ingest_service_output', '_fold_loot', '_deploy_worker', '_collect_scan_files', '_proof_shot', '_ad_shot', '_ad_live_kerberos', '_mssql_shot', '_smb_shot', '_ftp_shot', '_docker_shot', '_ldap_shot', '_run_service_scan', '_fmt_snmp', '_snmp_persist_accounts', '_fmt_mongodb', '_fmt_redis', '_fmt_elasticsearch', '_fmt_rsync', '_fmt_nfs', '_fmt_mysql', '_fmt_postgres', '_fmt_smtp', '_fmt_dns', '_fmt_memcached', '_fmt_couchdb', '_fmt_influxdb', '_fmt_cassandra', '_fmt_oracle', '_fmt_db2', '_probe_progress', '_probe_kwargs', '_report_partial', '_fold_service_findings', '_mark_capability_scanned', '_service_module_coverage', '_demo_credentials', '_demo_bloodhound']


BANNER = r"""
  ____  _____ ____ ____ _____
 |  _ \| ____/ ___/ ___| ____|
 | |_) |  _|| |  | |   |  _|
 |  _ <| |__| |__| |___| |___
 |_| \_\_____\____\____|_____|
   recon & coverage tracker for airgapped pentests
"""



_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}





def _fmt_dur(seconds: float) -> str:
    """Compact human duration: 45s / 3m20s / 1h04m."""
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"




def _progress(done: int, total: int, start: float) -> str:
    """A '· 42% · ETA 3m20s' suffix from elapsed time and completion ratio."""
    if total <= 0:
        return ""
    pct = int(done * 100 / total)
    elapsed = time.monotonic() - start
    if done and done < total:
        eta = elapsed / done * (total - done)
        return f" · {pct}% · ETA {_fmt_dur(eta)}"
    if done >= total:
        return f" · 100% · {_fmt_dur(elapsed)} total"
    return f" · {pct}%"




def _summarize_failures(phase: str, errs: list, total: int) -> None:
    """Loud end-of-phase failure summary so a bad host can't scroll past unseen.
    `errs` is a list of (ip, message); prints nothing when everything went fine."""
    if not errs:
        print(f"[+] {phase}: {total}/{total} host(s) OK, no errors.")
        return
    hosts = len({ip for ip, _ in errs})
    print("\n" + "!" * 64)
    print(f"[x] {phase}: {hosts} host(s) had errors ({len(errs)} issue(s)) - "
          f"{total - hosts}/{total} clean:")
    for ip, msg in errs:
        print(f"      {ip:<16} {msg}")
    print("!" * 64)




def _ports_for_host(xml_path: str, ip: str) -> list[int]:
    for h in np.parse_nmap_xml(xml_path):
        if h.ip == ip:
            return [p.portid for p in h.ports]
    return []




def _swept_ports_for_host(xml_path: str, ip: str) -> list:
    """The Port objects the sweep found for this host (open ports only - the parser
    already drops closed/filtered). Unlike _ports_for_host (portids for the `-p`
    arg), this keeps the whole Port so the sweep's authoritative open-port result can
    be folded into the host: the enum re-scan enriches those ports with service/script
    data, but must never be able to DROP one it happened to miss (a heavier -sV/-sC
    pass with no congestion-adaptive retry can under-report on a lossy net or under
    host-timeout, which silently turned a host with real services into '0 open ports')."""
    for h in np.parse_nmap_xml(xml_path):
        if h.ip == ip:
            return list(h.ports)
    return []


_RETRY_HOST_TIMEOUT_CAP_MIN = 30      # minutes




def _union_swept(a: list, b: list) -> list:
    """Union two lists of sweep Port objects by (protocol, portid), keeping the first
    seen. Used to merge a re-scan's authoritative open ports into the first pass's."""
    out = list(a)
    have = {(p.protocol, p.portid) for p in a}
    for p in b:
        if (p.protocol, p.portid) not in have:
            have.add((p.protocol, p.portid))
            out.append(p)
    return out




def _fold_swept_ports(host, swept) -> None:
    """Union the sweep's open ports into `host`, keyed by (protocol, portid). The enum
    re-scan already populated host.ports with rich data, so an existing port wins; a
    swept port the enum missed is added back as a bare open port (svcdetect/reprobe
    fill in its service later). Guarantees the enum phase can only ADD to or enrich the
    authoritative sweep result, never erase it."""
    if not swept:
        return
    have = {(p.protocol, p.portid) for p in host.ports}
    for sp in swept:
        if (sp.protocol, sp.portid) not in have:
            host.ports.append(sp)




def _disproved_ports_in_xml(xml_path: str, ip: str) -> set:
    """Ports the enum re-scan ACTIVELY disproved for this host: nmap got a reply that
    proves the port is shut (a RST => 'closed'). Returns {(protocol, portid)}.

    parse_nmap_xml drops closed ports, so this reads the raw enum XML to recover
    nmap's negative verdicts. Used to prune masscan's stateless false positives: a
    masscan SYN-ACK that nmap then saw closed is dropped, but a port nmap merely
    couldn't reach ('filtered'/no-response = packet loss, NOT counted here) is kept -
    masscan's positive evidence stands over nmap loss. Never raises."""
    import xml.etree.ElementTree as ET
    from ..parser import _declares_entities
    if _declares_entities(xml_path):
        return set()
    try:
        tree = ET.parse(xml_path)
    except (OSError, ET.ParseError):
        return set()
    disproved: set = set()
    for hnode in tree.getroot().findall("host"):
        if ip not in [a.get("addr") for a in hnode.findall("address")]:
            continue
        ports_node = hnode.find("ports")
        if ports_node is None:
            continue
        for pnode in ports_node.findall("port"):
            st = pnode.find("state")
            # Only "closed" (a definitive RST) disproves. "filtered"/no-response is
            # ambiguous (firewall or loss) and must NOT prune a masscan-observed port.
            if st is not None and st.get("state", "") == "closed":
                try:
                    disproved.add((pnode.get("protocol", "tcp"),
                                   int(pnode.get("portid", "0"))))
                except (TypeError, ValueError):
                    continue
    return disproved




def _open_store(db_path: str):
    """Open the datastore, turning a corrupt/unreadable DB (StoreError) into a
    clean actionable message + None instead of a traceback. Used by the commands
    that open an existing engagement directly (report/status/writeups/...)."""
    try:
        return Store(db_path)
    except StoreError as e:
        print(f"[x] {e}")
        return None




def _sudo_owner() -> tuple[int, int] | None:
    """The uid/gid that invoked sudo, when recce is running as root under sudo.

    Returns None when not applicable (not root, or not launched via sudo), in
    which case the output is already owned by the operator and needs no chown."""
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        return None
    uid = os.environ.get("SUDO_UID")
    if not (uid and uid.isdigit()):
        return None
    gid = os.environ.get("SUDO_GID")
    return int(uid), int(gid) if gid and gid.isdigit() else int(uid)




def _reown(target: str, owner: "tuple[int, int] | None", mode: int) -> None:
    """Best-effort: give `target` back to the operator with owner-only `mode`.

    chowns to the sudo-invoking user (when recce ran under sudo) and restricts
    permissions to the owner. Anything we can't chown/chmod is skipped, never
    fatal."""
    try:
        if owner is not None:
            os.chown(target, owner[0], owner[1])
        os.chmod(target, mode)
    except OSError:
        pass




def _relax_perms(path: str) -> None:
    """Best-effort: hand the engagement tree back to the operator after a sudo run,
    WITHOUT exposing it to other local users.

    recce is frequently run under sudo (raw socket scans, reading protected files),
    which leaves root-owned output a normal user can't reopen or edit afterward. We
    restore ownership to the sudo-invoking user and set owner-only permissions
    (dirs 0700, files 0600). The tree holds captured credentials and NTLM hashes,
    so it must never be group- or world-readable. Best-effort: anything we can't
    chown/chmod is skipped, never fatal."""
    if not path or not os.path.isdir(path):
        return
    owner = _sudo_owner()
    dirs_seen = [path]
    files_seen: list[str] = []
    for root, dirs, files in os.walk(path):
        dirs_seen.extend(os.path.join(root, n) for n in dirs)
        files_seen.extend(os.path.join(root, n) for n in files)
    for d in dirs_seen:
        _reown(d, owner, 0o700)
    for f in files_seen:
        _reown(f, owner, 0o600)




def _open_paths(out_dir: str) -> dict[str, str]:
    raw = os.path.join(out_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    # Keep the engagement folder accessible to the operator even when recce runs as
    # root under sudo, without exposing captured creds/hashes to other local users:
    # hand ownership back to the sudo-invoking user with owner-only perms (see
    # _relax_perms).
    owner = _sudo_owner()
    _reown(out_dir, owner, 0o700)
    _reown(raw, owner, 0o700)
    return {
        "raw": raw,
        "db": os.path.join(out_dir, "results.sqlite"),
        "xlsx": os.path.join(out_dir, "enumeration.xlsx"),
        "md": os.path.join(out_dir, "enumeration.md"),
        "csv": os.path.join(out_dir, "services.csv"),
        "html": os.path.join(out_dir, "report.html"),
        "docx": os.path.join(out_dir, "findings_report.docx"),
        "assets": os.path.join(out_dir, "assets.html"),
        "log": os.path.join(out_dir, "recce.log"),
    }




def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")




def _record_issues(store: Store, paths: dict, ip: str, issues: list) -> None:
    """Persist scan issues (errors / incomplete scans) to the datastore + the
    plain-text run log, and echo errors to the console so they're seen live."""
    if not issues:
        return
    # Clear this host's prior issues for each phase we're about to (re)write, so a
    # re-run replaces its own issues instead of stacking duplicates.
    for phase in {iss.get("phase", "") for iss in issues if isinstance(iss, dict)}:
        store.clear_issues(ip, phase)
    for iss in issues:
        phase = iss.get("phase", "") if isinstance(iss, dict) else ""
        level = iss.get("level", "warning") if isinstance(iss, dict) else "warning"
        message = iss.get("message", "") if isinstance(iss, dict) else str(iss)
        store.add_issue(ip, phase, level, message, ts=_now())
        try:
            with open(paths["log"], "a") as fh:
                fh.write(f"{_now()} [{level.upper()}] {ip} {message}\n")
        except OSError:
            pass
        marker = "[!]" if level == "error" else "[~]"
        print(f"    {marker} {ip}: {message}")




def _persist_host(store: Store, paths: dict, ip: str, phase: str, host,
                  clear_step: str | None = None) -> bool:
    """Persist one host's results, isolating a datastore failure to that host so
    a single problematic host can never abort the rest of the phase (the store
    already retries locks via busy_timeout; this catches a lock that outlasts it
    or any serialization edge). Returns True if the host was stored."""
    try:
        store.upsert_host(host)
        if clear_step:
            store.delete_tracking(tr.step_key(clear_step, ip))  # re-run clears override
        return True
    except Exception as e:  # noqa: BLE001
        _record_issues(store, paths, ip,
                       [{"phase": phase, "level": "error",
                         "message": f"could not persist results: {e}"}])
        return False




def _resolve_domains(store: Store, hosts: list) -> list:
    domains = {d.name.lower(): d for d in ad.derive_domains(hosts)}
    for d in store.all_domains():
        key = d.name.lower()
        domains[key] = ad.merge_domain(domains[key], d) if key in domains else d
    return list(domains.values())




def _reconcile_steps(store: Store, step_edits: dict) -> None:
    """Turn Checklist step-checkbox values into overrides: record one only when it
    differs from the tool's current auto-completion; otherwise clear it so the box
    follows the tool. (This is what makes 'auto-default, manual wins' work.)"""
    for key, (shown, _note) in step_edits.items():
        try:
            _, step, ip = key.split(":", 2)
        except ValueError:
            continue
        host = store.get_host(ip)
        # A step that no longer applies to the host carries no override.
        if host and not tr.step_applies(host, step):
            store.delete_tracking(key)
            continue
        auto = tr.step_auto(host, step) if host else False
        if shown == auto:
            store.delete_tracking(key)     # follow the tool
        else:
            store.set_reviewed(key, shown)  # persist the manual override




def _import_excel_tracking(store: Store, paths: dict[str, str],
                           reconcile_steps: bool = True) -> None:
    """Pull operator checkbox/notes edits from the workbook into the datastore.

    The datastore is authoritative; call this BEFORE any mutation or regenerate so
    manual edits are captured but never clobbered by a stale rebuild. Step
    checkboxes are reconciled against tool auto-state only in operator-driven
    commands (`reconcile_steps=True`); mid-scan refreshes skip them, because the
    workbook can lag the tool's fresh progress and would look like manual edits."""
    if not os.path.exists(paths["xlsx"]):
        return
    edits, statuses = read_workbook_edits(paths["xlsx"])
    if not edits:
        return
    step_edits = {k: v for k, v in edits.items() if k.startswith("step:")}
    plain: dict = {}
    status_items: dict = {}
    for k, (rev, note) in edits.items():
        if k.startswith("step:"):
            continue
        if k in statuses:
            # Per-port tri-state: persist the status + derived reviewed + notes.
            status_items[k] = (statuses[k], rev, note)
        else:
            plain[k] = (rev, note)
    if plain:
        store.bulk_set_tracking(plain)
    if status_items:
        store.bulk_set_status(status_items)
    if reconcile_steps and step_edits:
        _reconcile_steps(store, step_edits)




def _safe_refresh(store: Store, paths: dict[str, str], title: str) -> bool:
    """Refresh reports mid-scan without losing operator edits.

    Re-imports the operator's saved checkboxes/notes from the workbook FIRST (so
    editing Excel while the scan runs is safe), then regenerates. If the workbook
    is open/locked and can't be written, leaves it and returns False - the edits
    are already captured in the datastore, so nothing is lost.
    """
    _import_excel_tracking(store, paths, reconcile_steps=False)
    try:
        _generate_reports(store, paths, title, quiet=True)
        return True
    except Exception:  # noqa: BLE001
        # A locked workbook (OSError) OR any report-builder bug must NOT abort the
        # scan phase mid-run - the data is safe in the datastore, and the final
        # report (or a later `report` command) will regenerate it.
        return False


_DEFER_REPORTS = False




def _generate_reports(store: Store, paths: dict[str, str], title: str,
                      quiet: bool = False,
                      include_keys: "set[str] | None" = None) -> None:
    """Regenerate all reports from the datastore (the source of truth).

    include_keys: optional filter. When set, only vulns whose `.key` is in
    the set survive into the deliverables — used by the Report Studio's
    per-finding include/exclude toggles so the tester's selection reshapes
    the preview + downloads live."""
    if _DEFER_REPORTS:
        return
    hosts = store.all_hosts()
    from .. import qod, verify, dedup, kev, epss
    # Apply the tester's include filter first so downstream annotation and
    # dedup passes only touch what will actually appear in the report.
    # include_keys uses the same canonical vuln_row_key the frontend and
    # tracking table use ("vuln:ip:port:script_id:title[:60]"), so the two
    # views stay in sync.
    if include_keys is not None:
        from ..tracking import vuln_row_key
        for h in hosts:
            h.vulns = [v for v in h.vulns if vuln_row_key(v) in include_keys]
    for h in hosts:                    # ensure every finding is QoD-scored before report/gates
        qod.annotate(h)
        kev.annotate(h)                # flag CVEs confirmed exploited-in-the-wild (fix-first)
        epss.annotate(h)               # 30-day exploitation probability (prioritization)
        verify.apply_refutations(h)    # refute leads an NSE check already disproved (patched)
    # A refuted finding was actively disproven (an NSE check said NOT VULNERABLE), so it is
    # hidden from the deliverables by default - but NEVER deleted: the raw row stays in the
    # datastore, and `report --show-refuted` surfaces it (north star: no false negatives).
    if (store.get_meta("show_refuted") or "0") != "1":
        for h in hosts:
            h.vulns = [v for v in h.vulns if not verify.is_refuted(v)]
    for h in hosts:                    # collapse duplicate findings into one row (after
        dedup.dedupe_host(h)           # refutation) - presentation-only; raw rows kept
    # Optional noise floor: hide findings below the operator's QoD threshold from the
    # deliverables (set via `report --min-qod N`, persisted in meta; 0 = show all).
    try:
        min_qod = int(store.get_meta("min_qod") or 0)
    except (TypeError, ValueError):
        min_qod = 0
    if min_qod > 0:
        for h in hosts:
            h.vulns = [v for v in h.vulns if qod.qod_of(v) >= min_qod]
    tracking = store.get_tracking()
    domains = _resolve_domains(store, hosts)
    meta = {"subtitle": title}
    # If this (or the originating scan) ran through a proxy, stamp the datastore so the
    # note survives a later plain `recce report`, and surface it in the deliverables -
    # a reader must know the data came from a connect-scan-only, no-UDP proxied run.
    from .. import proxy as _proxy
    if _proxy.is_active():
        store.set_meta("proxy", _proxy.describe())
    proxy_note = store.get_meta("proxy") or ""
    if proxy_note:
        meta["proxy"] = proxy_note
    # Fold each deep-module's saved analysis blob into the report meta. They all
    # follow the identical shape (the report-meta key == the stored-meta name), so
    # one loop replaces what used to be a dozen copy-pasted get_meta/json.loads
    # guards - the same drift risk the service-command collapse removed.
    for _mk in ("ad_bloodhound", "mssql", "smb", "ftp", "docker", "kubernetes",
                "ldap", "snmp", "mongodb", "redis", "elasticsearch", "rsync",
                "nfs", "kerberos"):
        _blob = store.get_meta(_mk)
        if _blob:
            try:
                meta[_mk] = json.loads(_blob)
            except ValueError:
                pass
    credentials = store.all_credentials()   # one table scan, shared by both reports
    update_workbook(paths["xlsx"], hosts, meta=meta,
                    domains=domains, tracking=tracking, scope=store.get_scope(),
                    statuses=store.get_statuses(), issues=store.get_issues(),
                    credentials=credentials)
    build_markdown(hosts, paths["md"], title=title, domains=domains, proxy_note=proxy_note)
    build_csv(hosts, paths["csv"])
    # A client-facing write-up for EVERY true finding, following the write-up template
    # (Narrative / Finding Details / Mission Risk & Impact / Recommendations / Evidence
    # / Obtained Access / Technical Walkthrough). Auto-generated each run so the operator
    # never has to request them one by one; leads/version-guesses and info are excluded
    # by default (build_combined's _is_real filter). `recce writeup <id>` still targets one.
    try:
        from ..report_docx import build_combined
        # Client branding + engagement context so the cover page reflects the
        # actual engagement, not just "recce". Fields are optional; the builder
        # skips the cover cleanly when nothing is set.
        _brand_meta = {k: (store.get_meta(k) or "") for k in
                       ("client", "start_date", "end_date", "testers", "tester",
                        "scope_notes", "roe_notes", "client_logo")}
        _eng_dir = os.path.dirname(paths["docx"])
        build_combined(hosts, paths["docx"], title=title,
                       meta=_brand_meta, eng_dir=_eng_dir)
    except Exception as e:  # noqa: BLE001 - a writeup failure never blocks the other reports
        if not quiet:
            print(f"    [!] findings write-up doc skipped: {e}")
    from ..report_html import build_html, build_assets_html
    gen = _now()
    build_html(hosts, paths["html"], title=title, domains=domains,
               credentials=credentials, generated=gen, tracking=tracking,
               assets_link=os.path.basename(paths["assets"]), proxy_note=proxy_note)
    build_assets_html(hosts, paths["assets"], title=title, domains=domains,
                      credentials=credentials, generated=gen,
                      ad_bloodhound=meta.get("ad_bloodhound"),
                      report_link=os.path.basename(paths["html"]))
    # Standalone, directly-viewable diagrams (open the .svg in any browser — no tools).
    # Best-effort - never block a report on these.
    try:
        from .. import netmap
        eng_dir = os.path.dirname(paths["html"])
        ad_blob = meta.get("ad_bloodhound")

        def _write(name, text):
            with open(os.path.join(eng_dir, name), "w", encoding="utf-8") as fh:
                fh.write(text)

        def _standalone_svg(text):
            # the embedded copy omits xmlns; a file needs it to render on its own
            return text.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)

        # Two directly-viewable SVG network maps (open in any browser, no tools):
        #   * FULL     - every host as its own card (the detailed map)
        #   * OVERVIEW - each subnet collapsed to per-role counts (readable at scale)
        _write("network-architecture.svg",
               _standalone_svg(netmap.architecture_svg(hosts, domains, ad_blob)))
        _write("network-map-full.svg",
               _standalone_svg(netmap.svg(hosts, domains, ad_blob, aggregate=False)))
        _write("network-map-overview.svg",
               _standalone_svg(netmap.svg(hosts, domains, ad_blob, aggregate=True)))
        _write("network-map-tiered.svg",
               _standalone_svg(netmap.tiered_svg(hosts, domains, ad_blob)))
        # Observed reachability — only when an on-target enum brought topology back.
        if any((h.topology or {}) for h in hosts):
            _write("network-reachability.svg",
                   _standalone_svg(netmap.reachability_svg(hosts, ad_blob)))
        # Attack path as a standalone SVG too (only when there's a confirmed path).
        from .. import attackpath as _ap
        _ap_steps = _ap.build(hosts)
        if _ap_steps:
            _write("attack-path.svg", _standalone_svg(_ap.svg(hosts, _ap_steps)))
        # Standalone, directly-viewable AD tier-0 diagram (open the .svg in any
        # browser). It needs the xmlns the embedded copy omits to render as a file.
        arch = (meta.get("ad_bloodhound") or {}).get("architecture")
        if arch and arch.get("nodes"):
            svg = netmap.ad_svg(arch).replace(
                "<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
            with open(os.path.join(eng_dir, "ad-architecture.svg"), "w",
                      encoding="utf-8") as fh:
                fh.write(svg)
    except OSError:
        pass
    if not quiet:
        cov = tr.compute_coverage(hosts, tracking)["overall"]
        print(f"[+] Reports written ({cov['done']}/{cov['total']} items reviewed, "
              f"{cov['pct']}%):\n    {paths['xlsx']}\n    {paths['md']}\n    {paths['csv']}"
              f"\n    {paths['html']}\n    {paths['assets']} (architecture & assets)"
              f"\n    network map: network-architecture.svg (infra + segments) + "
              f"network-map-full.svg (every host) + "
              f"network-map-overview.svg (by role) + network-map-tiered.svg "
              f"(DC→servers→hosts) — open in any browser, no tools")
        counts = store.count_issues()
        if counts.get("total"):
            print(f"[!] {counts['total']} scan issue(s) logged "
                  f"({counts.get('error', 0)} error, {counts.get('warning', 0)} "
                  f"incomplete) - see the Overview tab or {paths['log']}")




# --- scan command ----------------------------------------------------------------

def _apply_profile_overrides(profile, args) -> None:
    g = lambda name, default=None: getattr(args, name, default)  # noqa: E731
    if g("top_ports"):
        profile.all_ports = False
        profile.top_ports = args.top_ports
    # --all-ports is the explicit, profile-overriding "full 65535-port sweep" and is
    # applied after --top-ports so it wins over a quick profile or a lingering
    # --top-ports.
    if g("all_ports"):
        profile.all_ports = True
    if g("no_ad"):
        profile.ad_enrich = False
    if g("no_os"):
        profile.os_detect = False
    if g("min_rate"):
        profile.min_rate = args.min_rate
    if g("max_retries") is not None:
        profile.max_retries = args.max_retries
    if g("no_verify"):
        profile.verify = False
    if g("verify_all"):
        profile.verify_all = True
    if g("no_udp_fallback"):
        profile.udp_fallback = False
    if g("reliable"):
        profile.reliable = True
    if g("udp_top") is not None:     # explicit --udp-top wins, including 0 (disable)
        profile.udp_top = args.udp_top
    if g("no_udp"):
        profile.udp_basic = False
        profile.udp_top = 0          # --no-udp skips BOTH the basic sweep and the top-N pass
    if g("masscan") or g("fast"):
        profile.scanner = "masscan"
    if g("offline"):
        profile.offline = True
    if g("host_timeout") is not None:
        profile.host_timeout = args.host_timeout
    if g("version_all"):
        profile.version_all = True
    if g("version_intensity") is not None:
        profile.version_intensity = args.version_intensity
    # An authoritative target list implies -Pn: every provided host is treated as up
    # (we pre-seed them), so discovery must not drop any as "down".
    if g("targets_up", False):
        profile.ping_discovery = False
    else:
        profile.ping_discovery = not g("no_discovery", False)
    profile.assume_up = not profile.ping_discovery   # -Pn: fail-fast on dead IPs
    if g("no_reconfirm", False):
        profile.reconfirm = False
    # Through a proxy, force the connect-scan / no-masscan / no-UDP / no-ICMP profile so
    # nothing bypasses the tunnel and scans from the operator's real IP (runs last so it
    # wins over the discovery flags above).
    scanner.harden_for_proxy(profile)




def _split_userdomain(username: str, domain: str | None) -> tuple[str, str]:
    """Accept a domain-qualified username and split the domain out, so a tester can
    type the credential however AD hands it to them:
        -u 'CORP\\administrator'        -> user=administrator, domain=CORP
        -u 'corp.local/administrator'   -> user=administrator, domain=corp.local
        -u 'administrator@corp.local'   -> user=administrator, domain=corp.local
    An explicit -d always wins; an embedded domain only fills in when -d was
    omitted (so `-u CORP\\admin -d corp.local` keeps the fuller -d form)."""
    user = username or ""
    dom = domain or ""
    if "\\" in user:
        d, user = user.split("\\", 1)
        dom = dom or d
    elif "/" in user:
        d, user = user.split("/", 1)
        dom = dom or d
    elif "@" in user:
        user, d = user.rsplit("@", 1)
        dom = dom or d
    return user, dom




def _creds_of(args) -> dict | None:
    if not getattr(args, "username", None):
        return None
    user, domain = _split_userdomain(args.username, getattr(args, "domain", None))
    return {"username": user, "password": args.password, "domain": domain}




def _db_login_creds(args, store) -> list[dict]:
    """Login credentials to try against auth-required DB instances: the command's own
    -u/-p first, then every cleartext-password credential already captured in the
    datastore (looted / sprayed) - so a protected DB is auto-tried with what we have."""
    out: list[dict] = []
    seen = set()

    def add(user, secret):
        if user and secret is not None and (user, secret) not in seen:
            seen.add((user, secret))
            out.append({"username": user, "secret": secret})

    if getattr(args, "username", None) and getattr(args, "password", None) is not None:
        add(args.username, args.password)
    try:
        for c in store.all_credentials():
            # password-shaped secrets only; hashes aren't usable for a SCRAM/md5 login.
            if getattr(c, "kind", "") in ("password", "plaintext", "cleartext", ""):
                add(c.username, c.secret)
    except Exception:      # noqa: BLE001 - a datastore hiccup must not abort the scan
        pass
    return out




def _web_login_creds(args, store) -> list[tuple]:
    """(user, password) pairs for web form auto-login: any -u/-p, then every harvested
    cleartext-password credential in the datastore."""
    out: list[tuple] = []
    seen: set = set()

    def add(u, p):
        if u and p is not None and (u, p) not in seen:
            seen.add((u, p))
            out.append((u, p))

    if getattr(args, "username", None) and getattr(args, "password", None) is not None:
        add(args.username, args.password)
    try:
        for c in store.all_credentials():
            if getattr(c, "kind", "") in ("password", "plaintext", "cleartext", ""):
                add(c.username, c.secret)
    except Exception:      # noqa: BLE001
        pass
    return out




def _admin_creds_of(args) -> dict | None:
    """The optional privileged/superuser account (domain defaults to -d)."""
    if not getattr(args, "admin_username", None):
        return None
    user, domain = _split_userdomain(
        args.admin_username,
        getattr(args, "admin_domain", None) or getattr(args, "domain", None))
    return {"username": user, "password": args.admin_password, "domain": domain}




def _final_report(store, paths, title) -> None:
    """Always-try final report (guarded); results survive even if the file is
    locked, since they're in the datastore."""
    try:
        _import_excel_tracking(store, paths, reconcile_steps=False)
        _generate_reports(store, paths, title)
    except Exception as e:  # noqa: BLE001
        # Runs in every command's `finally`, so a locked workbook OR any
        # report-builder bug must not turn completed scan work into a crash.
        detail = "open/locked" if isinstance(e, OSError) else f"{type(e).__name__}: {e}"
        print(f"[!] Could not write the workbook ({detail}). Your data is saved "
              "in the datastore - close the file and run `report` to rebuild it.")




# --- phase 1+2a: discovery + light service enumeration --------------------------

def _mkissue(scan_issue, phase: str) -> dict:
    return {"phase": phase, "level": scan_issue.level,
            "message": scan_issue.message}




def _enum_worker(ip, profile, paths, creds, port_map, subnet_map, active_probe=True,
                 disc_reason="", provided_name=""):
    """Returns (host|None, issues)."""
    issues: list[dict] = []
    truncated = False
    # Proof-of-life reason for this host. Seeded with the discovery reply (echo-reply
    # /syn-ack/arp-response) when host discovery ran; a UDP fallback below can supply
    # one for a silent -Pn host. Empty stays empty -> the host build falls back to
    # "user-set" under -Pn, which is-NOT proof (keeps it off the confirmed-up list).
    up_reason = disc_reason
    # The nmap sweep (-sS/-sT --open) is authoritative: its open ports are folded into
    # the host after enum so the enum re-scan can enrich them but never drop one it
    # missed. The masscan `--fast` port_map is a stateless sweep that can false-positive,
    # so its ports are handled differently below: kept UNLESS the enum re-scan actively
    # disproved them (nmap saw the port closed), so real ports survive enum packet loss
    # while masscan's spurious opens are still pruned.
    swept_ports: list = []
    masscan_candidates: list = []
    if port_map is not None:
        open_ports = port_map.get(ip, [])
        masscan_candidates = list(open_ports)
    else:
        fp_xml = os.path.join(paths["raw"], f"{ip}_ports.xml")
        _, iss = scanner.full_port_scan(ip, fp_xml, profile)
        if iss:
            issues.append(_mkissue(iss, "port-sweep"))
            truncated = iss.kind == "host-timeout"
        open_ports = _ports_for_host(fp_xml, ip)
        swept_ports = _swept_ports_for_host(fp_xml, ip)
        # Completeness safeguard: re-scan (congestion-adaptive) and UNION the result
        # in (never replace) when the fast pass looks under-reported. Two triggers:
        #  - ZERO ports: genuinely empty, or every probe was dropped. Verified for a
        #    discovered-live host always; for a -Pn host only with --verify-all (so a
        #    big dead-IP scope isn't all re-scanned).
        #  - SUSPICIOUSLY FEW ports (possible partial drop: a lossy firewall silently
        #    swallowing SYNs to some open ports, even 22/80). This re-scan is as
        #    expensive as the sweep, and a plain 1-2 service host is the COMMON case,
        #    so it only fires when we're already being thorough - under -Pn/assume-up
        #    or --verify-all - never slowing a clean discovery scan of a normal host.
        # Completeness safety net: ANY host that showed life (>=1 open port) gets a
        # SECOND, independent congestion-adaptive full sweep (verify_port_scan: no
        # --min-rate floor, -T3, --max-retries 6), UNIONed with the first pass. No finite
        # --max-retries can guarantee an open port is seen on a lossy link, but a port
        # dropped in one pass is almost always caught by an independent second pass - and
        # if BOTH miss it, a manual nmap would too. A dead / 0-port host is bounded by the
        # min-rate floor + --host-timeout and handled by the 0-port branch (not this
        # second sweep). `reliable` already IS the adaptive pass, so don't double it.
        alive = len(open_ports) > 0 and not profile.reliable
        do_verify = profile.verify and not truncated and (
            (not open_ports and (profile.ping_discovery or profile.verify_all)) or alive)
        if do_verify:
            vx = os.path.join(paths["raw"], f"{ip}_verify.xml")
            _, viss = scanner.verify_port_scan(ip, vx, profile)
            vports = _ports_for_host(vx, ip)
            if viss and viss.kind == "host-timeout":
                truncated = True
            if vports:
                before = set(open_ports)
                open_ports = sorted(before | set(vports))
                swept_ports = _union_swept(swept_ports, _swept_ports_for_host(vx, ip))
                gained = len(open_ports) - len(before)
                if gained > 0:
                    issues.append(_mkissue(scanner.ScanIssue(
                        "warning", f"port-sweep: fast pass found {len(before)} port(s); a "
                        f"congestion-adaptive re-scan found {gained} more - the first "
                        "sweep under-reported (network likely lossy); merged both"),
                        "port-sweep"))
        # Host-timeout auto-retry: a slow firewalled host whose sweep hit --host-timeout
        # is NOT a dead end. If it showed any sign of life (some ports, or a discovery/
        # named-target reply), give it ONE more pass with a LONGER (but capped)
        # host-timeout and congestion-adaptive timing, and union what it finds. Without
        # this a slow host times out mid-sweep and shows 0 ports even though 22/80 are
        # open. Gated on signs-of-life so a genuinely dead -Pn IP isn't re-scanned.
        if (truncated and profile.retry_truncated and profile.host_timeout
                and (open_ports or up_reason)):
            import dataclasses
            # Double the host-timeout, but capped so a dead/very-slow host can't become
            # a runaway (2x a 20-minute default would be 40 minutes for one host).
            retry_ht = min(max(1, profile.host_timeout) * 2,
                           max(_RETRY_HOST_TIMEOUT_CAP_MIN, profile.host_timeout))
            rprof = dataclasses.replace(profile, reliable=True, host_timeout=retry_ht)
            rx = os.path.join(paths["raw"], f"{ip}_retry.xml")
            _, riss = scanner.full_port_scan(ip, rx, rprof)
            rports = _ports_for_host(rx, ip)
            truncated = bool(riss and riss.kind == "host-timeout")
            if rports:
                before = set(open_ports)
                open_ports = sorted(before | set(rports))
                swept_ports = _union_swept(swept_ports, _swept_ports_for_host(rx, ip))
                issues.append(_mkissue(scanner.ScanIssue(
                    "warning", f"port-sweep: host timed out; a retry with a "
                    f"{rprof.host_timeout}m host-timeout recovered "
                    f"{len(open_ports) - len(before)} additional port(s)"),
                    "port-sweep"))
        # Filtered-port TCP-connect retry: a -sS pass records `open|filtered` when
        # a firewall silently drops the response - the port is OPEN or FILTERED,
        # never CLOSED, but the sweep can't tell which. A full TCP handshake (-sT,
        # no root needed) either completes (definitive open, with a service reply
        # the parser can grab as evidence) or gets a RST (definitive closed). Runs
        # only on the ports actually in `open|filtered` state, capped so a heavily
        # firewalled host can't blow scan time. Never DROPS a port - a probe that
        # still times out leaves the sweep record as-is.
        if profile.filtered_retry and swept_ports:
            filt = [p.portid for p in swept_ports if p.state == "open|filtered"]
            if filt:
                filt = sorted(set(filt))[: max(1, profile.filtered_retry_cap)]
                fx = os.path.join(paths["raw"], f"{ip}_filtered.xml")
                _, fiss = scanner.confirm_filtered_ports(ip, filt, fx, profile)
                if fiss and fiss.kind == "host-timeout":
                    truncated = True
                confirmed = _swept_ports_for_host(fx, ip)
                confirmed_open = [p for p in confirmed if p.state == "open"]
                if confirmed_open:
                    before = set(open_ports)
                    open_ports = sorted(before | {p.portid for p in confirmed_open})
                    # replace each still-filtered swept Port with the confirmed-open one
                    # so downstream folding gets the harder evidence + real reason.
                    idx = {(p.protocol, p.portid): i for i, p in enumerate(swept_ports)}
                    for cp in confirmed_open:
                        i = idx.get((cp.protocol, cp.portid))
                        if i is not None:
                            swept_ports[i] = cp
                    gained = len(open_ports) - len(before)
                    issues.append(_mkissue(scanner.ScanIssue(
                        "warning", f"filtered-retry: TCP-connect confirmed "
                        f"{len(confirmed_open)} of {len(filt)} `open|filtered` "
                        f"port(s) as OPEN"
                        + (f" (+{gained} previously unseen)" if gained else "")),
                        "filtered-retry"))
        # UDP fallback: still silent on TCP, no discovery reply, and we're treating
        # this IP as up on faith (-Pn / discovery blocked). A UDP ping to common
        # services tells up-behind-a-firewall apart from genuinely dead - so the host
        # is confirmed up on a real reply instead of being written off as down.
        if (not open_ports and not up_reason and not truncated
                and profile.udp_fallback and profile.assume_up):
            ulx = os.path.join(paths["raw"], f"{ip}_udpalive.xml")
            _, uiss = scanner.udp_liveness_probe(ip, ulx, profile)
            if uiss:                       # e.g. skipped (needs root) - surface it
                issues.append(_mkissue(uiss, "udp-liveness"))
            # np.parse_nmap_xml drops "down" hosts, so a host present here answered.
            alive = next((h for h in np.parse_nmap_xml(ulx) if h.ip == ip), None)
            if alive is not None:
                up_reason = alive.up_reason or "udp-response"
                issues.append(_mkissue(scanner.ScanIssue(
                    "warning", "udp-liveness: host answered a UDP probe "
                    f"({up_reason}) - confirmed UP despite 0 open TCP ports "
                    "(firewalled, not dead)"), "udp-liveness"))

    enum_xml = os.path.join(paths["raw"], f"{ip}_enum.xml")
    _, iss = scanner.enum_scan(ip, open_ports, enum_xml, profile, creds=creds)
    if iss:
        issues.append(_mkissue(iss, "enum"))
    host = _fold_host(ip, np.parse_nmap_xml(enum_xml), subnet_map)
    # The enum re-scan populated host.ports; fold the sweep's authoritative open ports
    # back in so a port the sweep definitively found is never lost when the heavier enum
    # pass under-reports (lossy network / host-timeout) - the root cause of a host with
    # real services being reported as "0 open ports".
    _fold_swept_ports(host, swept_ports)
    # masscan (--fast) path: masscan is stateless and can't be blindly trusted, so a
    # masscan-observed port is kept only if the enum re-scan didn't actively disprove it
    # (nmap saw it closed). This recovers ports enum lost to packet loss - the same "0
    # open ports" failure as the nmap path - while still pruning masscan's false opens.
    if masscan_candidates:
        from ..models import Port
        disproved = _disproved_ports_in_xml(enum_xml, ip)
        have = {(p.protocol, p.portid) for p in host.ports}
        for pid in masscan_candidates:
            key = ("tcp", pid)
            if key in have or key in disproved:
                continue
            host.ports.append(Port(
                portid=pid, protocol="tcp", state="open", detect_source="masscan",
                reason="masscan-syn-ack (enum re-scan got no reply - kept, not confirmed)"))
    host.enumerated = True
    host.incomplete_scan = truncated
    # Record how we know this host is up: a real reply (discovery or UDP fallback)
    # when we have one, else "user-set" under -Pn (scanned on faith - not proof, so
    # a silent host stays UNKNOWN, never marked down). An open port speaks for itself.
    host.up_reason = up_reason or ("user-set" if profile.assume_up else host.up_reason)
    # An authoritative list supplies the hostname up front; keep it (nmap-resolved
    # names, if any, come first) so the host is labelled even when it answered nothing.
    if provided_name:
        host.hostnames = list(dict.fromkeys(host.hostnames + [provided_name]))
    # Basic UDP sweep: a TCP-only scan misses DNS/SNMP/NTP/IKE/TFTP/NetBIOS/... Fold any
    # open UDP services into the host. Runs in the per-host nmap path only (not the fast
    # masscan sweep, where UDP stays opt-in via --udp-top).
    if profile.udp_basic and port_map is None and not truncated:
        udp_xml = os.path.join(paths["raw"], f"{ip}_udp_basic.xml")
        _, uiss = scanner.udp_basic_scan(ip, udp_xml, profile)
        if uiss:
            issues.append(_mkissue(uiss, "udp-basic"))
        uhost = next((h for h in np.parse_nmap_xml(udp_xml) if h.ip == ip), None)
        if uhost is not None:
            have = {(p.protocol, p.portid) for p in host.ports}
            host.ports.extend(p for p in uhost.ports
                              if (p.protocol, p.portid) not in have)
    # Recover the services nmap left as unknown/blank: mine its kept fingerprint,
    # fall back to the curated port map, then a stdlib banner grab (active) - so a
    # port like 5040 becomes 'Windows CDPSvc', not a dead 'unknown'.
    from .. import svcdetect
    svcdetect.enrich_host(host, active=active_probe)
    # Second opinion: for the handful of ports STILL unnamed, re-run nmap at max
    # version effort (--version-all) aimed at just those - cheap because it's a few
    # ports, and it's authoritative. Gated with the active probes (--no-probes).
    if active_probe:
        leftover = svcdetect.still_unknown_ports(host)
        if leftover:
            rp_xml = os.path.join(paths["raw"], f"{ip}_reprobe.xml")
            _, riss = scanner.reprobe_services(ip, leftover, rp_xml, profile)
            if riss:
                issues.append(_mkissue(riss, "reprobe"))
            svcdetect.apply_reprobe(host, np.parse_nmap_xml(rp_xml))
    ad.identify_roles(host)
    ad.parse_signing_and_ntlm(host)
    from .. import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings, immediately
    from .. import qod
    qod.annotate(host)                 # stamp Quality-of-Detection once, from the method
    return host, issues




def _reconfirm_missed(missed, profile, paths):
    """Fast -Pn top-ports re-probe of hosts that missed the ping sweep. A host that
    answers on ANY port is definitively up, so this recovers firewalled-but-alive boxes
    before they're written off as down. Returns ({ip: up_reason}, issue|None)."""
    if not missed or not profile.reconfirm:
        return {}, None
    if len(missed) > profile.reconfirm_cap:
        print(f"    ({len(missed)} non-responders exceed the reconfirm cap "
              f"{profile.reconfirm_cap}; skipping the re-probe - re-run with -Pn or "
              "--fast to sweep them all.)")
        return {}, None
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(missed))
        tfile = tf.name
    rx = os.path.join(paths["raw"], "reconfirm.xml")
    print(f"[*] Reconfirming {len(missed)} non-responder(s) with a fast -Pn top-ports "
          "probe (catches firewalled-but-alive hosts) ...")
    try:
        _, iss = scanner.reconfirm_hosts(tfile, rx, profile)
    finally:
        try:
            os.unlink(tfile)          # always remove the temp target list, even on error
        except OSError:
            pass
    recovered = {h.ip: (h.up_reason or "reconfirm: open port")
                 for h in np.parse_nmap_xml(rx) if h.open_ports}
    return recovered, iss




def _seed_targets(store, live_ips, subnet_map, hostname_map):
    """Pre-register every target as a known host BEFORE scanning, so a slow/timed-out/
    failed scan can never make a real target vanish from the report ('false no hosts').
    Each is stored up-front with its provided hostname and up_reason 'target-list'; the
    enum phase then enriches it in place. Returns the count seeded."""
    from ..models import Host
    n = 0
    for ip in live_ips:
        h = Host(ip=ip, subnet=subnet_map.get(ip, ""), up_reason="target-list")
        name = hostname_map.get(ip)
        if name:
            h.hostnames = [name]
        store.upsert_host(h, merge=True)     # merge: never clobber an already-scanned host
        n += 1
    return n




def _discover(args, profile, store, paths):
    try:
        hosts, subnet_map, hostname_map = load_targets(args.targets)
    except (ValueError, OSError) as e:
        # Bad CIDR/range (ValueError) or a missing/unreadable @file (OSError) - the
        # literal first thing a tester types. Fail with a clear message, not a crash.
        print(f"[x] Invalid targets: {e}\n    Fix the IP / range / CIDR / @file "
              "and re-run.")
        return None, [], None, None, {}
    # Exclusions: expand this run's --exclude (IPs / ranges / CIDRs / @file), MERGE with
    # any persisted from a prior run, and persist the union - so once an IP is excluded
    # it stays out of scope on every later phase/re-run without re-typing it.
    try:
        run_excl = expand_excludes(args.exclude or [])
    except (ValueError, OSError) as e:
        print(f"[x] Invalid --exclude: {e}")
        return None, [], None, None, {}
    try:
        stored_excl = set(json.loads(store.get_meta("excludes") or "[]"))
    except (ValueError, TypeError):
        stored_excl = set()
    excluded = run_excl | stored_excl
    if excluded != stored_excl:
        store.set_meta("excludes", json.dumps(sorted(excluded)))
    before = len(hosts)
    hosts = [h for h in hosts if h not in excluded]
    if before != len(hosts):
        print(f"[+] Excluded {before - len(hosts)} host(s) from scope "
              f"({len(excluded)} IP(s) on the exclusion list).")
    if not hosts:
        print("[x] No targets after expansion/exclusion.")
        return None, [], None, None, {}
    # Record the full scope so the report accounts for every subnet, even those
    # that turn out to have no live hosts.
    sizes: dict[str, int] = {}
    for ip in hosts:
        sizes[subnet_map[ip]] = sizes.get(subnet_map[ip], 0) + 1
    for subnet, size in sizes.items():
        store.set_scope(subnet, size)
    print(f"[+] {len(hosts)} target host(s) across {len(sizes)} subnet(s).")

    fast_mode = getattr(args, "fast", False) or profile.scanner == "masscan"
    port_map = None
    disc_reasons: dict[str, str] = {}   # ip -> real discovery reply reason (proof of up)
    if fast_mode:
        print("[*] Fast mode: network-wide masscan sweep ...")
        sweep_xml = os.path.join(paths["raw"], "masscan_sweep.xml")
        port_map = scanner.masscan_sweep(hosts, sweep_xml, profile)
        if port_map:
            if getattr(args, "targets_up", False):
                # Authoritative list: enumerate EVERY provided host, not just the ones
                # masscan found open, so a silent host is still seeded (never "no hosts").
                live_ips = sorted(hosts, key=_ip_key)
                print(f"[+] masscan found {len(port_map)} host(s) with open ports; "
                      f"enumerating all {len(live_ips)} authoritative target(s).")
            else:
                live_ips = sorted(port_map, key=_ip_key)
                print(f"[+] masscan found {len(live_ips)} host(s) with open ports.")
                # masscan is stateless and drops SYNs under load, so a target it did
                # NOT report is NOT necessarily closed - it may be a live host whose
                # probes were dropped. Never silently discard them: warn + record a
                # durable issue so they're recoverable, not lost from the engagement.
                missed = [ip for ip in hosts if ip not in set(port_map)]
                if missed:
                    print(f"[!] masscan reported 0 open ports on {len(missed)} of "
                          f"{len(hosts)} target(s). masscan can drop SYNs under load, so "
                          "this may hide live hosts. They are NOT enumerated in --fast - "
                          "re-run without --fast (accurate nmap sweep), or with "
                          "--targets-up to force-enumerate every target.")
                    _record_issues(store, paths, "(fast-sweep)", [{
                        "phase": "discovery", "level": "warning",
                        "message": f"--fast/masscan reported 0 open ports on "
                        f"{len(missed)} target(s); NOT enumerated (masscan drops SYNs "
                        "under load). Re-scan without --fast or use --targets-up. "
                        "Missed: " + ", ".join(missed[:50])
                        + (" …" if len(missed) > 50 else "")}])
        else:
            print("[!] masscan unavailable/empty; falling back to nmap.")
            port_map, fast_mode = None, False

    if not fast_mode:
        if profile.ping_discovery:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(hosts))
                targets_file = tf.name
            disc_xml = os.path.join(paths["raw"], "discovery.xml")
            print("[*] Discovery: host sweep ...")
            try:
                _, iss = scanner.discover_hosts(targets_file, disc_xml)
                if iss:
                    _record_issues(store, paths, "(discovery)", [_mkissue(iss, "discovery")])
                disc_hosts = np.parse_nmap_xml(disc_xml)
                live_ips = [h.ip for h in disc_hosts]
                # Carry each responder's real status reason (echo-reply/syn-ack/arp-...)
                # into the enum phase so the stored host records HOW we know it's up.
                disc_reasons = {h.ip: (h.up_reason or "discovery")
                                for h in disc_hosts if h.up_reason not in ("", "user-set")}
            finally:
                try:
                    os.unlink(targets_file)   # always remove the temp target list
                except OSError:
                    pass
            print(f"[+] {len(live_ips)} of {len(hosts)} target(s) responded to discovery.")
            if not live_ips:
                # Zero responses almost always means the network blocks ping/probes,
                # not that nothing is there. Don't hand back an empty engagement -
                # fall back to -Pn (scan every target as up) automatically.
                print("\n" + "!" * 64)
                print("[!] 0 hosts answered host discovery - the network is likely "
                      "blocking ping/probes.")
                print("    Falling back to -Pn (scanning all targets as up) so you "
                      "don't miss firewalled hosts.")
                print(f"    Per-host cap {profile.host_timeout}m + fail-fast keep it "
                      "moving; for a large scope, --fast (masscan) sweeps in seconds.")
                print("!" * 64)
                # Behave exactly like an explicit -Pn from here: assume-up + skip the
                # per-dead-IP verify re-scan (the UDP fallback still fires, gated on
                # assume_up). Leaving ping_discovery True would re-scan every dead IP
                # on precisely the large, discovery-blocked scope we want to move fast.
                profile.assume_up = True
                profile.ping_discovery = False
                # Discovery is fully blocked => this is the firewalled scope where a
                # single fast pass can silently drop every SYN with no drop-marker to
                # trigger the adaptive rescan. Force the union re-verify on EVERY host
                # (incl. ones that came back with 0 ports), so a firewalled-but-alive
                # box that the first pass missed gets a real second look instead of
                # being recorded as 0 ports. This is exactly the "manual nmap finds
                # ports recce didn't" engagement - be thorough here, not fast.
                profile.verify_all = True
                live_ips = hosts
            elif len(live_ips) < len(hosts):
                # Partial sweep: DON'T drop the non-responders on faith - a live host
                # behind a default-drop firewall blocks ping yet still answers a port
                # scan. Re-probe them; promote any that show an open port.
                responded = set(live_ips)
                missed = [ip for ip in hosts if ip not in responded]
                recovered, riss = _reconfirm_missed(missed, profile, paths)
                if riss:
                    _record_issues(store, paths, "(reconfirm)",
                                   [_mkissue(riss, "reconfirm")])
                if recovered:
                    live_ips = list(live_ips) + [ip for ip in missed if ip in recovered]
                    disc_reasons.update(recovered)
                    print(f"    [+] Reconfirm recovered {len(recovered)} host(s) that "
                          "blocked ping but answered a port scan.")
                # A host the operator NAMED individually (a bare IP / hostname, not a
                # CIDR-expanded scope host) that blocked discovery + reconfirm is very
                # likely a firewalled-but-alive box the operator cares about - force a
                # real -Pn port scan of it rather than dropping it. Bounded to named
                # targets, so a dead CIDR IP is still not full-scanned.
                still_ips = sorted((ip for ip in missed if ip not in set(live_ips)),
                                   key=_ip_key)
                named = explicit_targets(args.targets)
                named_still = [ip for ip in still_ips if ip in named]
                if named_still:
                    live_ips = list(live_ips) + named_still
                    for ip in named_still:
                        disc_reasons.setdefault(ip, "named-target (-Pn, blocked discovery)")
                    still_ips = [ip for ip in still_ips if ip not in named]
                    print(f"    [+] {len(named_still)} named target(s) blocked discovery "
                          "- force-scanning them with -Pn anyway.")
                # Any REMAINING (CIDR-expanded) non-responders are not scanned - full-
                # scanning every one would reintroduce the cost the reconfirm cap avoids -
                # but must not silently vanish. Persist the list as a durable issue.
                if still_ips:
                    shown = ", ".join(still_ips[:20]) + (" …" if len(still_ips) > 20 else "")
                    _record_issues(store, paths, "(discovery)", [_mkissue(
                        scanner.ScanIssue(
                            "warning",
                            f"discovery: {len(still_ips)} target(s) blocked host "
                            f"discovery AND the reconfirm port-probe, so they were NOT "
                            f"port-scanned and their open ports (if any) are unknown. "
                            f"Re-run with -Pn to force-scan them: {shown}"),
                        "discovery")])
                    print(f"    ({len(still_ips)} still didn't answer - recorded as "
                          "unscanned. Re-run with -Pn to force-scan them.)")
        else:
            live_ips = hosts
            print(f"[*] -Pn: skipping discovery, scanning all {len(hosts)} target(s) "
                  "as up.")
            print(f"    Each host is capped at {profile.host_timeout}m (--host-timeout) "
                  "and dead IPs are abandoned fast; --fast (masscan) is quickest on a "
                  "big scope.")
            if profile.udp_fallback:
                print("    A host still silent on TCP gets a UDP liveness ping, so a "
                      "firewalled-but-alive box is confirmed up, not ruled dead "
                      "(--no-udp-fallback to skip).")

    if getattr(args, "resume", False):
        # Skip only hosts the enum phase actually finished (host.enumerated, set at the
        # end of _enum_worker), NOT every seeded row. _seed_targets pre-writes a row for
        # every target before scanning, so a naive "all seeded IPs" set would wrongly treat a
        # host that was seeded-but-not-yet-enumerated (a run interrupted right after
        # seeding) as done and skip it forever.
        done = {h.ip for h in store.all_hosts() if h.enumerated}
        live_ips = [ip for ip in live_ips if ip not in done]
        print(f"[+] Resume: {len(live_ips)} host(s) remaining.")
    # Authoritative list: seed each responder's up-reason so a provided host is shown
    # up (labelled 'target-list') even before its scan finishes.
    if getattr(args, "targets_up", False):
        for ip in live_ips:
            disc_reasons.setdefault(ip, "target-list")
    return subnet_map, live_ips, port_map, disc_reasons, hostname_map




def _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map,
                disc_reasons=None, hostname_map=None) -> None:
    creds = _creds_of(args)
    workers = max(1, args.workers)
    disc_reasons = disc_reasons or {}
    hostname_map = hostname_map or {}
    # --no-probes disables our active stdlib layer (banner grabs); the free passive
    # layers (servicefp mining + curated port map) still run.
    active_probe = not getattr(args, "no_probes", False)
    # Announce the port scope so a full sweep is verifiable - and loudly flag a PARTIAL
    # (top-N) one so it's never mistaken for a complete scan. Recorded for the report.
    scope_label, is_full = scanner.port_scope_label(profile)
    store.set_meta("port_scope", scope_label)
    if is_full:
        print(f"[*] Port scope: {scope_label} per host (full sweep).")
    else:
        print(f"[!] Port scope: {scope_label} per host - PARTIAL, NOT a full scan. "
              "Pass --all-ports (or --profile standard) for all 65535 ports.")
    print(f"[*] Enumerating {len(live_ips)} host(s) with {workers} worker(s) "
          f"(ports + services) ...")
    completed = 0
    refresher = _Refresher(args)
    # B5 - detect the scanning source getting rate-limited/blocked mid-run: once we've
    # seen real signal (some hosts with open ports), a long run of consecutive 0-port
    # hosts is the classic "IPS blocked our source IP" symptom. Warn ONCE so the tail
    # of the scope isn't silently written off as clean.
    hosts_with_ports = 0
    zero_streak = 0
    ips_block_warned = False
    _IPS_ZERO_STREAK = 15
    # Resolve _enum_worker through the cli package so tests can monkey-patch
    # `cli._enum_worker` and see the patch take effect here (the classic
    # Python "how monkey-patching interacts with imports" gotcha — a local
    # reference would bypass the patch).
    _cli = sys.modules[__package__]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_cli._enum_worker, ip, profile, paths, creds, port_map,
                             subnet_map, active_probe, disc_reasons.get(ip, ""),
                             hostname_map.get(ip, "")): ip
                   for ip in live_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "enum", "level": "error",
                                 "message": f"enum crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            if host is None:
                continue
            if not _persist_host(store, paths, ip, "enum", host, clear_step="enum"):
                continue   # one host's persist failure never aborts the rest
            completed += 1
            extra = f" - {', '.join(host.roles)}" if host.roles else ""
            print(f"    [{completed}/{len(live_ips)}] {ip}: "
                  f"{len(host.open_ports)} open port(s){extra}")
            refresher.tick(store, paths, args.title)
            # B5: track the open-port hit-rate; a long zero-streak AFTER real signal
            # smells like the source got throttled/blocked partway through.
            if host.open_ports:
                hosts_with_ports += 1
                zero_streak = 0
            else:
                zero_streak += 1
            if (not ips_block_warned and hosts_with_ports >= 5
                    and zero_streak >= _IPS_ZERO_STREAK):
                ips_block_warned = True
                msg = (f"{zero_streak} consecutive host(s) returned 0 open ports after "
                       f"{hosts_with_ports} host(s) with open ports earlier - the "
                       "scanning source may have been rate-limited/blocked by an IPS. "
                       "Pause, switch source IP, or lower --workers / timing, then "
                       "re-scan the tail (recce merges, so nothing is duplicated).")
                print("\n" + "!" * 64
                      + f"\n[!] POSSIBLE SOURCE-IP BLOCK (IPS?): {msg}\n"
                      + "!" * 64 + "\n")
                _record_issues(store, paths, "(enum)", [{
                    "phase": "enum", "level": "warning",
                    "message": "possible IPS / source-IP block mid-scan: " + msg}])




# --- phase 2b: vulnerability scanning (per open port) ---------------------------

def _merge_vuln_results(host: Host, parsed_list) -> None:
    """Fold vuln-phase results (vulns, accounts, port scripts) into a host."""
    port_index = {(p.protocol, p.portid): p for p in host.ports}
    for ph in parsed_list:
        if ph.ip != host.ip:
            continue
        vseen = {v.key for v in host.vulns}
        host.vulns.extend(v for v in ph.vulns if v.key not in vseen)
        aseen = {(a.source, a.kind, a.name, a.domain, a.rid) for a in host.accounts}
        for a in ph.accounts:
            if (a.source, a.kind, a.name, a.domain, a.rid) not in aseen:
                host.accounts.append(a)
        hs = {s.id for s in host.host_scripts}
        host.host_scripts.extend(s for s in ph.host_scripts if s.id not in hs)
        for np_ in ph.ports:
            op = port_index.get((np_.protocol, np_.portid))
            if op:
                seen = {s.id for s in op.scripts}
                op.scripts.extend(s for s in np_.scripts if s.id not in seen)
                op.product = op.product or np_.product
                op.version = op.version or np_.version




def _vuln_worker(host, portids, profile, paths, creds, aggressive, use_ss,
                 use_probes=True, fast=False):
    """Returns (host, issues)."""
    ip = host.ip
    issues: list[dict] = []
    if portids:
        vx = os.path.join(paths["raw"], f"{ip}_vuln.xml")
        # Skip the ~90 deep service-enum scripts here when the enum phase already ran them
        # on this host (their output is present) - coverage-safe, ~half the vuln NSE work.
        _, iss = scanner.vuln_scan(ip, portids, vx, profile, creds=creds,
                                   aggressive=aggressive, fast=fast,
                                   skip_enum_scripts=scanner.enum_scripts_present(host))
        if iss:
            issues.append(_mkissue(iss, "vuln-scan"))
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
    if profile.udp_top:
        ux = os.path.join(paths["raw"], f"{ip}_udp.xml")
        _, iss = scanner.udp_scan(ip, ux, profile)
        if iss:
            issues.append(_mkissue(iss, "udp"))
        _merge_vuln_results(host, np.parse_nmap_xml(ux))
    pset = set(portids)
    for p in host.ports:
        if p.portid in pset:
            p.vuln_scanned = True
    ad.identify_roles(host)
    ad.parse_signing_and_ntlm(host)
    # Deep web enum runs BEFORE the CVE mapping so a product/version recovered from
    # a web fingerprint (Jenkins/Confluence/…) gets version->CVE matched too.
    if use_probes:
        from .. import web
        web.scan_host(host, active=True)   # headers/TLS + exposures + fingerprint
    from .. import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings
    if use_ss:
        exploits.enrich_hosts([host])
    return host, issues




def _selected_hosts(hosts, args):
    """Filter stored hosts by IP / range / CIDR selection (targets/--host/--subnet)."""
    tokens = ((getattr(args, "targets", None) or [])
              + (getattr(args, "host", None) or [])
              + (getattr(args, "subnet", None) or []))
    match = ip_matcher(tokens)
    return [h for h in hosts if match(h.ip)]




def _vuln_targets(hosts, args):
    """Return [(host, [portids])] after target selection + --only/--unscanned."""
    only = [o.lower() for o in (getattr(args, "only", None) or [])]
    out = []
    for h in _selected_hosts(hosts, args):
        ports = h.open_ports
        if getattr(args, "unscanned", False):
            ports = [p for p in ports if not p.vuln_scanned]
        if only:
            ports = [p for p in ports
                     if any(k in (p.service or "").lower() or k == str(p.portid)
                            for k in only)]
        if ports:
            out.append((h, [p.portid for p in ports]))
    return out




def _phase_vulns(store, paths, args, profile) -> None:
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    fast = getattr(args, "fast", False) and not aggressive
    use_ss = not getattr(args, "no_searchsploit", False) and exploits.available()
    use_probes = not getattr(args, "no_probes", False)
    if not getattr(args, "no_searchsploit", False) and not exploits.available():
        print("[!] searchsploit not found; skipping exploit mapping "
              "(apt install exploitdb).")
    if profile.offline:
        print("[*] Offline: vulners disabled; using local vuln scripts + searchsploit.")
    if aggressive:
        mode = "AGGRESSIVE (intrusive vuln category)"
    elif fast:
        mode = "FAST (top-signal detection scripts only)"
    else:
        mode = "safe (vuln+safe detection only)"
    print(f"[*] Vuln-scan mode: {mode}"
          f"{' + searchsploit' if use_ss else ''}"
          f"{' + web scan (headers/TLS + exposures)' if use_probes else ''}.")

    targets = _vuln_targets(store.all_hosts(), args)
    if not targets:
        print("[!] No open ports match the vuln-scan filters.")
        return
    workers = max(1, args.workers)
    total_ports = sum(len(p) for _, p in targets)
    total = len(targets)
    print(f"[*] Vuln-scanning {total} host(s) / {total_ports} port(s) "
          f"with {workers} worker(s) ...")
    completed = 0
    errs: list[tuple[str, str]] = []   # (ip, message) for a loud end-of-phase summary
    start = time.monotonic()
    refresher = _Refresher(args)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_vuln_worker, h, ports, profile, paths, creds,
                             aggressive, use_ss, use_probes, fast): h.ip
                   for h, ports in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "vuln-scan", "level": "error",
                                 "message": f"vuln-scan crashed: {e}"}])
                completed += 1
                errs.append((ip, f"crashed: {e}"))
                print(f"    [{completed}/{total}] {ip}: FAILED (crashed)"
                      f"{_progress(completed, total, start)}")
                continue
            _record_issues(store, paths, ip, issues)
            errs.extend((ip, i["message"]) for i in issues
                        if i.get("level") == "error")
            if not _persist_host(store, paths, ip, "vuln-scan", host, clear_step="vuln"):
                completed += 1
                continue
            completed += 1
            bits = []
            if host.vulns:
                bits.append(f"{len(host.vulns)} finding(s)")
            if host.exploits:
                bits.append(f"{len(host.exploits)} exploit(s)")
            b = f" [{', '.join(bits)}]" if bits else ""
            print(f"    [{completed}/{total}] {ip}: vuln-scanned{b}"
                  f"{_progress(completed, total, start)}")
            refresher.tick(store, paths, args.title)
    _summarize_failures("vuln-scan", errs, total)




# --- phase: database enumeration / vuln scan ------------------------------------

def _db_worker(host, portids, profile, paths, creds, aggressive, use_ss):
    """Returns (host, issues)."""
    from .. import db as dbmod
    issues: list[dict] = []
    vx = os.path.join(paths["raw"], f"{host.ip}_db.xml")
    _, iss = scanner.nse_scan(host.ip, portids, vx, profile,
                              dbmod.script_selection(aggressive), creds=creds)
    if iss:
        issues.append(_mkissue(iss, "db"))
    _merge_vuln_results(host, np.parse_nmap_xml(vx))
    pset = set(portids)
    for p in host.ports:
        if p.portid in pset:
            p.vuln_scanned = True
    host.db_scanned = True
    if use_ss:
        exploits.enrich_hosts([host])
    return host, issues




def _phase_db(store, paths, args, profile) -> None:
    from .. import db as dbmod
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    use_ss = not getattr(args, "no_searchsploit", False) and exploits.available()
    targets = [(h, [p.portid for p in dbmod.db_ports(h)])
               for h in _selected_hosts(store.all_hosts(), args)]
    targets = [(h, ports) for h, ports in targets if ports]
    if not targets:
        print("[!] No database services found in scope.")
        return
    mode = "AGGRESSIVE (brute/xp_cmdshell)" if aggressive else "safe (info + empty-pw)"
    print(f"[*] DB-scanning {len(targets)} host(s) [{mode}] ...")
    refresher = _Refresher(args)
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_db_worker, h, ports, profile, paths, creds,
                             aggressive, use_ss): h.ip for h, ports in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "db", "level": "error",
                                 "message": f"db-scan crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            if not _persist_host(store, paths, ip, "db", host, clear_step="db"):
                continue
            completed += 1
            print(f"    [{completed}/{len(targets)}] {ip}: db-scanned")
            refresher.tick(store, paths, args.title)




# --- phase: privilege-escalation --------------------------------------------------

def _privesc_worker(host, profile, paths, creds, aggressive):
    """Returns (host, issues)."""
    from .. import privesc as pe
    issues: list[dict] = []
    ports = [p.portid for p in host.open_ports
             if p.portid in (139, 445, 3389, 135) or "http" in (p.service or "")]
    if ports:
        vx = os.path.join(paths["raw"], f"{host.ip}_privesc.xml")
        _, iss = scanner.nse_scan(host.ip, ports, vx, profile,
                                  pe.nse_scripts(aggressive), creds=creds)
        if iss:
            issues.append(_mkissue(iss, "privesc"))
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
        ad.identify_roles(host)
        ad.parse_signing_and_ntlm(host)
    host.privesc_checked = True          # the phase considered this host (mirrors _db_worker)
    return host, issues




def _phase_privesc(store, paths, args, profile) -> None:
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    targets = _selected_hosts(store.all_hosts(), args)
    if not targets:
        print("[!] No hosts in scope.")
        return
    print(f"[*] Priv-esc checks on {len(targets)} host(s) "
          f"[{'aggressive' if aggressive else 'safe'} NSE] ...")
    refresher = _Refresher(args)
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_privesc_worker, h, profile, paths, creds,
                             aggressive): h.ip for h in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "privesc", "level": "error",
                                 "message": f"privesc crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            # clear_step clears any stale manual privesc override as part of the single
            # persist (host.privesc_checked was set in the worker) - no second pass.
            if not _persist_host(store, paths, ip, "privesc", host, clear_step="privesc"):
                continue
            completed += 1
            refresher.tick(store, paths, args.title)




# --- phase: credentialed enumeration (netexec / impacket / ssh) ------------------

def _ssh_creds_of(args) -> dict | None:
    user = getattr(args, "ssh_user", None)
    if not user:
        return None
    return {"username": user, "password": getattr(args, "ssh_pass", None),
            "key": getattr(args, "ssh_key", None)}




def _credenum_worker(host, creds, ssh_creds, aggressive, admin_creds=None):
    """Returns (host, issues, auth)."""
    from .. import credenum
    issues, auth = credenum.enrich_host(host, creds, ssh_creds, aggressive=aggressive,
                                        admin_creds=admin_creds)
    return host, issues, auth




def _auth_cell(st: dict | None) -> str:
    """Format one account's per-host auth outcome for the summary table. A cell
    is only recorded when the tool actually ran, so an unrecorded/absent cell
    shows '-' (never FAIL) - a missing tool is not an auth failure."""
    if not st or not st.get("tried"):
        return "-"
    if st.get("error"):
        return "ERR"          # tool ran but errored (unreachable/timeout)
    if not st.get("auth"):
        return "FAIL"         # credentials rejected
    return "OK (admin)" if st.get("admin") else "OK"




def _print_auth_table(auth_rows: list) -> None:
    """Per-host authentication success/fail table. Only shows the columns that
    were actually attempted; flags rejected credentials loudly at the end."""
    if not auth_rows:
        return
    cols = [("user", "USER ACCT"), ("admin", "PRIV ACCT"), ("ssh", "SSH")]
    used = [(k, hd) for k, hd in cols if any(a.get(k) for _, a in auth_rows)]
    if not used:
        return
    print("\n[*] Authentication summary (per host):")
    header = f"      {'HOST':<16}" + "".join(f"{hd:<13}" for _, hd in used)
    print(header)
    print("      " + "-" * (len(header) - 6))
    fails = errs = 0
    for ip, a in sorted(auth_rows, key=lambda r: _ip_key(r[0])):
        cells = ""
        for k, _ in used:
            val = _auth_cell(a.get(k))
            fails += val == "FAIL"
            errs += val == "ERR"
            cells += f"{val:<13}"
        print(f"      {ip:<16}{cells}")
    if fails:
        print(f"[!] {fails} credential(s) were REJECTED (FAIL) - check the "
              "username/password/domain for those rows.")
    if errs:
        print(f"[!] {errs} attempt(s) ERRORED (ERR) - host unreachable, timed "
              "out, or the tool failed; not necessarily a credential problem.")




def _phase_credenum(store, paths, args) -> None:
    from .. import credenum
    creds = _creds_of(args)
    admin_creds = _admin_creds_of(args)
    ssh_creds = _ssh_creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    want_set = (getattr(args, "all_creds", False) or getattr(args, "user_list", None)
                or getattr(args, "pass_list", None))
    if not creds and not ssh_creds and not admin_creds and not want_set:
        print("\n" + "!" * 64)
        print("[x] credenum needs credentials but none were given.")
        print("    Provide --username/--password (+--domain) for SMB/AD, --ssh-user for "
              "Linux hosts, or --all-creds/--user-list/--pass-list to spray a set.")
        print("!" * 64)
        return
    tools = credenum.available_tools()
    have = [k for k, v in tools.items() if v]
    print(f"[*] Credentialed enum tools present: {', '.join(have) or 'NONE'}.")
    if not have:
        print("\n" + "!" * 64)
        print("[x] No credentialed-enum tools found (netexec/impacket/ssh).")
        print("    Install netexec + impacket, or ensure ssh is on PATH, then re-run.")
        print("!" * 64)
        return
    # SMB/AD creds given but no SMB tool -> the SMB/AD half silently does nothing.
    # Say so explicitly (consistent with cmd_smb/cmd_mssql) rather than finishing
    # with a success message and zero accounts.
    if (creds or admin_creds) and not tools.get("netexec"):
        print("[!] netexec/impacket not installed - SMB/AD credentialed enum "
              "(accounts, shares, secretsdump) will be SKIPPED. Install netexec + "
              "impacket for the full credentialed pass; only the tools listed above run.")
    targets = _selected_hosts(store.all_hosts(), args)
    if not targets:
        print("[!] No hosts in scope.")
        return
    # --all-creds / --user-list / --pass-list: spray the credential SET first (lockout-
    # safe) to find the working cred PER HOST, then enum each host with its own cred.
    per_host_creds: dict[str, dict] = {}
    if want_set:
        from .. import credentials as cr
        from ..models import Credential
        stacked = cr.stack(targets, store.all_credentials()) if getattr(args, "all_creds", False) else []
        cred_set = _spray_cred_set(args, stacked)
        if cred_set:
            safe = not getattr(args, "spray", False)
            print(f"[*] Discovering working creds: spraying {len(cred_set)} credential(s) "
                  f"{'(lockout-safe)' if safe else '(FULL user x pass)'} across "
                  f"{len(targets)} host(s) ...")
            res = cr.run_spray(targets, cred_set, args.output_dir, safe=safe)
            if not res.get("ok"):
                print(f"[!] spray: {res.get('error')}")
            for h in res.get("hits", []):
                if h["ip"] not in per_host_creds:
                    u, dom = _split_userdomain(h["user"], None)
                    per_host_creds[h["ip"]] = {"username": u, "password": h["secret"], "domain": dom}
                    store.add_credential(Credential(
                        username=u, secret=h["secret"], kind="password", domain=dom,
                        source="spray-validated", origin_ip=h["ip"],
                        notes=f"validated over {h['proto']}" + (" (local admin)" if h["admin"] else "")))
            print(f"[+] {len(per_host_creds)} host(s) have a working credential"
                  + (" - enumerating with it." if per_host_creds else "; nothing to enum credentialed."))
    accts = []
    if creds:
        accts.append(f"user '{creds['username']}'")
    if admin_creds:
        accts.append(f"privileged '{admin_creds['username']}' (admin checks + secretsdump)")
    mode = (" with " + " + ".join(accts)) if accts else ""
    if aggressive and not admin_creds:
        mode += " + secretsdump (aggressive)"
    total = len(targets)
    print(f"[*] Credentialed enum on {total} host(s){mode} ...")
    refresher = _Refresher(args)
    completed = 0
    start = time.monotonic()
    errs: list[tuple[str, str]] = []
    auth_rows: list[tuple[str, dict]] = []   # (ip, auth) for the success/fail table
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_credenum_worker, h, per_host_creds.get(h.ip, creds),
                             ssh_creds, aggressive, admin_creds): h.ip
                   for h in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues, auth = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "credenum", "level": "error",
                                 "message": f"credenum crashed: {e}"}])
                completed += 1
                errs.append((ip, f"crashed: {e}"))
                print(f"    [{completed}/{total}] {ip}: FAILED (crashed)"
                      f"{_progress(completed, total, start)}")
                continue
            _record_issues(store, paths, ip, issues)
            errs.extend((ip, i["message"]) for i in issues
                        if i.get("level") == "error")
            if auth:
                auth_rows.append((ip, auth))
            if not _persist_host(store, paths, ip, "credenum", host):
                completed += 1
                continue
            completed += 1
            n_acct = sum(1 for a in host.accounts
                         if a.source in ("netexec", "impacket", "secretsdump"))
            print(f"    [{completed}/{total}] {ip}: cred-enum done"
                  + (f" ({n_acct} account/loot rows)" if n_acct else "")
                  + _progress(completed, total, start))
            refresher.tick(store, paths, args.title)
    _print_auth_table(auth_rows)
    _summarize_failures("credenum", errs, total)




def _setup_scan(args):
    """Shared setup: profile, env check, store. Returns (profile, paths, store)."""
    # deepcopy: PROFILES holds shared module-level singletons; overriding a live one
    # would leak flags (--all-ports, --min-rate, a downgraded scanner) into later runs
    # in the same process (tests, library reuse).
    profile = copy.deepcopy(scanner.PROFILES[args.profile])
    _apply_profile_overrides(profile, args)
    rules = getattr(args, "rules", None)
    if rules:
        from .. import vulndb
        n = vulndb.load_rules(rules)
        print(f"[+] Loaded {n} extra detection rule(s) from {rules}."
              if n else f"[!] No usable detection rules found in {rules}.")
    try:
        for w in scanner.check_environment(profile):
            print(f"[!] {w}")
    except scanner.ScannerError as e:
        print(f"[x] {e}")
        return None, None, None
    try:
        paths = _open_paths(args.output_dir)
    except OSError as e:
        print(f"[x] Cannot use output dir '{args.output_dir}': {e}")
        return None, None, None
    try:
        store = Store(paths["db"])
    except StoreError as e:
        print(f"[x] {e}")
        return None, None, None
    _import_excel_tracking(store, paths)
    return profile, paths, store




def _print_next(paths: dict, output_dir: str, n: int = 1) -> None:
    """Echo the top next-best-action(s) for this engagement (ambient guidance). Opens a
    short-lived read of the datastore, so it works after the main scan store is closed.
    Silent on any error - guidance must never break a command."""
    from .. import workflow
    try:
        s = Store(paths["db"])
    except Exception:  # noqa: BLE001
        return
    try:
        acts = workflow.next_actions(s.all_hosts(), s.all_credentials(), output_dir)
        for line in workflow.format_next(acts, top=n):
            print(f"    {line}")
    except Exception:  # noqa: BLE001
        pass
    finally:
        s.close()




def _recovery_hint(output_dir: str) -> None:
    """After an interruption or failure, tell the tester exactly how to pick up. recce
    phases are idempotent (finished hosts are skipped), so recovery is always one command -
    and `recce next` computes what's actually left. Recovery must never dead-end."""
    print(f"    ↻ Pick up:  re-run the command (add --resume to skip finished hosts), "
          f"or `recce next -o {output_dir}` to see what's left.")




def _sweep_defaults(args: argparse.Namespace) -> None:
    """Fill in every attribute the deep-module handlers read that the `sweep` parser
    doesn't define, so each runs its credential-free path without an AttributeError.
    Anything the user *did* pass (creds, --no-probe) is left untouched."""
    defaults = {
        "no_probe": False, "no_run": True, "prove_write": False, "no_active": False,
        "cookie": None, "header": None, "creds": False, "crawl": False,
        "sqli_time": False, "username": None, "password": None, "domain": None,
        "dc_ip": None, "local_auth": False, "lhost": "<LHOST>", "data": False,
        "exec_cmd": None, "method": None, "link_depth": 1, "no_links": False,
        "perms": False, "relay": None,
    }
    for k, v in defaults.items():
        if not hasattr(args, k):
            setattr(args, k, v)


_UNAUTH_SWEEP = [
    ("web", "cmd_web"), ("api", "cmd_api"), ("smb", "cmd_smb"), ("ftp", "cmd_ftp"), ("ldap", "cmd_ldap"),
    ("snmp", "cmd_snmp"), ("mongodb", "cmd_mongodb"), ("redis", "cmd_redis"),
    ("elasticsearch", "cmd_elasticsearch"), ("rsync", "cmd_rsync"),
    ("nfs", "cmd_nfs"), ("kerberos", "cmd_kerberos"), ("docker", "cmd_docker"),
    ("kubernetes", "cmd_kubernetes"), ("mssql", "cmd_mssql"),
    ("mysql", "cmd_mysql"), ("postgres", "cmd_postgres"),
    ("memcached", "cmd_memcached"), ("couchdb", "cmd_couchdb"),
    ("influxdb", "cmd_influxdb"), ("cassandra", "cmd_cassandra"),
    ("oracle", "cmd_oracle"), ("db2", "cmd_db2"),
    ("smtp", "cmd_smtp"), ("dns", "cmd_dns"),
]


_AUTH_SWEEP = [
    ("credenum", "cmd_credenum"), ("ldap", "cmd_ldap"), ("smb", "cmd_smb"),
    ("mssql", "cmd_mssql"), ("ftp", "cmd_ftp"),
]




def _run_sweep(args: argparse.Namespace, *, authenticated: bool) -> int:
    """Shared engine for `sweep` (unauth) and `credsweep` (auth). Runs each applicable
    module with the workbook rebuild deferred to a single pass at the end; a module
    that errors is isolated so one failure doesn't abort the rest."""
    global _DEFER_REPORTS
    print(BANNER)
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    _sweep_defaults(args)

    if authenticated:
        if not getattr(args, "username", None):
            print("[x] credsweep is the authenticated pass and needs credentials: "
                  "-u USER -p PASS [-d DOMAIN]. For the credential-free modules, "
                  "run `recce sweep`.")
            return 1
        # The whole point of credsweep is to run the authenticated tooling, so the
        # nxc/impacket matrix must actually execute (handlers gate it on `not no_run`).
        args.no_run = False
        table, kind, tag = _AUTH_SWEEP, "credentialed", "CREDSWEEP"
    else:
        # `sweep` is strictly unauthenticated: drop any creds so a stray -u can't fire
        # a credentialed action as an invisible side-effect of this command.
        if getattr(args, "username", None):
            print("[!] `sweep` is the unauthenticated pass - ignoring the credentials "
                  "you passed. Run `recce credsweep -u ... -p ...` for the "
                  "authenticated modules.")
            args.username = args.password = None
            args.ldap_enum = args.ldap_anon = False
        table, kind, tag = _UNAUTH_SWEEP, "credential-free", "SWEEP"

    modules = [(n, globals()[fn]) for n, fn in table]
    skip = {s.strip().lower() for s in (getattr(args, "skip", None) or [])}
    only = {s.strip().lower() for s in (getattr(args, "only_modules", None) or [])}
    if only:
        modules = [(n, h) for n, h in modules if n in only]
    if skip:
        modules = [(n, h) for n, h in modules if n not in skip]

    # The NSE vuln scan is an unauthenticated concept - only offered on `sweep`.
    run_vulns = getattr(args, "vulns", False) and not authenticated
    ran, failed = [], []
    _DEFER_REPORTS = True
    try:
        if run_vulns:
            print("\n" + "=" * 64 + "\n[SWEEP] vulns (nmap NSE)\n" + "=" * 64)
            try:
                cmd_vulns(args)
                ran.append("vulns")
            except Exception as e:  # noqa: BLE001 - one module must not abort the sweep
                failed.append(("vulns", e))
                print(f"[!] vulns failed: {type(e).__name__}: {e}")
        for name, handler in modules:
            print("\n" + "=" * 64 + f"\n[{tag}] {name}\n" + "=" * 64)
            try:
                handler(args)
                ran.append(name)
            except Exception as e:  # noqa: BLE001
                failed.append((name, e))
                print(f"[!] {name} failed: {type(e).__name__}: {e}")
    finally:
        _DEFER_REPORTS = False

    # Single, authoritative report rebuild from everything the modules folded in.
    store = _open_store(paths["db"])
    if store is not None:
        _import_excel_tracking(store, paths)
        title = store.get_meta("engagement") or args.title
        _generate_reports(store, paths, title)
        store.close()

    print("\n" + "=" * 64)
    print(f"[+] {kind.capitalize()} sweep complete: ran {len(ran)} module(s) "
          f"({', '.join(ran) or 'none'}).")
    if failed:
        print(f"[!] {len(failed)} module(s) errored: "
              f"{', '.join(n for n, _ in failed)} - re-run individually to debug.")
    nxt = ("`recce credsweep -u ... -p ...` (once you have creds), then `recce prove`"
           if not authenticated else "`recce prove` then `recce attackpath`")
    print(f"    Reports rebuilt. Next: {nxt}.")
    return 1 if failed else 0




def _match_one_host(hosts, selector):
    """Best-effort: the host(s) an IP/IP:port selector points at (for screenshots)."""
    sel = (selector or "").split(":")[0].strip()
    return [h for h in hosts if h.ip == sel] if sel else []




def _web_screenshots(targets, output_dir) -> None:
    """Headless-browser screenshot per web endpoint -> engagement/screenshots/."""
    from .. import screenshot, web
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
    from .. import proofs
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
    from ..models import Credential
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




def _spray_cred_set(args, stacked):
    """The credential set to spray: the stacked/looted creds (default) plus any
    --user-list usernames and --pass-list passwords. Returns Credential objects; a
    spray combines all usernames x all passwords (paired when lockout-safe)."""
    from ..models import Credential
    creds = list(stacked)
    for path, make in ((getattr(args, "user_list", None), lambda v: Credential(username=v)),
                       (getattr(args, "pass_list", None),
                        lambda v: Credential(secret=v, kind="password"))):
        if not path:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                creds.extend(make(v) for v in (ln.strip() for ln in fh) if v)
        except OSError as e:
            print(f"[!] could not read {path}: {e}")
    return creds




def _self_scan() -> bool:
    import tempfile
    try:
        from .. import scanner
        profile = scanner.PROFILES["quick"]
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "p.xml")
            scanner.full_port_scan("127.0.0.1", fp, profile)
            ports = _ports_for_host(fp, "127.0.0.1")
            deep = os.path.join(d, "e.xml")
            scanner.enum_scan("127.0.0.1", ports or [80], deep, profile)  # (xml, issue)
            host = _fold_host("127.0.0.1", np.parse_nmap_xml(deep), {"127.0.0.1": "local"})
            host.enumerated = True
            from ..report_excel import build_workbook, read_workbook_tracking
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




def _ip_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)




def _fold_host(ip, parsed_list, subnet_map):
    base = Host(ip=ip, subnet=subnet_map.get(ip, ""))
    for h in parsed_list:
        if h.ip != ip:
            continue
        base.hostnames = list(dict.fromkeys(base.hostnames + h.hostnames))
        base.mac = base.mac or h.mac
        base.vendor = base.vendor or h.vendor
        if h.os_accuracy >= base.os_accuracy and h.os_name:
            base.os_name, base.os_accuracy, base.os_family = h.os_name, h.os_accuracy, h.os_family
        base.distance = base.distance or h.distance
        # Carry proof-of-life: an imported .gnmap/.nmap host with no open ports and no
        # hostname is kept up only by its up_reason ("report-listed"); dropping it here
        # would make is_up wrongly read False and hide the host the report enumerated.
        base.up_reason = base.up_reason or h.up_reason
        base.state = h.state or base.state
        base.last_scanned = h.last_scanned or base.last_scanned
        base.ports.extend(h.ports)
        base.vulns.extend(h.vulns)
        base.accounts.extend(h.accounts)
        base.exploits.extend(h.exploits)
        base.host_scripts.extend(h.host_scripts)
    base.subnet = subnet_map.get(ip, base.subnet)
    return base




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
    from .. import ingest
    from ..models import Host, Port
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
    from .. import ingest
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
    from .. import deploy
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
    from .. import screenshot
    if not screenshot.available():
        return None
    mod = import_module(f"recce.{module}")
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
    from .. import proxy
    if udp and proxy.is_active():
        # A UDP-only service can't be reached through a TCP proxy, and a datagram would
        # leak from the operator's real IP. Say so loudly instead of returning a clean,
        # misleading "0 findings" (north star: never a silent false negative).
        print(f"[!] {label} is UDP-only and can't traverse the proxy ({proxy.describe()}) "
              f"- skipped. Run it from the pivot host directly, or without --proxy.")
        return 0
    mod = import_module(f"recce.{module}")
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
    """budget + progress kwargs for a deep module's analyze()."""
    return {"budget": getattr(args, "budget", None),
            "progress": _probe_progress(label)}




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
    from .. import (mssql, smb, ftp, docker, kubernetes as k8s, ldap as _ldap,
                   snmp as _snmp, mongodb as _mongo, redis as _redis,
                   elasticsearch as _es, rsync as _rsync, nfs as _nfs,
                   kerberos as _krb)
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
    from ..models import Credential
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
    from .. import bloodhound as bh
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
class _Refresher:
    """Throttled interim report refresh: regenerate after every N hosts OR at
    least every `interval` seconds, whichever comes first. Results are already
    persisted to SQLite per host, so this only controls how often the *sheet* is
    rebuilt - findings are durable even if a refresh is skipped or the run dies.
    """

    def __init__(self, args, interval: float = 20.0):
        self.every = getattr(args, "refresh_every", 0) or 0
        self.interval = interval
        self.count = 0
        self.last = time.monotonic()

    def tick(self, store, paths, title) -> None:
        self.count += 1
        now = time.monotonic()
        due = (self.every and self.count % self.every == 0) or \
              (now - self.last >= self.interval)
        if not due:
            return
        if _safe_refresh(store, paths, title):
            self.last = now
            print(f"    ~ report refreshed ({self.count} host(s) so far).")
        else:
            print("    ~ report open/locked - kept your edits, will retry.")

