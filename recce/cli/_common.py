"""Common CLI helpers: filesystem, engagement layout, report generation.

Extracted from helpers.py. These are utility helpers — filesystem, engagement layout, report
generation, port folding, host persistence, permission fixups — used
by many command handlers and by webui/routes callers via re-export
from `recce.cli`.

Nothing in this module should reference a `cmd_*` function; the flow
of dependencies is one-way: cmd_ -> helpers, never the other direction.
"""

from __future__ import annotations

import json
import os
import time

from .. import ad
from ..core import parser as np
from ..core import tracking as tr
from ..core.models import Host
from ..report.excel import read_workbook_edits, update_workbook
from ..report.markdown import build_csv, build_markdown
from ..core.store import Store, StoreError




__all__ = ['_fmt_dur', '_progress', '_summarize_failures', '_ports_for_host', '_swept_ports_for_host', '_union_swept', '_fold_swept_ports', '_disproved_ports_in_xml', '_open_store', '_sudo_owner', '_reown', '_relax_perms', '_open_paths', '_now', '_record_issues', '_persist_host', '_resolve_domains', '_reconcile_steps', '_import_excel_tracking', '_safe_refresh', '_generate_reports', 'BANNER', '_SEV_ORDER', '_RETRY_HOST_TIMEOUT_CAP_MIN', '_DEFER_REPORTS', '_Refresher', '_ip_key', '_fold_host', '_spray_cred_set']


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
    from ..core.parser import _declares_entities
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
    from ..core import qod
    from ..intake import dedup
    from ..vuln import verify, kev, epss
    # Apply the tester's include filter first so downstream annotation and
    # dedup passes only touch what will actually appear in the report.
    # include_keys uses the same canonical vuln_row_key the frontend and
    # tracking table use ("vuln:ip:port:script_id:title[:60]"), so the two
    # views stay in sync.
    if include_keys is not None:
        from ..core.tracking import vuln_row_key
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
    from ..core import proxy as _proxy
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
        from ..report.docx import build_combined
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
    from ..report.html import build_html, build_assets_html
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
        from ..report import netmap
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
        from ..act import attackpath as _ap
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


def _spray_cred_set(args, stacked):
    """The credential set to spray: the stacked/looted creds (default) plus any
    --user-list usernames and --pass-list passwords. Returns Credential objects; a
    spray combines all usernames x all passwords (paired when lockout-safe)."""
    from ..core.models import Credential
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

