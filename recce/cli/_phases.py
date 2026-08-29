"""Scan-phase helpers: discovery, enumeration, vulnerability scanning, sweeps.

Extracted from helpers.py. Used primarily by _scan.py.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import ad
from ..vuln import exploits
from ..core import parser as np
from ..core import scanner
from ..core.models import Host
from ..core.store import Store, StoreError
from ..core.targets import expand_excludes, explicit_targets, ip_matcher, load_targets

from . import _common
from ._common import (
    BANNER,
    _RETRY_HOST_TIMEOUT_CAP_MIN,
    _Refresher,
    _disproved_ports_in_xml,
    _fold_host,
    _fold_swept_ports,
    _generate_reports,
    _import_excel_tracking,
    _ip_key,
    _open_paths,
    _open_store,
    _persist_host,
    _ports_for_host,
    _progress,
    _record_issues,
    _spray_cred_set,
    _summarize_failures,
    _swept_ports_for_host,
    _union_swept,
)

__all__ = ['_apply_profile_overrides', '_split_userdomain', '_creds_of', '_db_login_creds', '_web_login_creds', '_admin_creds_of', '_final_report', '_mkissue', '_enum_worker', '_reconfirm_missed', '_seed_targets', '_discover', '_phase_enum', '_merge_vuln_results', '_vuln_worker', '_selected_hosts', '_vuln_targets', '_phase_vulns', '_db_worker', '_phase_db', '_privesc_worker', '_phase_privesc', '_ssh_creds_of', '_credenum_worker', '_auth_cell', '_print_auth_table', '_phase_credenum', '_setup_scan', '_print_next', '_recovery_hint', '_sweep_defaults', '_UNAUTH_SWEEP', '_AUTH_SWEEP', '_run_sweep']

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
        from ..core.models import Port
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
    from ..services import svcdetect
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
    from ..vuln import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings, immediately
    from ..core import qod
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
    from ..core.models import Host
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
        from ..services import web
        web.scan_host(host, active=True)   # headers/TLS + exposures + fingerprint
    from ..vuln import vulndb
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
    from ..services import db as dbmod
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
    from ..services import db as dbmod
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
    from ..act import privesc as pe
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
    from ..creds import credenum
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
    from ..creds import credenum
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
        from ..creds import credentials as cr
        from ..core.models import Credential
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
        from ..vuln import vulndb
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
    from ..act import workflow
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
    # T4 scanner-expansion services:
    ("zookeeper", "cmd_zookeeper"), ("kafka", "cmd_kafka"),
    ("etcd", "cmd_etcd"), ("consul", "cmd_consul"), ("nomad", "cmd_nomad"),
    ("prometheus", "cmd_prometheus"),
    ("docker-registry", "cmd_docker_registry"),
    ("vnc", "cmd_vnc"), ("modbus", "cmd_modbus"),
    ("rdp", "cmd_rdp"), ("ipmi", "cmd_ipmi"), ("ntp", "cmd_ntp"),
    # Post-sweep: mine whatever landed under evidence/ during the sweep
    # (auto-collected loot from container escapes, credential-exposed
    # configs, .git dumps that path_enum pulled locally, etc.) into
    # first-class findings. Runs last so it sees anything the earlier
    # phases wrote.
    ("loot-scan", "cmd_loot_scan"),
]


_AUTH_SWEEP = [
    ("credenum", "cmd_credenum"), ("ldap", "cmd_ldap"), ("smb", "cmd_smb"),
    ("mssql", "cmd_mssql"), ("ftp", "cmd_ftp"),
]




def _run_sweep(args: argparse.Namespace, *, authenticated: bool) -> int:
    """Shared engine for `sweep` (unauth) and `credsweep` (auth). Runs each applicable
    module with the workbook rebuild deferred to a single pass at the end; a module
    that errors is isolated so one failure doesn't abort the rest."""
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

    # Resolve handler names against the top-level `recce.cli` namespace.
    # `globals()` here is helpers.py's module dict, which does NOT contain
    # the cmd_* functions (they live in cli/_services.py, cli/_meta.py,
    # cli/_db.py, cli/_ad.py — wildcard-re-exported from cli/__init__.py).
    # This lookup path was latently broken: `globals()[fn]` would KeyError
    # for every entry in _UNAUTH_SWEEP / _AUTH_SWEEP.
    import sys as _sys
    _cli_ns = _sys.modules["recce.cli"]
    modules = [(n, getattr(_cli_ns, fn)) for n, fn in table if hasattr(_cli_ns, fn)]
    skip = {s.strip().lower() for s in (getattr(args, "skip", None) or [])}
    only = {s.strip().lower() for s in (getattr(args, "only_modules", None) or [])}
    if only:
        modules = [(n, h) for n, h in modules if n in only]
    if skip:
        modules = [(n, h) for n, h in modules if n not in skip]

    # The NSE vuln scan is an unauthenticated concept - only offered on `sweep`.
    run_vulns = getattr(args, "vulns", False) and not authenticated
    ran, failed = [], []
    _common._DEFER_REPORTS = True
    try:
        if run_vulns:
            print("\n" + "=" * 64 + "\n[SWEEP] vulns (nmap NSE)\n" + "=" * 64)
            try:
                # Late lookup for the same reason as the module table above:
                # _scan does `from .helpers import *`, and helpers pulls in
                # _phases, so a top-level `from ._scan import cmd_vulns` here
                # is circular. Bare `cmd_vulns(args)` was a NameError that the
                # broad except below swallowed into "vulns failed".
                _cli_ns.cmd_vulns(args)
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
        _common._DEFER_REPORTS = False

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




