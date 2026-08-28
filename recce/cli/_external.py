"""CLI handlers for the external-tool bridges (nuclei, certipy).

These shell out to the tool, capture its native output, and fold results
into the shared engagement store — same pattern as an import, but the
tool runs against live targets right now (from recce's perspective, an
active scan).
"""
from __future__ import annotations

import argparse
import os

from ..core.store import Store
from ..services import external as _ext


__all__ = ["cmd_nuclei", "cmd_certipy"]


def _helpers():
    """Late-import shared CLI helpers so this module has no import-time cost
    for anyone not using the external bridges."""
    from . import helpers as _h
    return _h


def cmd_nuclei(args: argparse.Namespace) -> int:
    """Run `nuclei -u <target>` against each target, ingest results."""
    h = _helpers()
    paths = h._open_paths(args.output_dir)
    raw_dir = os.path.join(args.output_dir, "raw")
    targets = args.targets or []
    if not targets:
        # Default: every host in the engagement with a web-ish port open.
        # This means `recce nuclei -o <eng>` after enum "just works".
        with Store(paths["db"]) as st:
            hosts = st.all_hosts()
        targets = []
        for host in hosts:
            for p in host.open_ports:
                svc = (p.service or "").lower()
                if (svc.startswith("http") or p.portid in (80, 443, 8080, 8443, 8000, 8888)):
                    scheme = "https" if p.portid in (443, 8443) or "https" in svc else "http"
                    targets.append(f"{scheme}://{host.ip}:{p.portid}")
        targets = sorted(set(targets))
        if not targets:
            print("[!] no web endpoints found — pass URLs explicitly: recce nuclei https://example.com")
            return 1
        print(f"[*] nuclei scanning {len(targets)} web endpoint(s) from the engagement.")
    total_vulns = 0
    total_hosts = 0
    for target in targets:
        print(f"[*] nuclei → {target}")
        vulns, out_path, err = _ext.run_nuclei(target, raw_dir)
        if err:
            print(f"    ! {err}")
            # Short-circuit hard on "no binary" — retrying more targets won't
            # help. Both wordings appear across error paths (which/OSError).
            if ("not found" in err.lower() or "no such file" in err.lower()
                    or "not installed" in err.lower()):
                return 1
        if vulns:
            with Store(paths["db"]) as st:
                # Fold each vuln onto its host (parse_nuclei sets ip/port).
                by_ip: dict = {}
                for v in vulns:
                    by_ip.setdefault(v.ip, []).append(v)
                for ip, vs in by_ip.items():
                    host = st.get_host(ip)
                    if host is None:
                        from ..core.models import Host
                        host = Host(ip=ip)
                    for v in vs:
                        host.vulns.append(v)
                    st.upsert_host(host, merge=True)
                total_hosts += len(by_ip)
                total_vulns += len(vulns)
            print(f"    + {len(vulns)} finding(s) folded")
    print(f"[+] nuclei complete: {total_vulns} finding(s) across {total_hosts} host(s).")
    # Regenerate reports so the folded findings appear in the deliverables.
    if total_vulns > 0:
        with Store(paths["db"]) as st:
            title = st.get_meta("engagement") or args.title
            h._generate_reports(st, paths, title, quiet=True)
    return 0


def cmd_certipy(args: argparse.Namespace) -> int:
    """Run `certipy find` against a DC and fold the AD-CS findings via the
    existing `ad` import path. Needs -u, -p, -d, --dc-ip."""
    h = _helpers()
    paths = h._open_paths(args.output_dir)
    raw_dir = os.path.join(args.output_dir, "raw")
    print(f"[*] certipy → dc={args.dc_ip} user={args.username}@{args.domain}")
    json_path, err = _ext.run_certipy(
        args.dc_ip, args.username, args.password, args.domain, raw_dir)
    if err:
        print(f"[x] {err}")
        return 1
    print(f"[+] certipy output at {json_path}")
    # Feed through the existing `ad` import pipeline (recce.cli._ad.cmd_ad
    # accepts positional file paths).
    from . import _ad as _ad_mod
    ad_args = argparse.Namespace(**vars(args))
    ad_args.paths = [json_path]
    return _ad_mod.cmd_ad(ad_args)
