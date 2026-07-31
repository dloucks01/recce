"""Markdown + CSV reporting for quick review / grepping / VCS diffing."""

from __future__ import annotations

import csv
from collections import defaultdict

from . import ad
from .models import Domain, Host


def _ip_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)


def build_markdown(hosts: list[Host], out_path: str, title: str = "Enumeration Report",
                   domains: list[Domain] | None = None) -> str:
    lines: list[str] = [f"# {title}", ""]
    total_open = sum(len(h.open_ports) for h in hosts)
    total_vulns = sum(len(h.vulns) for h in hosts)
    # Report only hosts we can prove are up; count the rest separately so a scanned-
    # but-silent IP is never quietly counted as live nor written off as down.
    up = sum(1 for h in hosts if h.is_up)
    unconfirmed = len(hosts) - up
    lines += [
        "## Summary", "",
        f"- **Hosts confirmed up:** {up}",
        f"- **Open service ports:** {total_open}",
        f"- **Vuln findings:** {total_vulns}",
        f"- **Subnets:** {len({h.subnet for h in hosts if h.subnet})}",
    ]
    if unconfirmed:
        lines.append(f"- **Scanned, not confirmed up:** {unconfirmed} "
                     "(no open port or reply - treat as UNKNOWN, not down)")
    lines.append("")

    # Active Directory section.
    domains = domains or ad.derive_domains(hosts)
    dcs = ad.domain_controllers(hosts)
    relay = ad.relay_targets(hosts)
    kerb = ad.kerberoastable(hosts)
    asrep = ad.asrep_roastable(hosts)
    if domains or dcs:
        lines += ["## Active Directory", ""]
        for dom in domains:
            lines.append(f"- **Domain `{dom.name}`** (NetBIOS {dom.netbios or '?'}) - "
                         f"DCs: {', '.join(dom.dc_ips) or 'n/a'}"
                         + (f"; functional level {dom.functional_level}" if dom.functional_level else ""))
            if dom.password_policy:
                lines.append("    - Password policy: "
                             + "; ".join(f"{k}={v}" for k, v in dom.password_policy.items()))
            if dom.anonymous_bind:
                lines.append("    - ⚠️ Anonymous LDAP bind allowed")
            for t in dom.trusts:
                lines.append(f"    - Trust: {t.get('name')} ({t.get('direction')})")
        if relay:
            lines.append("- **NTLM relay targets (SMB signing not required):** "
                         + ", ".join(h.ip for h in relay))
        if kerb:
            lines.append("- **Kerberoastable:** "
                         + ", ".join(f"{a.domain}\\{a.name}".strip("\\") for a in kerb))
        if asrep:
            lines.append("- **AS-REP roastable:** "
                         + ", ".join(f"{a.domain}\\{a.name}".strip('\\') for a in asrep))
        lines.append("")

    # Services grouped by product/version.
    groups: dict[str, list[str]] = defaultdict(list)
    for h in hosts:
        for p in h.open_ports:
            groups[p.product_version_key].append(f"{h.ip}:{p.portid}")
    lines += ["## Services by product / version", ""]
    for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
        product, _, version = key.partition("|")
        label = f"{product} {version}".strip()
        lines.append(f"- **{label}** ({len(groups[key])}): {', '.join(sorted(set(groups[key])))}")
    lines.append("")

    # High/critical vulns first.
    lines += ["## Notable findings", ""]
    findings = [(h, v) for h in hosts for v in h.vulns
                if v.severity in ("critical", "high")]
    if findings:
        for h, v in findings:
            refs = f" [{', '.join(v.ids)}]" if v.ids else ""
            label = v.title or v.script_id
            src = f" _({v.source})_" if v.source and v.source != "nse" else ""
            lines.append(f"- `{h.ip}:{v.port or '-'}` **{v.severity.upper()}** "
                         f"{label}{refs}{src}")
    else:
        lines.append("_No high/critical findings from automated scripts._")
    lines.append("")

    # Per-host checklist.
    lines += ["## Hosts checklist", ""]
    for h in sorted(hosts, key=lambda x: _ip_key(x.ip)):
        name = f" ({h.hostname})" if h.hostname else ""
        os_ = f" - {h.os_guess}" if h.os_guess else ""
        lines.append(f"- [ ] **{h.ip}**{name}{os_}")
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            banner = f" - {p.service_banner}" if p.service_banner else ""
            lines.append(f"    - [ ] {p.portid}/{p.protocol} {p.service}{banner}")

    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return out_path


def build_csv(hosts: list[Host], out_path: str) -> str:
    """Flat services CSV - easy to import anywhere / pivot in any tool."""
    with open(out_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["reviewed", "ip", "hostname", "subnet", "os", "port",
                    "proto", "state", "service", "product", "version",
                    "extrainfo", "cpe"])
        for h in sorted(hosts, key=lambda x: _ip_key(x.ip)):
            if not h.open_ports:
                w.writerow(["FALSE", h.ip, h.hostname, h.subnet, h.os_guess,
                            "", "", "", "", "", "", "", ""])
            for p in sorted(h.open_ports, key=lambda p: p.portid):
                w.writerow(["FALSE", h.ip, h.hostname, h.subnet, h.os_guess,
                            p.portid, p.protocol, p.state, p.service, p.product,
                            p.version, p.extrainfo, ";".join(p.cpe)])
    return out_path
