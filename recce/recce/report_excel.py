"""Excel workbook generation and update - standard-library only (see xlsx.py).

Airgapped-friendly: no openpyxl. Two entry points:

  build_workbook(...)   - write a fresh workbook.
  update_workbook(...)  - regenerate the workbook while preserving the operator's
                          checkboxes and notes AND the existing row order, with
                          rows for new IPs/services appended at the bottom. This
                          gives an in-place feel (reviewed rows stay put, new
                          systems show up below) without a heavyweight editor.

Every tracked sheet carries a hidden "Key" column (stable per-item id), a
checkbox column and a Notes column. Read-back resolves both inline strings (what
we write) and shared strings (what Excel writes when the operator saves).
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from . import ad
from . import db as dbmod
from . import privesc as pe
from . import tracking as tr
from . import xlsx
from .exploitref import proven_exploit_ref
from .models import Domain, Host

CHECKBOX_HEADERS = {"Reviewed", "Checked", "Triaged", "Done", "Worked"}
CHECKLIST_TITLE = "Checklist"
Tracking = dict  # {key: (reviewed_bool, notes_str)}

# Per-port tri-state work status (Services sheet): a tester marks each open port
# not-started / in-progress / done. Symbol-prefixed so the cell reads at a glance.
STATUS_TODO = "☐ Not started"
STATUS_WIP = "◐ In progress"
STATUS_DONE = "☑ Done"
STATUS_VALUES = [STATUS_TODO, STATUS_WIP, STATUS_DONE]
STATUS_HEADERS = {"Status"}

_SEV_STYLE = {
    "critical": "sev_critical", "high": "sev_high", "medium": "sev_medium",
    "low": "sev_low", "info": "sev_info",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _host_sev_rank(h) -> int:
    """0=critical .. 4=info, 6=no findings - so risky hosts sort to the top."""
    return min((_SEV_RANK.get((v.severity or "").lower(), 5) for v in h.vulns), default=6)


def _host_maxsev(h) -> str:
    return {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}.get(
        _host_sev_rank(h), "")

# Columns holding machine data render in a monospace font (like the HTML
# previews), so IPs, ports, versions, CVEs and IDs line up and read as data.
# ("IP" is handled separately - it also gets the teal accent colour.)
MONO_COLS = {
    "Port", "Proto", "Version", "CVE / refs", "CWE", "Scope", "CPE",
    "Extra info", "RID", "EDB-ID", "CVEs", "Hosts (ip:port)", "Open ports",
    "# Vulns", "# Hosts", "Script", "Path", "SPN", "Command (fill in your values)",
    "Enum command", "Command",
}


@dataclass
class SheetSpec:
    title: str
    cols: list[tuple[str, str, int]]   # (header, role, width); role: checkbox|data|notes|key
    rows: list[dict]                   # {"key": str, "data": {header: value}}
    styler: Callable | None = None     # data_dict -> {header: style_name}
    skip_if_empty: bool = False
    group_by: str | None = None        # row["group"] value to fold rows under collapsible bands
    # (group_value, [row dicts]) -> band label; default = "<group> · <hostname> · N <noun>".
    group_summary: Callable | None = None
    # An optional one-line note written ABOVE the header row (e.g. a colour legend).
    # The header then sits on row 2 and everything downstream accounts for the shift.
    legend: str | None = None


# Tab colours group the sheets into visual bands in Excel's tab bar, by role:
#   guide/summary (grey-blue) · working (blue) · findings (red) · inventory
#   (green) · raw evidence (grey). Titles not listed get no colour.
_TAB_GUIDE, _TAB_WORK = "FF8497B0", "FF0E7C75"
_TAB_FIND, _TAB_INV, _TAB_RAW = "FFC00000", "FF548235", "FF7F7F7F"
TAB_COLORS = {
    "Start Here": _TAB_GUIDE, "Runbook": _TAB_GUIDE, "Overview": _TAB_GUIDE,
    "Checklist": _TAB_WORK, "Services": _TAB_WORK, "Web": _TAB_WORK,
    "Vulnerabilities": _TAB_FIND, "Exploits": _TAB_FIND, "Verification": _TAB_FIND,
    "AD Quick Wins": _TAB_FIND, "Priv-Esc": _TAB_FIND,
    "Priv-Esc Playbook": _TAB_RAW, "Credentials": _TAB_FIND,
    "Exploitation": _TAB_FIND, "Attack Path": _TAB_FIND,
    "Services by Product": _TAB_INV, "Databases": _TAB_INV,
    "Active Directory": _TAB_INV, "Users & Accounts": _TAB_INV,
    "AD Findings": _TAB_FIND, "AD Attack Paths": _TAB_FIND, "MSSQL": _TAB_FIND,
    "SMB": _TAB_FIND, "FTP": _TAB_FIND, "Docker": _TAB_FIND,
    "Kubernetes": _TAB_FIND, "LDAP": _TAB_FIND,
    "SNMP": _TAB_FIND, "MongoDB": _TAB_FIND, "Redis": _TAB_FIND,
    "Elasticsearch": _TAB_FIND, "rsync": _TAB_FIND, "NFS": _TAB_FIND,
    "Kerberos": _TAB_FIND, "Raw NSE": _TAB_RAW,
}


def _ip_sort_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)


def _col_sqref(letter: str, rows: list[int]) -> str:
    """Compress a row list for one column into contiguous ranges:
    [4,5,7,8,9] -> 'A4:A5 A7:A9'. A per-cell list ('A4 A5 A7 A8 A9') is valid but at
    900 hosts x 9 step columns (and ~9000 Services rows), emitted twice (validation +
    conditional format), it bloats the sheet XML and risks Excel's sqref length limit;
    one token per run keeps it tiny. Excel treats the two forms identically."""
    rows = sorted(set(rows))
    if not rows:
        return ""
    parts = []
    start = prev = rows[0]
    for r in rows[1:]:
        if r == prev + 1:
            prev = r
            continue
        parts.append(f"{letter}{start}" if start == prev
                     else f"{letter}{start}:{letter}{prev}")
        start = prev = r
    parts.append(f"{letter}{start}" if start == prev
                 else f"{letter}{start}:{letter}{prev}")
    return " ".join(parts)


# --- stylers (return {header: style_name} for special cells) ---------------------

def _subnet_sort_key(subnet: str):
    subnet = subnet or ""            # a SQL NULL subnet would AttributeError on .split
    try:
        net = subnet.split("/")[0]
        return (0,) + tuple(int(o) for o in net.split("."))
    except ValueError:
        return (1, subnet)


# Per-step column widths on the Checklist (headers come from tr.STEP_COLUMNS).
_STEP_WIDTHS = {"Enumerated": 11, "Vuln-scan": 11, "Web": 7, "AD": 6, "DB": 6,
                "Access": 8, "Priv-esc": 10, "Creds": 8, "Lateral": 8}

# How many leading identity columns to freeze per sheet (in addition to the
# header row), so the host IP stays on-screen while scrolling through the wide
# right-hand columns. 0 (default) freezes only the header row.
_FREEZE_COLS = {"Checklist": 3, "Services": 2, "Vulnerabilities": 3,
                "Verification": 2}
# Any data column at least this wide wraps its text (so long cells read DOWN inside
# their column instead of running off to the right); narrow columns stay single-line.
_WRAP_WIDTH = 34


def _spec_checklist(hosts: list[Host]) -> SheetSpec:
    """One row per IP, folded under a collapsible per-subnet band, with a checkbox
    for each workflow step.

    Each subnet is a collapsible group (click the outline [-] to fold a whole /24 to
    one summary band: "subnet · N hosts · reviewed · high/crit") - so 900 hosts
    become a handful of bands you expand one at a time. Within a subnet, hosts with
    critical/high findings sort to the top, and the # Vulns cell is coloured by the
    worst severity so risk pops out. Auto steps (Enumerated/Vuln-scan/Web/DB) turn
    green when the tool finishes them (Access ticks when credentialed enum confirms
    a foothold, or via `recce access`); manual steps (AD review, Creds, Lateral) are
    operator sign-offs you tick as you go. Steps that don't
    apply to a host show "—" instead of a box (no Web box without a web server,
    no AD box off a DC, no DB box without a database), so a checked box always
    means real work was done. The Reviewed checkbox is your per-host sign-off.
    The long tail of services (SMB, remote access, mail, SNMP...) is tracked
    per-port on the Services tab rather than as columns here.
    """
    step_cols = [(h, "check", _STEP_WIDTHS.get(h, 9)) for h in tr.STEP_COLUMNS]
    # The Subnet column is gone: rows fold under a collapsible per-subnet band that
    # carries the subnet + a rollup, so it isn't repeated on every one of 900 rows.
    cols = [
        ("Reviewed", "checkbox", 9), ("IP", "data", 15),
        ("Hostname", "data", 22), ("OS", "data", 20), ("Hops", "data", 6),
        ("Roles", "data", 22), ("Open ports", "data", 28), ("# Vulns", "data", 8),
        ("AV / EDR", "data", 26),
        *step_cols,
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    # Show only hosts we can PROVE are up. `is_up` is deliberately one-directional:
    # any concrete sign of life (open port, enum/finding, a real nmap discovery reply,
    # DNS/ARP/OS evidence) keeps a host on the list, so a live host is never dropped;
    # only IPs with zero evidence (e.g. -Pn phantoms in a 900-host sweep) fall away.
    up_hosts = [h for h in hosts if h.is_up]
    hidden = len(hosts) - len(up_hosts)
    rows = []
    # Sort by subnet (keeps each subnet's rows contiguous for the band), then by risk
    # so the hosts with critical/high findings float to the top of each subnet, then IP.
    for h in sorted(up_hosts, key=lambda x: (_subnet_sort_key(x.subnet),
                                          _host_sev_rank(x), _ip_sort_key(x.ip))):
        checks = {header: (tr.step_key(step, h.ip), tr.step_auto(h, step),
                           tr.step_applies(h, step))
                  for header, step in tr.STEP_COLUMNS.items()}
        open_ports = ", ".join(str(p.portid) for p in sorted(h.open_ports, key=lambda p: p.portid))
        if getattr(h, "incomplete_scan", False):
            # the sweep was truncated - flag the list as partial so it's never read
            # as authoritative (downstream phases key off these ports)
            open_ports = (open_ports + "  ⚠ PARTIAL (sweep timed out)").strip()
        rows.append({"key": tr.host_key(h.ip), "group": h.subnet or "(no subnet)",
                     "checks": checks, "data": {
            "IP": h.ip, "Hostname": h.hostname, "OS": h.os_guess,
            "Hops": (str(h.distance) if h.distance else ""),
            "Roles": ", ".join(h.roles), "Open ports": open_ports,
            "# Vulns": len(h.vulns), "AV / EDR": "; ".join(h.defenses),
            "_maxsev": _host_maxsev(h)}})
    legend = (
        "Legend:   green step headers = auto-ticked by recce as each phase finishes"
        "  ·  amber step headers = your manual sign-off"
        "  ·  ☑ done   ☐ to do   — = not applicable to this host.        "
        "This tab lists only hosts confirmed UP (an open port or a real reply); "
        "a host is never shown as down unless it is provably down.")
    if hidden:
        legend += (f"   {hidden} scanned IP{'s' if hidden != 1 else ''} with no sign "
                   "of life hidden — see the Overview for the full count.")
    return SheetSpec(CHECKLIST_TITLE, cols, rows, _styler_checklist,
                     group_by="Subnet", group_summary=_checklist_band, legend=legend)


def _checklist_band(subnet: str, grows: list[dict], tracking: Tracking) -> str:
    """The collapsible subnet band label: subnet · N hosts · reviewed · high/crit."""
    n = len(grows)
    reviewed = sum(1 for r in grows if tracking.get(r["key"], (False, ""))[0])
    hc = sum(1 for r in grows if r["data"].get("_maxsev") in ("critical", "high"))
    label = (f"{subnet or '(no subnet)'}      ·   {n} host{'s' if n != 1 else ''}"
             f"   ·   {reviewed}/{n} reviewed")
    if hc:
        label += f"   ·   ⚠ {hc} high/crit"
    return label


def _styler_checklist(d: dict) -> dict:
    out = {}
    if "Domain Controller" in str(d.get("Roles", "")):
        out["Roles"] = "boldred"
    sev = d.get("_maxsev")
    if d.get("# Vulns") and sev in _SEV_STYLE:      # colour the count by worst severity
        out["# Vulns"] = _SEV_STYLE[sev]
    return out


def _styler_vulns(d: dict) -> dict:
    out = {"Details": "wrap"}
    sev = str(d.get("Severity", "")).lower()
    if sev in _SEV_STYLE:
        out["Severity"] = _SEV_STYLE[sev]
    return out


def _styler_quickwins(d: dict) -> dict:
    fills = {
        "Domain Controller": "sev_high", "NTLM relay target": "sev_high",
        "SMBv1 / MS17-010": "sev_critical", "Kerberoastable": "sev_medium",
        "AS-REP roastable": "sev_high", "Delegation": "sev_medium",
        "Privileged account": "sev_low",
    }
    cat = d.get("Category", "")
    return {"Category": fills[cat]} if cat in fills else {}


def _styler_accounts(d: dict) -> dict:
    out = {}
    if d.get("Roastable"):
        out["Roastable"] = "sev_high"
    if d.get("Delegation"):
        out["Delegation"] = "sev_medium"
    return out


# --- tracked-sheet specs --------------------------------------------------------

def _spec_services(hosts: list[Host]) -> SheetSpec:
    """One row per open port, grouped by IP. Each port has its own tri-state work
    Status (not started / in progress / done) and a Notes cell, so a tester can
    track exactly which ports they've looked at, are working, or haven't touched."""
    from . import serviceenum as se
    from . import svcdetect
    # Hostname isn't a column - it rides in the collapsible per-IP band, so it isn't
    # repeated on every port row.
    cols = [
        ("Status", "status", 15), ("IP", "data", 16),
        ("Port", "data", 7), ("Proto", "data", 6),
        ("Service", "data", 16), ("ID source", "data", 10),
        ("Product", "data", 22), ("Version", "data", 16),
        ("Backing binary", "data", 34),
        ("Extra info", "data", 24), ("CPE", "data", 28),
        ("Enum command", "data", 46), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            script = se.script_for(p.service, p.portid)
            if script:
                enum_cmd = f"{se.DRIVER} {script} {h.ip} {p.portid}"
            else:
                # No dedicated script - don't dead-end: hand the tester the exact
                # command to positively identify a still-unknown port.
                enum_cmd = svcdetect.suggest_id_command(h.ip, p)
            # Provenance of the service label: nmap (authoritative), our inferred
            # port-map guess, our banner grab, or a leftover nmap non-answer.
            if p.detect_source:
                source = p.detect_source
            elif p.service and p.service not in ("unknown", "tcpwrapped"):
                source = "nmap"
            else:
                source = "—"
            rows.append({"key": tr.svc_key(h.ip, p.protocol, p.portid),
                         "group": h.ip, "data": {
                "IP": h.ip, "Hostname": h.hostname, "Port": p.portid,
                "Proto": p.protocol, "Service": p.service or "unknown",
                "ID source": source,
                "Product": p.product, "Version": p.version,
                "Backing binary": p.binary,
                "Extra info": p.extrainfo,
                "CPE": ", ".join(p.cpe), "Enum command": enum_cmd}})
    return SheetSpec("Services", cols, rows, group_by="IP")


def _spec_web(hosts: list[Host]) -> SheetSpec:
    """Every web-facing endpoint (HTTP/HTTPS on ANY port), categorized in one place,
    with its tech stack, how many web findings it carries, and the exact Kali
    deep-scan commands to run against it. Populated deeper by `recce web`."""
    from . import web
    cols = [
        ("Status", "status", 15), ("IP", "data", 16), ("Hostname", "data", 20),
        ("URL", "data", 30), ("Scheme", "data", 7), ("Tech / server", "data", 34),
        ("Web findings", "data", 12), ("Deep-scan commands (Kali)", "data", 80),
        ("Notes", "notes", 24), ("Key", "key", 4),
    ]
    rows = []
    for e in web.web_endpoints(hosts):
        rows.append({"key": tr.web_key(e["ip"], e["port"]), "group": e["ip"], "data": {
            "IP": e["ip"], "Hostname": e["hostname"], "URL": e["url"],
            "Scheme": e["scheme"], "Tech / server": e["tech"],
            "Web findings": e["findings"], "Deep-scan commands (Kali)": e["commands"]}})
    return SheetSpec("Web", cols, rows, group_by="IP", skip_if_empty=True)


def _spec_services_by_product(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Product", "data", 26), ("Version", "data", 18),
        ("Service", "data", 16), ("# Hosts", "data", 8), ("Hosts (ip:port)", "data", 80),
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    groups: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    display: dict[str, tuple[str, str, str]] = {}
    for h in hosts:
        for p in h.open_ports:
            key = p.product_version_key
            groups[key].append((h.ip, p.portid, h.hostname))
            display.setdefault(key, (p.product or p.service or "unknown", p.version, p.service))
    rows = []
    for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
        product, version, service = display[key]
        entries = sorted(groups[key], key=lambda t: _ip_sort_key(t[0]))
        rows.append({"key": tr.prod_key(key), "data": {
            "Product": product, "Version": version, "Service": service,
            "# Hosts": len(entries),
            "Hosts (ip:port)": ", ".join(f"{ip}:{port}" for ip, port, _ in entries)}})
    return SheetSpec("Services by Product", cols, rows)


def _spec_vulns(hosts: list[Host]) -> SheetSpec:
    # Findings fold under a collapsible per-host band (Hostname lives there, not on
    # every row), so a host's findings collapse to one line and the hosts with the
    # worst findings sort to the top.
    cols = [
        ("Triaged", "checkbox", 9), ("Severity", "data", 10), ("Tier", "data", 10),
        ("IP", "data", 16), ("Port", "data", 6), ("Finding", "data", 44),
        ("Source", "data", 11), ("QoD", "data", 18), ("CVE / refs", "data", 22),
        ("CWE", "data", 16), ("Exploit", "data", 52), ("To confirm", "data", 40),
        ("Remediation", "data", 44), ("Details", "data", 50),
        ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    worst = {h.ip: min((_SEV_RANK.get((v.severity or "").lower(), 9) for v in h.vulns),
                       default=9) for h in hosts}
    rows = []
    ordered = [(h, v) for h in hosts for v in h.vulns]
    # host worst-severity, then IP (keeps a host's findings contiguous for the band),
    # then this finding's severity, then confidence tier (confirmed edges above a lead of
    # the same severity - honest signal without disturbing the severity-first ordering).
    ordered.sort(key=lambda hv: (worst[hv[0].ip], _ip_sort_key(hv[0].ip),
                                 _SEV_RANK.get((hv[1].severity or "").lower(), 9),
                                 _TIER_RANK.get(_tier(hv[1]), 3)))
    for h, v in ordered:
        # Full output, shown in a wrapped column so it reads down inside its cell
        # (never truncated). Rows fold under the per-host band, so verbose findings
        # stay out of the way until you expand that host.
        out = v.output
        rows.append({"key": tr.vuln_row_key(v), "group": h.ip,
                     "data": {
            "Severity": (v.severity or "info").upper(), "Tier": _tier(v), "IP": h.ip,
            "Port": v.port if v.port else "", "Finding": v.title or v.script_id,
            "Source": v.source, "QoD": _qod_cell(v), "CVE / refs": ", ".join(v.ids),
            "CWE": ", ".join(v.cwes), "Exploit": _exploit_cell(h, v),
            "To confirm": _to_confirm_cell(h, v),
            "Remediation": v.remediation, "Details": out,
            "Hostname": h.hostname, "_worstsev": v.severity}})
    return SheetSpec("Vulnerabilities", cols, rows, _styler_vulns,
                     group_by="IP", group_summary=_vuln_band)


def _vuln_band(ip: str, grows: list[dict], tracking: Tracking) -> str:
    """Collapsible per-host band on Vulnerabilities: IP · hostname · N · worst sev."""
    hostname = grows[0]["data"].get("Hostname", "")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    worst = min((str(r["data"].get("Severity", "")).upper() for r in grows),
                key=lambda s: order.get(s, 9), default="")
    n = len(grows)
    label = f"{ip}"
    if hostname:
        label += f"   ·   {hostname}"
    label += f"   ·   {n} finding{'s' if n != 1 else ''}"
    if worst:
        label += f"   ·   worst: {worst}"
    return label


# Config / crypto-hardening weaknesses are never "run this exploit" findings,
# even if the scanner mentioned an exploitable CVE in passing (a weak-cipher
# finding must never claim a Heartbleed exploit).
_HARDENING_KW = ("weak", "cipher", "sslv", "tlsv1", "tls 1.0", "tls 1.1",
                 "deprecated", "self-signed", "self signed", "expired", "missing",
                 " header", "risky http", "anonymous", "banner grab", "clickjack",
                 "cookie", "renegotiation", "compression")


def _is_hardening_finding(v) -> bool:
    t = (v.title or "").lower()
    if any(k in t for k in _HARDENING_KW):
        return True
    return bool({c.upper() for c in (v.cwes or [])} & {"CWE-326", "CWE-327", "CWE-1104"})


def _qod_cell(v) -> str:
    """The finding's Quality of Detection as 'NN tier' (e.g. '99 active_vuln',
    '80 remote_banner'). Falls back to computing it if the finding wasn't annotated
    (a direct spec call in a test), so the column is always meaningful."""
    from . import qod as _qod
    score = v.qod or _qod.qod_of(v)
    kind = v.qod_type or _qod.score(v)[1]
    verified = " ✓" if score >= _qod.MIN_QOD_VERIFIED else ""
    return f"{score} {kind}{verified}".strip()


def _tier(v) -> str:
    """The honest confidence bucket from QoD: confirmed (actively verified),
    likely (a version/inference lead worth checking), or lead (low-confidence)."""
    from . import qod as _qod
    score = v.qod or _qod.qod_of(v)
    if score >= _qod.MIN_QOD_VERIFIED:
        return "confirmed"
    if score >= _qod.MIN_QOD_VISIBLE:
        return "likely"
    return "lead"


_TIER_RANK = {"confirmed": 0, "likely": 1, "lead": 2}


def _to_confirm_cell(h, v) -> str:
    """For a not-yet-confirmed lead, the exact SAFE command that would settle it (the
    honesty loop's `to_confirm`); blank for an actively-verified finding."""
    from . import qod as _qod
    from .verify_rules import rule_for_cve
    if (v.qod or _qod.qod_of(v)) >= _qod.MIN_QOD_VERIFIED:
        return ""
    for cve in (i.upper() for i in (v.ids or [])):
        rule = rule_for_cve(cve)
        if rule:
            cmd = (rule.get("confirm", "") or "").replace("<ip>", h.ip)
            if v.port:
                cmd = cmd.replace("<port>", str(v.port))
            return f"recce verify --run   ·   {cmd}"
    return ""


def _curated_exploit(v) -> str:
    """A genuinely PROVEN public exploit for this finding (curated CVE/keyword ->
    named Metasploit module / PoC), or ''. Never for a config-hardening finding or
    an unconfirmed advisory. This is the trustworthy 'proven' signal."""
    if v.confidence == "potential" or _is_hardening_finding(v):
        return ""
    return proven_exploit_ref(v.ids, f"{v.title} {v.script_id}") or ""


def _candidate_exploits(host: Host, v) -> list:
    """searchsploit EDB hits whose CVEs ACTUALLY match this finding (not merely the
    same port). Unverified leads to check, never presented as proof."""
    vids = {c.upper() for c in (v.ids or [])}
    if not vids or v.confidence == "potential":
        return []
    return [e for e in host.exploits
            if e.edb_id and vids & {c.upper() for c in (e.cves or [])}]


def _exploit_cell(host: Host, v) -> str:
    """The Exploit column: a proven curated exploit if we have one, else a
    CVE-matched searchsploit candidate (clearly labelled to verify), else ''."""
    proven = _curated_exploit(v)
    if proven:
        return proven
    cands = _candidate_exploits(host, v)
    if cands:
        return "candidate — verify: " + ", ".join(f"EDB-{e.edb_id}" for e in cands[:4])
    return ""


def _spec_exploits(hosts: list[Host]) -> SheetSpec:
    """searchsploit candidates. These are LOOSE Exploit-DB text matches on product
    name/version - leads to verify, not confirmed exploits. The 'Corroborates'
    column says whether a candidate's CVEs actually line up with a confirmed
    finding on the host (high-signal) or it's only a product/version guess."""
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Port", "data", 6), ("Product", "data", 20), ("Version", "data", 16),
        ("EDB-ID", "data", 9), ("Type", "data", 12),
        ("Corroborates finding?", "data", 34), ("Title", "data", 54),
        ("CVEs", "data", 24), ("Path", "data", 40), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        entries = []
        for e in h.exploits:
            ecves = {c.upper() for c in (e.cves or [])}
            hits = ([v.title or v.script_id for v in h.vulns
                     if ecves & {c.upper() for c in (v.ids or [])}] if ecves else [])
            corro = "; ".join(dict.fromkeys(hits)) if hits else \
                    "no — product/version guess, verify"
            entries.append((bool(hits), e, corro))
        # Corroborated candidates first, then loose product-name guesses.
        for _matched, e, corro in sorted(entries, key=lambda t: (not t[0], t[1].type)):
            rows.append({"key": tr.exploit_key(e.ip, e.port, e.edb_id), "data": {
                "IP": e.ip, "Hostname": h.hostname, "Port": e.port or "",
                "Product": e.product, "Version": e.version, "EDB-ID": e.edb_id,
                "Type": e.type, "Corroborates finding?": corro, "Title": e.title,
                "CVEs": ", ".join(e.cves), "Path": e.path}})
    return SheetSpec("Exploits", cols, rows, skip_if_empty=True)


def _clip(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


def _styler_raw(d: dict) -> dict:
    return {"Output": "wrap_mono"}       # raw evidence in monospace, wrapped


def _spec_raw_nse(hosts: list[Host]) -> SheetSpec:
    """All raw NSE script output, verbatim, in one place. The Scope column says
    whether a script ran against the whole host ("host": smb-os-discovery,
    smb2-time, nbstat, ldap-rootdse...) or a single open port (the port number:
    ftp-anon on 21, ssl-cert on 443...). This is the unparsed evidence behind the
    parsed sheets - filter Scope to `host` for host-wide facts, or to a port to
    read that service's output. Grouped by host and collapsible."""
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Scope", "data", 8), ("Script", "data", 28), ("Output", "data", 94),
        ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for s in h.host_scripts:                     # host-wide scripts first
            if not (s.output or "").strip():
                continue
            rows.append({"key": f"raw:{h.ip}:host:{s.id}", "group": h.ip, "data": {
                "IP": h.ip, "Hostname": h.hostname, "Scope": "host",
                "Script": s.id, "Output": _clip(s.output)}})
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            for s in p.scripts:                      # then per-port scripts
                if not (s.output or "").strip():
                    continue
                rows.append({"key": f"raw:{h.ip}:{p.portid}:{s.id}", "group": h.ip,
                             "data": {
                    "IP": h.ip, "Hostname": h.hostname, "Scope": str(p.portid),
                    "Script": s.id, "Output": _clip(s.output)}})
    return SheetSpec("Raw NSE", cols, rows, _styler_raw, skip_if_empty=True,
                     group_by="IP")


def _styler_databases(d: dict) -> dict:
    return {"Auth": "sev_high"} if d.get("Auth") else {}


def _spec_databases(hosts: list[Host]) -> SheetSpec:
    # Convention: state box, then IP + Hostname lead every host-centric sheet
    # (Vuln-scan status moved next to Engine/Version rather than before the IP).
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Port", "data", 6), ("Engine", "data", 12), ("Version", "data", 22),
        ("Vuln-scan", "data", 11), ("Auth", "data", 16), ("Databases", "data", 34),
        ("Users", "data", 30), ("Findings", "data", 40), ("Notes", "notes", 26),
        ("Key", "key", 4),
    ]
    rows = []
    for inst in dbmod.db_instances(hosts):
        rows.append({"key": f"db:{inst['ip']}:{inst['port']}", "data": {
            "Vuln-scan": "scanned" if inst["vuln_scanned"] else "pending",
            "IP": inst["ip"], "Hostname": inst["hostname"], "Port": inst["port"],
            "Engine": inst["engine"], "Version": inst["version"],
            "Auth": inst["auth"], "Databases": inst["databases"],
            "Users": inst["users"], "Findings": inst["findings"]}})
    return SheetSpec("Databases", cols, rows, _styler_databases, skip_if_empty=True)


_PE_TYPE = {"escalation": "Escalation path", "finding": "Finding",
            "action": "To do"}


def _styler_privesc(d: dict) -> dict:
    t = d.get("Type")
    if t == "Escalation path":
        return {"Type": "sev_high"}          # confirmed, actually escalatable
    if t == "Finding":
        return {"Type": "sev_medium"}
    return {"Type": "sev_info"} if t == "To do" else {}


def _spec_privesc(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 18),
        ("Type", "data", 15), ("OS", "data", 18), ("Category", "data", 10),
        ("Vector", "data", 30), ("How-to / command", "data", 55),
        ("Ref / note", "data", 40), ("Notes", "notes", 24), ("Key", "key", 4),
    ]
    rows = []
    for r in pe.all_rows(hosts):
        rows.append({"key": r["key"], "data": {
            "IP": r["ip"], "Hostname": r["hostname"],
            "Type": _PE_TYPE.get(r.get("type"), ""), "OS": r["os"],
            "Category": r["category"], "Vector": r["vector"],
            "How-to / command": r["howto"], "Ref / note": r["note"]}})
    return SheetSpec("Priv-Esc", cols, rows, _styler_privesc, skip_if_empty=True)


def _styler_verification(d: dict) -> dict:
    v = d.get("Verdict")
    if v == "CONFIRMED":
        return {"Verdict": "sev_high"}          # proven real
    if v == "LIKELY":
        return {"Verdict": "sev_medium"}
    if v == "FALSE POSITIVE":
        return {"Verdict": "sev_info"}          # noise - dismiss
    return {"Verdict": "sev_low"}               # inconclusive


def _spec_verification(hosts: list[Host]) -> SheetSpec:
    """Per-finding proof verdict: CONFIRMED / LIKELY / FALSE POSITIVE / INCONCLUSIVE,
    with the evidence used, the preconditions, the exact safe command to finish
    proving, and what a false positive looks like. Answers 'is this real?'."""
    from . import proofs
    cols = [
        ("Verdict", "data", 15), ("IP", "data", 16), ("Port", "data", 7),
        ("Vulnerability", "data", 34), ("Evidence (why this verdict)", "data", 64),
        ("Preconditions", "data", 40), ("Finish proving (in ROE)", "data", 52),
        ("False positive if…", "data", 36), ("Key", "key", 4),
    ]
    vrank = {"CONFIRMED": 0, "LIKELY": 1, "INCONCLUSIVE": 2, "FALSE POSITIVE": 3}
    results = list(proofs.verify_hosts(hosts))
    # Contiguous per host (for the band), CONFIRMED first within a host.
    results.sort(key=lambda r: (_ip_sort_key(r["ip"]),
                                vrank.get(r["verdict"], 4)))
    rows = []
    for r in results:
        rows.append({"key": r["key"], "group": r["ip"], "data": {
            "Verdict": r["verdict"], "IP": r["ip"], "Port": r["port"] or "",
            "Vulnerability": r["vuln"],
            "Evidence (why this verdict)": "  •  ".join(r["evidence"]),
            "Preconditions": "; ".join(r["preconditions"]),
            "Finish proving (in ROE)": r["finish"],
            "False positive if…": r["fp"], "_verdict": r["verdict"]}})
    return SheetSpec("Verification", cols, rows, _styler_verification,
                     skip_if_empty=True, group_by="IP", group_summary=_verify_band)


def _verify_band(ip: str, grows: list[dict], tracking: Tracking) -> str:
    """Collapsible per-host band on Verification: IP · N checks · confirmed count."""
    n = len(grows)
    confirmed = sum(1 for r in grows if r["data"].get("_verdict") == "CONFIRMED")
    label = f"{ip}   ·   {n} check{'s' if n != 1 else ''}"
    if confirmed:
        label += f"   ·   ✔ {confirmed} CONFIRMED"
    return label


def _spec_privesc_playbook(hosts: list[Host]) -> SheetSpec:
    """Reference sheet: the generic Windows/Linux local-privesc checklist, listed
    once per OS in scope. Deliberately separate from Priv-Esc so that tab stays
    real findings (from `recce deploy`/`ingest`), not boilerplate."""
    cols = [
        ("Done", "checkbox", 7), ("OS", "data", 10), ("Vector", "data", 32),
        ("How-to / command", "data", 60), ("Note", "data", 50), ("Key", "key", 4),
    ]
    rows = []
    for r in pe.playbook_rows(hosts):
        rows.append({"key": r["key"], "data": {
            "OS": r["os"], "Vector": r["vector"],
            "How-to / command": r["howto"], "Note": r["note"]}})
    return SheetSpec("Priv-Esc Playbook", cols, rows, skip_if_empty=True)


def _spec_exploitation(hosts: list[Host]) -> SheetSpec:
    """The finding -> run-this bridge for every CONFIRMED finding: remote exploits
    (Metasploit modules, params filled in), remote tool actions (impacket / netexec
    / GTFOBins), and post-shell priv-esc - each mapped to the exact EXISTING public
    tool, the command with the finding's values filled in, the prerequisite, and how
    to validate. References vetted tools - it does not generate exploit code. Empty
    (sheet skipped) until there are confirmed findings. `exploitplan` writes the
    same actions out as runnable .rc / .sh artifacts."""
    from . import exploitplan as xp
    _KIND = {"remote-msf": "remote (msf)", "remote-tool": "remote (tool)",
             "post-shell": "post-shell"}
    defenses = {h.ip: "; ".join(h.defenses) for h in hosts if h.defenses}
    cols = [
        ("Done", "checkbox", 9), ("IP", "data", 15), ("Hostname", "data", 15),
        ("Type", "data", 13), ("Confidence", "data", 18), ("Finding", "data", 28),
        ("Existing tool", "data", 28), ("Command (fill in your values)", "data", 58),
        ("Prerequisite", "data", 28), ("Validate", "data", 22),
        ("Defenses (host)", "data", 26), ("Notes", "notes", 20), ("Key", "key", 4),
    ]
    # An action off an actively-verified finding is "confirmed"; one off a version/
    # inference lead is a "candidate - verify" (run the check before firing). This is the
    # honest fix for a version match ever reading as a confirmed exploit.
    rows = [{"key": a["key"], "data": {
        "IP": a["ip"], "Hostname": a["hostname"],
        "Type": _KIND.get(a["kind"], a["kind"]),
        "Confidence": "confirmed" if a.get("verified", True) else "candidate — verify",
        "Finding": a["finding"],
        "Existing tool": a["tool"], "Command (fill in your values)": a["cmd"],
        "Prerequisite": a["prereq"], "Validate": a["validate"],
        "Defenses (host)": defenses.get(a["ip"], "")}}
        for a in xp.all_actions(hosts)]
    return SheetSpec("Exploitation", cols, rows, skip_if_empty=True)


def _spec_attackpath(hosts: list[Host]) -> SheetSpec:
    """The confirmed findings chained into a prioritised attack path (foothold ->
    priv-esc -> creds -> lateral -> domain), grounded in what recce found. Empty
    (sheet skipped) until there are confirmed, chainable findings."""
    from . import attackpath as ap
    cols = [
        ("Done", "checkbox", 9), ("Stage", "data", 20), ("IP", "data", 22),
        ("Hostname", "data", 16), ("Step", "data", 34), ("Existing tool", "data", 26),
        ("Command", "data", 60), ("Why it matters", "data", 40),
        ("Notes", "notes", 20), ("Key", "key", 4),
    ]
    rows = [{"key": s["key"], "data": {
        "Stage": s["stage"], "IP": s["ip"], "Hostname": s["hostname"],
        "Step": s["title"], "Existing tool": s["tool"], "Command": s["cmd"],
        "Why it matters": s["why"]}}
        for s in ap.build(hosts)]
    return SheetSpec("Attack Path", cols, rows, skip_if_empty=True)


def _spec_quick_wins(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Category", "data", 20), ("Target", "data", 34),
        ("Detail", "data", 40), ("Why it matters", "data", 55), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = [{"key": w["key"], "data": {
        "Category": w["category"], "Target": w["target"], "Detail": w["detail"],
        "Why it matters": w["why"]}} for w in ad.quick_wins(hosts)]
    return SheetSpec("AD Quick Wins", cols, rows, _styler_quickwins, skip_if_empty=True)


def _spec_accounts(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Kind", "data", 9), ("Domain", "data", 14),
        ("Name", "data", 22), ("RID", "data", 7), ("Enabled", "data", 8),
        ("AdminCount", "data", 10), ("Roastable", "data", 18), ("Delegation", "data", 13),
        ("SPN", "data", 40), ("Member of", "data", 30), ("Description", "data", 30),
        ("OS", "data", 22), ("Source", "data", 14), ("IP", "data", 15),
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    kind_order = {"user": 0, "group": 1, "computer": 2, "spn": 3, "share": 4,
                  "domain": 5, "trust": 6}
    rows = []
    for h, a in sorted(((h, a) for h in hosts for a in h.accounts),
                       key=lambda ha: (kind_order.get(ha[1].kind, 9), ha[1].domain,
                                       ha[1].name.lower())):
        at = a.attrs
        roastable = []
        if at.get("spn"):
            roastable.append("kerberoast")
        if at.get("asrep_roastable") == "yes":
            roastable.append("AS-REP")
        rows.append({"key": tr.acct_key(a.source, a.kind, a.domain, a.name, a.rid), "data": {
            "Kind": a.kind, "Domain": a.domain, "Name": a.name, "RID": a.rid,
            "Enabled": at.get("enabled", ""), "AdminCount": at.get("admincount", ""),
            "Roastable": ", ".join(roastable), "Delegation": at.get("delegation", ""),
            "SPN": at.get("spn", "") or at.get("members", ""),
            "Member of": at.get("memberof", ""), "Description": at.get("description", ""),
            "OS": at.get("os", ""), "Source": a.source, "IP": h.ip}})
    return SheetSpec("Users & Accounts", cols, rows, _styler_accounts, skip_if_empty=True)


# --- writing a tracked sheet (with stable ordering) ------------------------------

def _ordered_keys(spec_rows: list[dict], order: list[str] | None) -> list[str]:
    """Row keys in final order: existing rows keep their saved position, new
    items append at the bottom. Shared by the sheet writer and the Overview's
    Checklist-row deep-link computation so the two always agree."""
    rows_by_key = {r["key"]: r for r in spec_rows}
    ordered: list[str] = []
    seen: set[str] = set()
    for k in (order or []):
        if k in rows_by_key and k not in seen:
            ordered.append(k)
            seen.add(k)
    for k in rows_by_key:
        if k not in seen:
            ordered.append(k)
            seen.add(k)
    return ordered


def _write_spec(sheet, spec: SheetSpec, tracking: Tracking,
                order: list[str] | None = None,
                statuses: dict | None = None) -> None:
    statuses = statuses or {}
    # Colour step-checkbox headers so a reader can tell at a glance which boxes the
    # tool auto-ticks (green) from the ones that are a manual operator sign-off
    # (amber). Only the Checklist has 'check' columns, so other sheets are unchanged.
    def _hdr_style(header, role):
        if role == "check":
            step = tr.STEP_COLUMNS.get(header)
            return "header_manual" if step in tr.MANUAL_STEPS else "header_auto"
        return "header"
    # An optional legend/note line sits ABOVE the header (row 1); the column headers
    # then land on row 2. header_row keeps freeze-pane, auto-filter and the tall
    # header height aligned to wherever the headers actually are.
    if spec.legend:
        sheet.write([(spec.legend, "sub")]
                    + [("", "sub")] * (len(spec.cols) - 1))
        sheet.header_row = 2
    sheet.write([(h, _hdr_style(h, role)) for h, role, _w in spec.cols])

    rows_by_key = {r["key"]: r for r in spec.rows}
    ordered_keys = _ordered_keys(spec.rows, order)

    # Optional collapsible grouping: reorder keys into per-host bands (stable by
    # first appearance), so each host's rows sit under a header the tester can
    # collapse. `items` is a flat sequence of ("hdr", groupval) / ("row", key).
    grouped = bool(spec.group_by)
    ip_col = next((i for i, (h, _, _) in enumerate(spec.cols, 1) if h == "IP"), 1)
    noun = {"Services": "ports", "Raw NSE": "scripts"}.get(spec.title, "rows")
    if grouped:
        buckets: dict[str, list[str]] = {}
        for k in ordered_keys:
            buckets.setdefault(rows_by_key[k].get("group", ""), []).append(k)
        items: list[tuple[str, str]] = []
        for gv, keys in buckets.items():
            items.append(("hdr", gv))
            items += [("row", k) for k in keys]
    else:
        items = [("row", k) for k in ordered_keys]

    # Excel row numbers (1-based, header is row 1) where a "check" column holds a
    # real checkbox rather than an N/A dash - used to scope validation/formatting.
    active_check_rows: dict[int, list[int]] = {}
    data_rows: list[int] = []            # detail (non-group-header) row numbers
    # First data/band row sits just below the header, wherever the header ended up
    # (row 1 normally, row 2 when a legend line precedes it).
    excel_row = sheet.header_row
    for kind, key in items:
        excel_row += 1
        if kind == "hdr":
            # A collapsible section band: a summary in the IP column, the rest blank
            # but styled, so a whole host (or subnet) folds into one row.
            grp_rows = buckets[key]
            if spec.group_summary:
                label = spec.group_summary(key, [rows_by_key[k] for k in grp_rows],
                                           tracking)
            else:
                hostname = rows_by_key[grp_rows[0]]["data"].get("Hostname", "")
                # Join only the present parts, so an empty hostname doesn't leave a
                # dangling "·" (previously patched with a fragile 6-space replace()).
                parts = [key, hostname, f"{len(grp_rows)} {noun}"]
                label = "   ·   ".join(p for p in parts if p)
            hdr_cells = []
            for ci, (_h, _role, _w) in enumerate(spec.cols, start=1):
                hdr_cells.append((label if ci == ip_col else "", "group"))
            sheet.write(hdr_cells, outline=0)
            continue
        data_rows.append(excel_row)
        row = rows_by_key[key]
        data = row["data"]
        checks = row.get("checks", {})   # {header: (stepkey, auto_default, applies)}
        rev, note = tracking.get(key, (False, ""))
        styles = spec.styler(data) if spec.styler else {}
        band = (excel_row % 2 == 0)      # zebra-stripe even data rows
        data_style = "cell_band" if band else "cell"
        center_style = "center_band" if band else "center"
        cells = []
        for ci, (header, role, _w) in enumerate(spec.cols, start=1):
            if role == "checkbox":
                cells.append((xlsx.CHECK_ON if rev else xlsx.CHECK_OFF, center_style))
            elif role == "check":
                stepkey, auto, applies = checks.get(header, ("", False, True))
                if not applies:
                    cells.append((tr.STEP_NA, center_style))  # not relevant here
                    continue
                shown = tracking[stepkey][0] if stepkey in tracking else auto
                cells.append((xlsx.CHECK_ON if shown else xlsx.CHECK_OFF, center_style))
                active_check_rows.setdefault(ci, []).append(excel_row)
            elif role == "status":
                # Explicit tri-state wins; otherwise fall back to the reviewed
                # flag (a port already marked done shows Done, else Not started).
                cells.append((statuses.get(key)
                              or (STATUS_DONE if rev else STATUS_TODO), data_style))
            elif role == "notes":
                cells.append((note, data_style))
            elif role == "key":
                cells.append((key, data_style))
            else:
                val = data.get(header, "")
                st = styles.get(header)
                wide = _w >= _WRAP_WIDTH       # wide cols wrap so text reads down
                if st:                        # styler-assigned accent (severity/wrap)
                    if st == "wrap":
                        st = "wrap_band" if band else "wrap"
                    elif st == "wrap_mono":
                        st = "wrap_band_mono" if band else "wrap_mono"
                    cells.append((val, st))
                elif header == "IP":          # teal monospace accent
                    cells.append((val, "ip_band" if band else "ip"))
                elif header in MONO_COLS:      # machine data -> monospace
                    if wide:
                        cells.append((val, "wrap_band_mono" if band else "wrap_mono"))
                    else:
                        cells.append((val, "cell_band_mono" if band else "cell_mono"))
                elif wide:                    # wide free-text -> wrap, don't run across
                    cells.append((val, "wrap_band" if band else "wrap"))
                else:
                    cells.append((val, data_style))
        sheet.write(cells, outline=(1 if grouped else 0))

    ncols = len(spec.cols)
    sheet.freeze_header = True
    sheet.hide_gridlines = True          # our hairline rules read cleaner than gridlines
    sheet.header_height = 22
    sheet.tab_color = TAB_COLORS.get(spec.title)
    # Freeze the identity columns so the IP stays visible when scrolling right.
    sheet.freeze_cols = _FREEZE_COLS.get(spec.title, 0)
    sheet.autofilter_cols = ncols
    for i, (_h, role, w) in enumerate(spec.cols, start=1):
        sheet.set_col(i, w, hidden=(role == "key"))
    last = sheet.nrows

    def _rowset_sqref(col: int) -> str | None:
        # On grouped sheets, scope validation/formatting to the DATA rows only, so
        # the collapsible group-header rows never sprout a stray dropdown arrow.
        if not grouped:
            return None
        return _col_sqref(xlsx.col_letter(col), data_rows) or None

    # Checkbox / check columns get the ☑/☐ dropdown + green-when-checked. For
    # per-step "check" columns, restrict it to the cells that actually hold a box
    # so N/A dashes don't trip Excel's list-validation error.
    for i, (h, role, _w) in enumerate(spec.cols, 1):
        if role == "check":
            active = active_check_rows.get(i, [])
            if not active:
                continue
            sqref = _col_sqref(xlsx.col_letter(i), active)
            sheet.dropdown(i, 2, last, sqref=sqref)
            sheet.green_when_true(i, 2, last, sqref=sqref)
        elif role == "status":
            sq = _rowset_sqref(i)
            sheet.dropdown(i, 2, last, sqref=sq, values=STATUS_VALUES)
            sheet.highlight_when_equal(i, 2, last, STATUS_DONE, dxf_id=0, sqref=sq)
            sheet.highlight_when_equal(i, 2, last, STATUS_WIP, dxf_id=1, sqref=sq)
        elif h in CHECKBOX_HEADERS:
            sq = _rowset_sqref(i)
            sheet.dropdown(i, 2, last, sqref=sq)
            sheet.green_when_true(i, 2, last, sqref=sq)


# --- computed (non-tracked) sheets ----------------------------------------------

def _build_guide(wb, meta: dict) -> None:
    """A friendly 'Start Here' sheet so the workbook explains itself."""
    sh = wb.add_sheet("Start Here")
    sh.write([("recce - engagement tracker", "title")])
    sh.write([(meta.get("subtitle", ""), "sub")])
    sh.write([""])
    sh.write([("Scans fill this workbook in; you check things off as you go. "
               "Your ticks and notes are saved and survive re-scans.", "bold")])
    sh.write([""])

    sh.write([("How to use it", "title")])
    for line in [
        "1. Go to the CHECKLIST tab - one row per IP, a checkbox for each step. Each "
        "subnet is a collapsible group: click the [-] in the left margin to fold a "
        "whole /24 to one summary band, expand the one you're working. Hosts with "
        "high/critical findings sort to the top of each subnet.",
        "2. The step columns are colour-coded in the header so you can see which fill "
        "themselves: GREEN headers = AUTO (the tool ticks them) - Enumerated, "
        "Vuln-scan, Web, DB, Access, Priv-esc turn green as recce finishes each phase "
        "(running smb/ftp/docker/k8s/mssql/ldap also auto-ticks the ports they assess; "
        "Access ticks when credentialed enum confirms a foothold, or via `recce "
        "access`). AMBER headers = MANUAL sign-offs you tick yourself - AD, Creds, "
        "Lateral - the kill-chain steps only you can confirm.",
        "3. Steps that don't apply to a host show '—' instead of a box (e.g. no AD "
        "box off a non-DC). SMB/remote/mail/SNMP are tracked on the SERVICES tab.",
        "4. You can tick/untick any box by hand - your choice sticks (untick to "
        "flag 'redo'). Tick 'Reviewed' when you're personally done with a host.",
        "5. The boxes are ☑ / ☐ dropdowns: click the cell and pick ☑ to check it.",
        "6. Use the SERVICES tab to track each open PORT: set its Status dropdown "
        "to Not started / In progress / Done and jot findings in Notes.",
        "7. Filter a step column to ☐ (or Services Status to 'Not started') to see "
        "exactly what still needs work.",
        "8. The OVERVIEW tab and the `status` command show overall progress.",
    ]:
        sh.write([line])
    sh.write([""])

    sh.write([("What each tab is", "title")])
    sh.write([("Tab", "header"), ("What it shows", "header")])
    for tab, desc in [
        ("Runbook", "Step-by-step: exactly what to type for each phase + the options "
                    "that matter, plus a troubleshooting table. Start here if you "
                    "just want the commands."),
        ("Overview", "Totals, review progress, and live-hosts-per-subnet coverage."),
        ("Checklist", "THE working tab: one row per IP under a collapsible per-subnet "
                      "band (fold a /24 to one summary line), a checkbox for each phase "
                      "+ host detail + Reviewed + Notes. Step headers are colour-coded - "
                      "GREEN = auto (the tool ticks it), AMBER = your manual sign-off. "
                      "# Vulns is coloured by worst severity; risky hosts sort to the "
                      "top of each subnet. Lists only hosts CONFIRMED up (an open port "
                      "or a real reply); a host is never written off as down - IPs with "
                      "no proof of life are tallied on the Overview as UNKNOWN instead."),
        ("Services", "The other working tab: every open port folded under a collapsible "
                     "per-host band, each with a Status (not started / in progress / "
                     "done) and Notes - track each port you work."),
        ("Web", "Every HTTP/HTTPS endpoint (any port), its tech stack, web-finding "
                "count, and the exact Kali deep-scan commands. Run `recce web`."),
        ("Vulnerabilities", "Findings folded under a collapsible per-host band (hosts "
                            "with the worst findings first), severity-coloured. Wide "
                            "columns wrap so they read down, not across; Details is "
                            "shown in full."),
        ("Exploits", "searchsploit matches (EDB-ID, type, CVEs, local path)."),
        ("Verification", "Is it REAL? Per-host collapsible bands; per-finding verdict "
                         "(CONFIRMED / LIKELY / FALSE POSITIVE / INCONCLUSIVE) with the "
                         "evidence + the exact safe command to finish proving. Run "
                         "`recce prove`."),
        ("Services by Product", "Who runs the same service+version (mass-patch pivot)."),
        # --- per-service deep-dive band (grouped, right after the findings) ---
        ("Databases", "DB inventory: engine, version, auth, databases, users."),
        ("MSSQL", "SQL Server offensive view: endpoints (version/encryption/access/"
                  "privilege), misconfig/vuln findings, and the credential-free + "
                  "MSSQLPwner-style runbook & attack chain. Run `recce mssql`."),
        ("SMB", "SMB offensive view: pre-auth posture (dialect / signing / SMBv1), "
                "anonymous & credentialed share enumeration, and a reversible "
                "writable-share proof. Run `recce smb`."),
        ("FTP", "FTP offensive view: banner / anonymous-login / AUTH-TLS posture, "
                "known-backdoor matches (vsftpd 2.3.4, ProFTPD), and a reversible "
                "writable-directory proof. Run `recce ftp`."),
        ("Docker", "Docker Engine API exposure: an unauthenticated API is remote root "
                   "RCE on the host. recce READS the API to prove it. Run `recce docker`."),
        ("Kubernetes", "Kubernetes attack surface: unauthenticated reads of the kubelet "
                       "(exec-into-pods), kube-apiserver (anonymous LIST / Secrets) and "
                       "etcd (all cluster secrets). Run `recce k8s`."),
        ("LDAP", "LDAP / AD directory (stdlib BER client): anonymous bind, RootDSE "
                 "(domain/forest/DC/functional level), anonymous directory-read "
                 "detection, cleartext-389 / relay surface - and, with -u/-p/-d, a "
                 "paged authenticated enum (users/SPNs/delegation -> AD Quick Wins). "
                 "Run `recce ldap`."),
        ("SNMP", "SNMP over UDP (stdlib BER v2c client): community-string guessing, "
                 "sysDescr/sysName, and a walk of the LanMgr user table, running "
                 "processes and installed software (local accounts -> Users & "
                 "Accounts). Read-only. Run `recce snmp`."),
        ("MongoDB", "MongoDB wire protocol (stdlib OP_MSG/BSON client): hello + "
                    "buildInfo fingerprint, then listDatabases to prove whether the "
                    "instance answers privileged commands with no authentication. "
                    "Run `recce mongodb`."),
        ("Redis", "Redis wire protocol (stdlib RESP client): PING + INFO, then "
                  "INFO-without-auth to prove an unauthenticated instance (read/write "
                  "+ CONFIG/SAVE file-write -> RCE). Run `recce redis`."),
        ("Elasticsearch", "Elasticsearch HTTP API (stdlib client): / fingerprint, "
                          "then /_cat/indices-without-auth to prove an exposed cluster "
                          "(all documents readable). Run `recce elasticsearch`."),
        ("rsync", "rsync daemon protocol (stdlib): #list the modules, then prove which "
                  "answer @RSYNCD: OK with no credential (unauthenticated file read). "
                  "Run `recce rsync`."),
        ("NFS", "ONC RPC (stdlib): portmapper DUMP + mountd EXPORT (showmount -e); an "
                "export shared to * / everyone is world-mountable. Run `recce nfs`."),
        ("Kerberos", "Credential-less AD roasting (stdlib Kerberos): AS-REP roast "
                     "pre-auth-disabled accounts + validate usernames via the KDC, no "
                     "creds and no lockouts. Run `recce kerberos -d DOMAIN`."),
        # --- Active Directory cluster (kept contiguous) ---
        ("Active Directory", "Domains, DCs, password policy, trusts."),
        ("AD Quick Wins", "Prioritised AD attack paths (DC, relay, roast, deleg)."),
        ("AD Findings", "Misconfigurations/vulns from a SharpHound + Certipy import "
                        "(Kerberoast, DCSync, delegation, RBCD, shadow-creds, ADCS "
                        "ESC1-15) - each with the exact certipy/impacket command to "
                        "prove it. Run `recce ad`."),
        ("AD Attack Paths", "Shortest path from YOUR account (or any authenticated "
                            "user) to Domain Admin / the domain / a DC, plus the "
                            "Kerberos actions to run. Run `recce ad -u USER -p PASS`."),
        ("Users & Accounts", "AD/SMB users, groups, computers, shares."),
        # --- loot -> act -> post-exploitation ---
        ("Credentials", "Stacked credentials (auto-harvested + manually captured), "
                        "ready to spray. `recce creds --plan` builds the netexec / "
                        "impacket spray plan."),
        ("Exploitation", "Every CONFIRMED finding (remote service exposures AND local "
                         "priv-esc) mapped to the exact existing tool + command (your "
                         "values filled in) + how to validate. Run `recce exploitplan`."),
        ("Attack Path", "A PROJECTED route: confirmed findings chained into a staged "
                        "path (foothold -> priv-esc -> creds -> lateral -> domain). "
                        "recce grounds each step in what it observed but does NOT "
                        "execute it - each row gives the command to run + how to "
                        "validate. Run `recce attackpath`."),
        ("Priv-Esc", "Per-host escalation findings from the local sweep "
                     "(recce deploy/ingest) + remote signals. Un-swept hosts show a "
                     "'run recce deploy' to-do; dead IPs get no rows."),
        ("Priv-Esc Playbook", "Reference: the generic Windows/Linux local-privesc "
                              "checklist (what to run once you have a shell)."),
        ("Raw NSE", "All raw NSE script output, verbatim (Scope = host or port) - "
                    "the evidence behind the parsed sheets; grouped by host."),
    ]:
        sh.write([tab, desc])
    sh.write([""])

    sh.write([("Commands (run these to fill the workbook)", "title")])
    sh.write([("Command", "header"), ("What it does", "header")])
    for cmd, desc in [
        ("doctor", "Check this box can run everything (env + tools + self-scan)."),
        ("enum <targets>", "Phase 1: discover hosts, scan ports, ID services (fast)."),
        ("vulns [targets]", "Phase 2: vuln-scan open ports (safe; --aggressive for more)."),
        ("sweep", "ONE command for the whole UNAUTHENTICATED deep pass: runs every "
                  "applicable credential-free module below (web/smb/ftp/ldap/snmp/"
                  "mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql), "
                  "skipping services you don't have. Add --vulns for the NSE scan too."),
        ("credsweep -u U -p P -d DOM",
         "ONE command for the whole AUTHENTICATED deep pass (once you have creds): "
         "credenum (netexec/impacket) + authenticated ldap/smb/mssql/ftp. Run the "
         "individual commands below only to focus or pass module-specific options."),
        ("web [targets]", "Deep, non-intrusive scan of every HTTP/HTTPS endpoint "
                          "(exposed files, PUT/JWT proofs, CORS, GraphQL). Fills Web."),
        ("db [targets]", "Database enumeration + vuln scan."),
        ("privesc [targets]", "Priv-esc playbook (+ --scan for remote checks)."),
        ("credenum -u U -p P -d DOM", "Authenticated enum (netexec/impacket/ssh) "
                                      "- shares, roasting, local admin, hashes."),
        ("mssql [-u U -p P -d DOM]",
         "MSSQL: pre-auth probes (no creds) + nxc access/priv matrix + the "
         "MSSQLPwner-style runbook & attack chain (commands pre-filled)."),
        ("smb [-u U -p P -d DOM] [--prove-write]",
         "SMB: stdlib signing/SMBv1 posture + anonymous/credentialed share enum + "
         "a reversible writable-share proof."),
        ("ftp [-u U -p P] [--prove-write]",
         "FTP: anonymous-login / AUTH-TLS posture + known-backdoor match + a "
         "reversible writable-directory proof."),
        ("docker", "Docker: read the Engine API (2375/2376) unauthenticated -> a "
                   "CONFIRMED exposed daemon is remote root RCE on the host."),
        ("kubernetes / k8s", "Kubernetes: unauthenticated reads of the kubelet, "
                             "kube-apiserver and etcd (exec-into-pods / anonymous "
                             "Secrets / all cluster secrets)."),
        ("ldap", "LDAP: anonymous bind + RootDSE (domain/forest/DC/functional level) "
                 "and anonymous directory-read detection; flags cleartext 389."),
        ("snmp", "SNMP: community-string guessing over UDP + a read-only walk of "
                 "users / processes / installed software (local accounts -> spray)."),
        ("mongodb / mongo", "MongoDB: fingerprint + prove unauthenticated "
                            "listDatabases (no-auth exposure)."),
        ("ad <sharphound> <certipy> -u U -p P -d DOM",
         "Import SharpHound + Certipy (ADCS): AD vulns, ESC findings, and the "
         "shortest paths from your account to Domain Admin - commands pre-filled."),
        ("exploitplan --lhost <ip>",
         "Every CONFIRMED finding -> exact tool + command + msf .rc artifacts. "
         "Fills Exploitation."),
        ("attackpath", "Chain the confirmed findings into a staged path (foothold -> "
                       "priv-esc -> creds -> lateral -> domain). Fills Attack Path."),
        ("creds --add 'DOM\\u:p' / --plan",
         "Stack captured credentials + build the netexec/impacket spray plan. "
         "Fills Credentials."),
        ("writeups", "Generate a Word (.docx) write-up per finding - finish each "
                     "in Word (screenshots auto-added for web when a browser is present)."),
        ("access [--host IP --note '...']",
         "Review footholds per host (auto-derived from credentialed enum), or record "
         "one you gained another way - ticks the Checklist Access step."),
        ("status / report", "Show progress + deep-dive coverage / rebuild this "
                            "workbook from the datastore."),
    ]:
        sh.write([cmd, desc])
    sh.write([""])
    sh.write([("Targets = a single IP, several IPs, a range (10.0.0.10-40), a "
               "whole subnet (10.0.0.0/24), or @file.", "sub")])
    sh.set_col(1, 24)
    sh.set_col(2, 78)


def _build_runbook(wb, meta: dict) -> None:
    """A step-by-step 'Runbook' sheet: exactly what to type, phase by phase,
    with the options that matter for each phase. The tester can work top-to-
    bottom without leaving the workbook."""
    sh = wb.add_sheet("Runbook")
    sh.hide_gridlines = True

    def section(title, blurb=""):
        sh.write([""])
        sh.write([(title, "title")])
        if blurb:
            sh.write([(blurb, "sub")])
        sh.write([("Type this", "header"), ("What it does / options", "header")])

    def cmd(c, desc):
        sh.write([(c, "cell_mono"), (desc, "wrap")])

    sh.write([("recce - tester runbook", "title")])
    sh.write([(meta.get("subtitle", "") or "Work top-to-bottom. Each phase writes "
               "into this workbook; your ticks and notes survive re-scans.", "sub")])
    sh.write([("Prefix every command with `python3 -m recce` (or use the bundled "
               "`./bin/recce` wrapper). `-o DIR` is the engagement folder that holds "
               "the workbook + datastore; keep it the same across all phases.", "bold")])

    section("Targets - the one thing every scan phase takes",
            "Give enum/vulns/scan any of these forms (space-separated to mix):")
    cmd("10.0.0.5", "a single host")
    cmd("10.0.0.5 10.0.0.9 10.0.0.20", "several hosts")
    cmd("10.0.0.10-40", "a range (last octet 10 through 40)")
    cmd("10.0.0.0/24", "a whole subnet")
    cmd("@scope.txt", "read targets from a file (one per line; # comments ok)")
    cmd("--exclude 10.0.0.1,10.0.0.0/28", "carve out-of-scope hosts back out")

    section("0. Pre-flight - prove the box can do the work")
    cmd("doctor", "Check env + required/optional tools + run a localhost self-scan. "
                  "Run this first; it tells you loudly what's missing.")

    section("1. Enumerate - discover hosts, ports, services (fast, safe)",
            "Already have an nmap scan? Use `import` instead of `enum` (no scanning).")
    cmd("import scan.xml [more...] -o eng",
        "Import EXISTING nmap scans - XML (-oX, richest), grepable (-oG), or normal "
        "(-oN); multiple files/dirs/globs; masscan XML too. Appends + merges (never "
        "duplicates). Runs the same offline enrichment as enum; ticks Enumerated.")
    cmd("enum <targets> -o eng --title \"Client X\"",
        "Host discovery + full TCP + service/version/OS + deep service NSE. "
        "Fills Checklist, Services, Raw NSE.")
    cmd("  --profile quick|standard|thorough",
        "How hard to look (standard is the default; quick skips deep enum for speed).")
    cmd("  --workers N", "How many hosts to scan at once (default 6).")
    cmd("  --host-timeout MIN", "Give up on a slow host after MIN minutes and move on.")

    section("2. Vulns - vuln-scan the open ports you found")
    cmd("vulns -o eng", "Curated detection NSE + version-matched offline vuln DB + "
                        "HTTP/TLS probes. Fills Vulnerabilities, Exploits.")
    cmd("  --fast", "Top-signal detection scripts only - much quicker on a /24 when "
                    "you just want the high-value hits. Shows live per-host progress + ETA.")
    cmd("  --aggressive", "Add nmap `vulners` + broader scripts (slower, noisier, "
                          "more coverage). Opposite end from --fast.")
    cmd("  [targets]", "Optional: limit to specific hosts/ports (default = everything "
                       "enum found).")

    section("2b. Web - deep, non-intrusive scan of every HTTP/HTTPS endpoint",
            "Runs stdlib checks (exposed .git/.env, dangerous methods PROVEN via a "
            "reversible PUT, JWT alg:none forge-and-replay, CORS, GraphQL, secrets) and "
            "writes the exact Kali deep-scan commands. Fills the Web tab.")
    cmd("web -o eng", "Scan every web endpoint (any port). Add creds with -u/-p to scan "
                      "authenticated.")

    section("2c. Deep pass - one command instead of running each module by hand",
            "After enum, rather than typing web/smb/ftp/ldap/snmp/mongodb/redis/"
            "elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql one at a time, run the "
            "whole pass at once. Each module self-skips "
            "when there's no matching service; the workbook rebuilds once at the end.")
    cmd("sweep -o eng", "UNAUTHENTICATED pass: every applicable credential-free module. "
                        "Add --vulns to also run the NSE vuln scan; --only-modules / "
                        "--skip to narrow. Refuses creds (use credsweep for those).")
    cmd("credsweep -u user -p pass -d corp.local -o eng",
        "AUTHENTICATED pass (needs -u/-p): credenum (netexec/impacket) + authenticated "
        "ldap/smb/mssql/ftp in one shot. Run once you have creds; see section 5.")

    section("3. Databases (optional) - deep DB enumeration")
    cmd("db -o eng", "Enumerate + vuln-scan discovered database services. Fills Databases.")

    section("4. Priv-esc playbook - per-host escalation guidance")
    cmd("privesc -o eng", "Build the Priv-Esc sheet from what's already known.")
    cmd("  --scan", "Also run remote priv-esc NSE checks against the hosts.")
    cmd("ingest loot.txt -o eng",
        "Fold findings from an on-target run of recce-enum.sh / recce-enum.ps1 "
        "(the [!] lines) into the Priv-Esc sheet. Point it at the saved -o/-OutFile.")

    section("5. Credentialed enum - authenticated power moves",
            "Two accounts are supported: a normal user does the enumeration; an "
            "optional privileged account runs the admin-only checks. Tip: "
            "`credsweep -u ... -p ... -d ...` runs credenum AND the authenticated "
            "ldap/smb/mssql/ftp modules in one shot.")
    cmd("credenum -u user -p pass -d corp.local -o eng",
        "Authenticated SMB/LDAP enum with the user account: shares, roasting, "
        "delegation, local-admin reach. Fills Users & Accounts, AD sheets.")
    cmd("  --admin-user adm --admin-pass P [--admin-domain D]",
        "Privileged account: confirms local-admin reach and dumps secrets "
        "(secretsdump). Each result is labelled by which account produced it.")
    cmd("  --ldap-enum / --ldap-anon / --ldap-ssl / --dc-ip IP",
        "Credentialed LDAP of the DC / anonymous bind / LDAPS / target a specific DC.")

    section("5b. Active Directory - import SharpHound + Certipy (offline analysis)",
            "Collect on the target with SharpHound and `certipy find -json`, bring the "
            "files back, then let recce map the vulns and the paths to Domain Admin.")
    cmd("ad loot.zip *_Certipy.json -u alice -p 'Passw0rd!' -d corp.local --dc-ip IP -o eng",
        "Parse SharpHound (.zip/dir/.json) and/or Certipy JSON - any mix, auto-detected. "
        "Fills AD Findings + AD Attack Paths, folds into the main severity totals + "
        "writeups. Every command is pre-filled with your credentials. No hash needed.")
    cmd("  --owned USER[,USER...]",
        "Override the path start set (default: your -u account, else any authenticated user).")
    cmd("  --replace-ad",
        "Clear the previously-imported AD/ESC findings first, so remediated items drop "
        "off on re-import (default: accumulate across imports).")

    section("5c. MSSQL - offensive SQL Server enumeration + attack chain",
            "recce probes SQL Browser + TDS pre-login itself (no creds); with creds it "
            "runs the nxc access/priv matrix and writes the MSSQLPwner-style runbook.")
    cmd("mssql -o eng",
        "Credential-free: SQL Browser (UDP 1434) instances + TDS pre-login version/"
        "encryption for every MSSQL host, plus the no-cred access checks (blank sa, relay).")
    cmd("mssql -u alice -p 'Passw0rd!' -d corp.local -o eng",
        "With creds: nxc access/privilege matrix (Pwn3d! = sysadmin), then live "
        "impacket-mssqlclient enumeration that DETECTS the actual escalation chain "
        "(impersonation / TRUSTWORTHY / linked-server) and RECURSIVELY WALKS the "
        "linked-server graph (EXEC AT) to every reachable sysadmin. Pre-filled; feeds "
        "the main totals.")
    cmd("  --local-auth / --lhost IP / --no-run",
        "SQL (not Windows) auth / your capture-relay IP for the UNC commands / write the "
        "commands without executing nxc/impacket (airgapped-safe).")
    cmd("  --link-depth N / --no-links",
        "Max linked-server chain depth to walk (default 4) / skip the recursive walk.")
    cmd("  --relay --lhost 10.10.14.5",
        "Trigger the SQL service account to authenticate to your box (xp_dirtree) so a "
        "running impacket-ntlmrelayx catches it - relay to the DC's LDAP, another MSSQL, "
        "or an SMB-signing-off host (targets listed on the MSSQL sheet).")
    cmd("  --exec 'whoami' --method xp|ole|agent|clr",
        "Run an OS command for effect and capture the output - xp_cmdshell, OLE "
        "Automation, or a SQL Agent job (clr hands off to mssqlpwner). Result is folded "
        "into the findings as confirmed RCE.")
    cmd("  --data",
        "Mine the databases: enumerate every table (+ row counts) and find sensitive "
        "columns/tables (passwords, PII, financial) across all databases.")
    cmd("  --perms",
        "Per-database object-permission mining: guest-enabled databases + exactly what "
        "public/guest can read/write/execute (every login inherits it).")
    cmd("  --prove-write",
        "Prove write + permission-modify impact REVERSIBLY: create a table, modify a "
        "field, toggle a role - capture before/after, then undo everything.")
    cmd("  --screenshots",
        "Capture terminal-style PROOF screenshots of executed actions (RCE output, "
        "write-proof, data mining) into engagement/screenshots/ for the walkthroughs.")

    section("5d. Additional services - SMB / FTP / Docker / Kubernetes / LDAP / SNMP / "
            "MongoDB / Redis / Elasticsearch / rsync / NFS",
            "Deep, per-service offensive enumeration. Each probes with recce's own "
            "stdlib code (no creds needed to start), folds findings into the main "
            "totals, and fills its own tab. Run the ones your enum turned up.")
    cmd("smb -o eng   [-u alice -p 'Passw0rd!' -d corp.local] [--prove-write]",
        "SMB: stdlib SMB2/SMBv1 negotiate posture (signing NOT required -> NTLM relay; "
        "SMBv1 -> EternalBlue surface), anonymous & credentialed share enumeration, and "
        "a reversible writable-share proof (drop a marker, list it, delete it).")
    cmd("ftp -o eng   [-u bob -p 'hunter2'] [--prove-write]",
        "FTP: banner / anonymous-login / AUTH-TLS posture, known-backdoor match (vsftpd "
        "2.3.4, ProFTPD mod_copy), and a reversible writable-directory proof.")
    cmd("docker -o eng   [--screenshots]",
        "Docker: read the Engine API (2375/2376) unauthenticated - a CONFIRMED exposed "
        "daemon is remote ROOT RCE on the host (recce only READS to prove it).")
    cmd("k8s -o eng",
        "Kubernetes: unauthenticated reads of the kubelet (exec-into-pods), "
        "kube-apiserver (anonymous LIST / Secrets = cluster compromise) and etcd "
        "(all cluster secrets in the clear).")
    cmd("ldap -o eng   [-u alice -p 'Passw0rd!' -d corp.local | --hash <NT>]",
        "LDAP: stdlib BER client anonymously binds, reads the RootDSE (domain / forest "
        "/ DC / functional level) and tests for anonymous directory read; flags cleartext "
        "389 as a credential-sniff / relay surface. WITH creds (password OR --hash for "
        "pass-the-hash via an NTLM SASL bind) it PAGES an authenticated enum (users / "
        "computers / domain) in-house and derives kerberoastable / AS-REP / delegation / "
        "privileged accounts straight into Users & Accounts + AD Quick Wins. Read-only.")
    cmd("snmp -o eng   [--no-probe]",
        "SNMP: guesses community strings over UDP 161, reads sysDescr / sysName, and "
        "walks the LanMgr user table, running processes and installed software - local "
        "accounts flow into Users & Accounts. Flags read-write communities by name. "
        "Read-only (never sends a SET).")
    cmd("mongodb -o eng   [--no-probe]",
        "MongoDB: speaks the wire protocol (OP_MSG/BSON), fingerprints with hello + "
        "buildInfo, then proves whether listDatabases answers with NO authentication - "
        "a CONFIRMED no-auth instance is full read/write to every database.")
    cmd("redis -o eng   [--no-probe]",
        "Redis: speaks RESP, fingerprints with PING + INFO, then proves whether INFO "
        "answers with NO authentication - a CONFIRMED no-auth instance is full "
        "read/write plus a CONFIG+SAVE file-write -> RCE primitive.")
    cmd("elasticsearch -o eng   [--no-probe]",
        "Elasticsearch: GETs the HTTP API, fingerprints via /, then proves whether "
        "/_cat/indices answers with NO authentication - a CONFIRMED no-auth cluster is "
        "unauthenticated read/write to every document.")
    cmd("rsync -o eng   [--no-probe]",
        "rsync daemon: lists the modules over the rsync protocol, then proves which "
        "answer @RSYNCD: OK with NO authentication - a CONFIRMED open module is "
        "unauthenticated read (often write) of every file it exposes.")
    cmd("nfs -o eng   [--no-probe]",
        "NFS: speaks ONC RPC to the portmapper + mountd (showmount -e), then flags any "
        "export shared to * / everyone - a CONFIRMED world-mountable export is readable "
        "by any host (and writable via no_root_squash).")
    cmd("kerberos -d DOMAIN -o eng   [--dc-ip IP] [--userlist f]",
        "Credential-less AD roasting: speaks Kerberos (no impacket) to AS-REP roast "
        "every pre-auth-disabled account (capture a crackable hash with NO credential) "
        "and validate usernames via the KDC - no logon, no lockouts.")

    section("6. Act on the findings - turn CONFIRMED findings into a plan",
            "Once findings are proven (Verification tab), stage the exploitation and "
            "pivot. These read the datastore and fill the Exploitation / Attack Path / "
            "Credentials tabs - no re-scan.")
    cmd("exploitplan -o eng --lhost <ip>",
        "Every CONFIRMED finding -> exact existing tool + command (your values filled "
        "in) + how to validate; also writes ready-to-run msf .rc + per-host plans to "
        "exploit-plan/. Fills the Exploitation tab.")
    cmd("attackpath -o eng",
        "Chain the confirmed findings into a staged path (foothold -> priv-esc -> "
        "creds -> lateral -> domain). Fills the Attack Path tab.")
    cmd("creds --add 'CORP\\alice:Passw0rd!' -o eng  /  creds --plan -o eng",
        "Stack captured credentials, then build the netexec/impacket spray plan. Fills "
        "the Credentials tab.")
    cmd("deploy -u U -p P -o eng",
        "Mass local-enum + priv-esc: run the read-only on-target scripts across every "
        "host you have creds for (SSH/WinRM/SMB), folded straight into Priv-Esc.")

    section("7. Report - turn findings into deliverables")
    cmd("writeups -o eng", "One Word (.docx) write-up per finding (web screenshots "
                           "auto-added when a browser is present). Finish each in Word.")
    cmd("report -o eng", "Rebuild this workbook + reports from the datastore "
                         "(preserves your ticks and notes).")
    cmd("status -o eng", "Print live review-coverage + per-service deep-dive coverage "
                         "and the suggested next command.")
    cmd("access -o eng", "Review which hosts you have a foothold on (auto-derived from "
                         "credentialed enum). Record one you got another way with "
                         "`access --host IP --note '...'` - it ticks the Access step.")

    section("On-target - run these ON a compromised host (read-only)",
            "Copy the script from recce/local/ to the target, self-test, then run "
            "and save the output; bring it back and `ingest` it (phase 4).")
    cmd("./recce-enum.sh -t", "Linux: self-test (parse-check + what will run). Safe first step.")
    cmd("./recce-enum.sh -o loot.txt", "Linux: full read-only sweep, saved to loot.txt.")
    cmd("powershell -ep bypass -File recce-enum.ps1 -SelfTest",
        "Windows: self-test only (no enumeration).")
    cmd("powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt",
        "Windows: full read-only sweep, saved to loot.txt.")

    # --- troubleshooting ---------------------------------------------------------
    sh.write([""])
    sh.write([("If something goes wrong", "title")])
    sh.write([("Run `doctor` first - it reports what's missing and self-tests the "
               "pipeline. Re-running any phase is safe (idempotent - never "
               "duplicates rows).", "sub")])
    sh.write([("Symptom", "header"), ("Fix", "header")])

    def fix(symptom, action):
        sh.write([(symptom, "wrap"), (action, "wrap")])

    fix("nmap not found", "Install nmap - the only hard requirement. Everything "
                          "else is optional and degrades cleanly.")
    fix("'Not running as root' / weak scan",
        "Run with sudo. Under sudo use `sudo ./bin/recce ...` so PATH/PYTHONPATH "
        "survive (SYN scan, OS detection and UDP need root).")
    fix("Discovery finds no hosts",
        "A firewall is dropping pings. Re-run `enum` with --no-discovery (-Pn: "
        "treat every target as up).")
    fix("Scans too slow",
        "--fast (masscan), --workers N, `vulns --fast` (top-signal + progress/ETA), "
        "--profile quick, --top-ports N, --host-timeout MIN.")
    fix("Crashed or interrupted",
        "Nothing is lost. Re-run with --resume, or `report -o eng` to rebuild from "
        "saved data. Set RECCE_DEBUG=1 for the full traceback.")
    fix("'No open ports match' on vulns",
        "Run `enum` first; --unscanned finds nothing once everything is scanned; "
        "widen or drop --only.")
    fix("No findings (but you expected some)",
        "Improve service ID on enum (--version-all / --version-intensity 9), then "
        "try `vulns --aggressive` for the full intrusive NSE category.")
    fix("credenum: no tools / auth table",
        "Install netexec + impacket (or ssh). In the table: FAIL = credential "
        "rejected (check user/pass/DOMAIN); ERR = unreachable/tool error; '-' = "
        "not attempted (a missing tool is never shown as FAIL).")
    fix("Workbook won't update / locked",
        "Close it in Excel/LibreOffice before a scan or `report` - an open file is "
        "locked. Your ticks and notes are read back on the next run.")
    fix("Web screenshots missing in write-ups",
        "Install firefox/chromium, or point RECCE_BROWSER at a browser; or use "
        "`writeups --no-screenshots` and add them in Word.")
    fix("Full guide",
        "See TROUBLESHOOTING.md in the project, or run `recce <command> -h` for "
        "every option.")

    sh.set_col(1, 46)
    sh.set_col(2, 82)


def _bar(pct: int) -> str:
    filled = round(pct / 10)
    return "▓" * filled + "░" * (10 - filled)


def _build_overview(wb, hosts: list[Host], meta: dict, domains: list[Domain],
                    tracking: Tracking, scope: dict, issues: list | None = None,
                    nav: list[str] | None = None,
                    host_rows: dict | None = None) -> None:
    """One summary tab: engagement totals, review progress, and (prominently)
    live-hosts-per-subnet coverage. Doubles as a navigation hub - the jump bar
    and several totals are clickable links to the matching sheet."""
    sh = wb.add_sheet("Overview")
    nav = nav or []
    open_ports = [p for h in hosts for p in h.open_ports]
    win = sum(1 for h in hosts if "windows" in (h.os_family or h.os_name).lower())
    lin = sum(1 for h in hosts if "linux" in (h.os_family or h.os_name).lower())
    crit = sum(1 for h in hosts for v in h.vulns if v.severity in ("critical", "high"))
    # Confirmed-up vs scanned-but-unconfirmed. The Checklist shows only the confirmed
    # set; the unconfirmed count is surfaced here so a host is never silently dropped.
    up_hosts = [h for h in hosts if h.is_up]
    unconfirmed = len(hosts) - len(up_hosts)

    sh.write([("Engagement Overview", "title")])
    sh.write([(meta.get("subtitle", ""), "sub")])
    sh.write([""])

    # --- Navigation hub: a clickable jump bar to every populated sheet ---
    if nav:
        sh.write([("Jump to", "header")])
        link_row = sh.nrows + 1
        sh.write([(t, "link") for t in nav])
        for ci, title in enumerate(nav, start=1):
            sh.link_to(link_row, ci, title)
        sh.write([""])

    # --- Scan issues (front and centre so nothing failed silently) ---
    issues = issues or []
    if issues:
        errs = sum(1 for i in issues if i.get("level") == "error")
        warns = len(issues) - errs
        sh.write([(f"⚠ SCAN ISSUES: {errs} error(s), {warns} incomplete - "
                   f"review before trusting coverage (full log: recce.log)",
                   "boldred")])
        sh.write([("When", "bold"), ("Host", "bold"), ("Phase", "bold"),
                  ("Level", "bold"), ("What happened", "bold")])
        for i in issues[:40]:
            lvl = i.get("level", "warning")
            sh.write([i.get("ts", ""), i.get("ip", ""), i.get("phase", ""),
                      (lvl.upper(), "sev_high" if lvl == "error" else "sev_medium"),
                      i.get("message", "")])
        if len(issues) > 40:
            sh.write([("", None), (f"... and {len(issues) - 40} more (see recce.log)",
                                   "sub")])
        sh.set_col(5, 70)
        sh.write([""])

    # --- Totals (several labels link straight to the relevant sheet) ---
    sh.write([("Totals", "header"), ("", "header")])
    nav_set = set(nav)
    proven = sum(1 for h in hosts for v in h.vulns if _curated_exploit(v))
    from . import proofs
    confirmed = sum(1 for r in proofs.verify_hosts(hosts)
                    if r["verdict"] == proofs.CONFIRMED)
    _links = {
        "Hosts confirmed up (on Checklist)": "Checklist",
        "Open service ports": "Services",
        "Vuln findings": "Vulnerabilities", "High / Critical findings": "Vulnerabilities",
        "Confirmed by recce (prove engine)": "Verification",
        "Findings with a curated exploit": "Vulnerabilities",
        "Candidate exploits": "Exploits", "Domains / DCs": "Active Directory",
        "NTLM relay targets": "AD Quick Wins",
        "Kerberoastable / AS-REP": "AD Quick Wins",
    }
    for label, val in [
        ("Hosts confirmed up (on Checklist)", len(up_hosts)),
        ("Windows / Linux", f"{win} / {lin}"),
        ("Open service ports", len(open_ports)),
        ("Vuln findings", sum(len(h.vulns) for h in hosts)),
        ("High / Critical findings", crit),
        ("Confirmed by recce (prove engine)", confirmed),
        ("Findings with a curated exploit", proven),
        ("Candidate exploits", sum(len(h.exploits) for h in hosts)),
        ("Domains / DCs", f"{len(domains or ad.derive_domains(hosts))} / "
                          f"{len(ad.domain_controllers(hosts))}"),
        ("NTLM relay targets", len(ad.relay_targets(hosts))),
        ("Kerberoastable / AS-REP", f"{len(ad.kerberoastable(hosts))} / "
                                    f"{len(ad.asrep_roastable(hosts))}"),
        ("Hosts with AV / EDR seen", sum(1 for h in hosts if h.defenses)),
    ]:
        target = _links.get(label)
        if target in nav_set:
            r = sh.nrows + 1
            sh.write([(label, "link"), val])
            sh.link_to(r, 1, target)
        else:
            sh.write([(label, "bold"), val])
    if unconfirmed:
        # Not hidden away: these IPs were scanned but returned no proof of life, so
        # they're kept off the Checklist. Flagged here so nobody assumes they're down.
        sh.write([("Scanned, not confirmed up (kept off Checklist)", "bold"),
                  unconfirmed])
        sh.write([("These IPs answered no TCP probe and no UDP liveness ping - treat "
                   "as UNKNOWN, not down. A slower/wider re-scan (more UDP ports, a "
                   "higher --host-timeout) may still surface a heavily firewalled "
                   "host.", "sub")])
    sh.write([""])

    # --- Credentialed access matrix (only when credenum has run) ---
    cred_hosts = [h for h in hosts if getattr(h, "cred_enumerated", False)]
    if cred_hosts:
        def _has(h, needle):
            return any(needle in v.title for v in h.vulns)
        sh.write([("Credentialed access matrix (per account)", "header"),
                  ("", "header"), ("", "header"), ("", "header"), ("", "header")])
        sh.write([("Host", "bold"), ("User acct", "bold"),
                  ("User = admin", "bold"), ("Priv acct = admin", "bold"),
                  ("Hashes dumped", "bold")])
        for h in sorted(cred_hosts, key=lambda x: _ip_sort_key(x.ip)):
            user_admin = _has(h, "Local admin confirmed - user account")
            priv_admin = _has(h, "Local admin confirmed - privileged account")
            dumped = _has(h, "Credential hashes dumped")
            yes, no = ("✓", "done"), "—"
            name = f"{h.ip}" + (f" ({h.hostname})" if h.hostname else "")
            sh.write([name, "✓",
                      yes if user_admin else no,
                      yes if priv_admin else no,
                      yes if dumped else no])
        sh.write([("✓ = access confirmed via netexec (Pwn3d!) / secretsdump; "
                   "a User=admin tick means the low-priv account is over-privileged.",
                   "sub")])
        sh.write([""])

    # --- Review progress ---
    sh.write([("Review progress (what you've ticked off)", "header"),
              ("", "header"), ("", "header"), ("", "header")])
    cov = tr.compute_coverage(hosts, tracking)
    labels = {"hosts": "Hosts", "services": "Services", "vulns": "Vulnerabilities",
              "web": "Web", "exploits": "Exploits", "quick_wins": "AD Quick Wins",
              "accounts": "Users & Accounts"}
    o = cov["overall"]
    sh.write([("OVERALL", "bold"), (f"{o['done']}/{o['total']}", "bold"),
              (f"{o['pct']}%", "bold"), (_bar(o["pct"]), "bold")])
    for cat in tr.COVERAGE_CATEGORIES:
        c = cov[cat]
        sh.write([labels.get(cat, cat), f"{c['done']}/{c['total']}",
                  f"{c['pct']}%", _bar(c["pct"])])
    sh.write([""])

    # --- Coverage by subnet (live hosts + auto phase completion) ---
    # Only the tool-completed surfaces belong here; AD review and the kill-chain
    # markers are manual sign-offs, tracked per host on the Checklist.
    sh.write([("Coverage by subnet - live hosts and phase completion", "header"),
              ("", "header"), ("", "header"), ("", "header"), ("", "header"),
              ("", "header"), ("", "header"), ("", "header")])
    sh.write([("Subnet", "bold"), ("In range", "bold"), ("Live hosts", "bold"),
              ("Enumerated", "bold"), ("Vuln-scanned", "bold"), ("Web", "bold"),
              ("DB", "bold"), ("# Vulns", "bold")])
    # Only confirmed-up hosts count here, so this table agrees exactly with the
    # Checklist (which also shows only up hosts). Unconfirmed IPs are tallied
    # separately in the Totals block, never folded into a subnet's "Live hosts".
    agg: dict[str, list] = defaultdict(list)
    for h in hosts:
        if h.is_up:
            agg[h.subnet or "unknown"].append(h)

    def cell(done, total):
        # Denominator counts only hosts the step applies to, so "x/y" reflects
        # real coverage of that surface (blank when the surface is absent).
        if not total:
            return ""
        return (f"{done}/{total}", "done") if done == total else \
               (f"{done}/{total}", "sev_medium") if done else f"{done}/{total}"

    def phase(hs, step):
        applic = [h for h in hs if tr.step_applies(h, step)]

        def done(h):
            # Honor an operator tick/un-tick the same way the Checklist does, so
            # the two tables can't disagree; fall back to tool auto-progress.
            k = tr.step_key(step, h.ip)
            return tracking[k][0] if k in tracking else tr.step_auto(h, step)
        return cell(sum(1 for h in applic if done(h)), len(applic))

    for sn in sorted(set(agg) | set(scope or {}), key=_subnet_sort_key):
        hs = agg.get(sn, [])
        sh.write([sn, (scope or {}).get(sn, ""), len(hs),
                  phase(hs, "enum"), phase(hs, "vuln"), phase(hs, "web"),
                  phase(hs, "db"), sum(len(h.vulns) for h in hs)])
    for col, w in {1: 26, 2: 10, 3: 11, 4: 12, 5: 13, 6: 8, 7: 8, 8: 8}.items():
        sh.set_col(col, w)
    sh.write([""])

    # --- Host index: click an IP to jump straight to its Checklist row ---
    host_rows = host_rows or {}
    if host_rows:
        sh.write([("Host index - click an IP to jump to its Checklist row",
                   "header"), ("", "header"), ("", "header"), ("", "header"),
                  ("", "header")])
        sh.write([("IP", "bold"), ("Hostname", "bold"), ("OS", "bold"),
                  ("Open ports", "bold"), ("# Vulns", "bold")])
        by_ip = {h.ip: h for h in hosts}
        # List in Checklist row order (host_rows maps ip -> that sheet's row).
        for ip, crow in sorted(host_rows.items(), key=lambda kv: kv[1]):
            h = by_ip.get(ip)
            if h is None:
                continue
            r = sh.nrows + 1
            sh.write([(ip, "link"), h.hostname, h.os_guess,
                      len(h.open_ports), len(h.vulns)])
            sh.link_to(r, 1, CHECKLIST_TITLE, cell=f"A{crow}")


def _build_active_directory(wb, hosts: list[Host], domains: list[Domain]) -> None:
    if not domains and not ad.domain_controllers(hosts):
        return
    sh = wb.add_sheet("Active Directory")
    sh.write([("Active Directory Overview", "title")])
    sh.write([""])
    for dom in domains or ad.derive_domains(hosts):
        sh.write([(f"Domain: {dom.name}", "boldred")])
        facts = [
            ("NetBIOS", dom.netbios),
            ("Forest / functional level", f"{dom.forest} / {dom.functional_level}".strip(" /")),
            ("Naming context", dom.naming_context),
            ("Domain Controllers", ", ".join(dom.dc_ips)),
            ("Machine account quota", dom.machine_account_quota),
            ("Anonymous LDAP bind", "YES" if dom.anonymous_bind else "no"),
            ("Sources", ", ".join(dom.sources)),
        ]
        if dom.password_policy:
            facts.append(("Password policy",
                          "; ".join(f"{k}={v}" for k, v in dom.password_policy.items())))
        for label, val in facts:
            if not val and val != "no":
                continue
            style = None
            if label == "Anonymous LDAP bind" and dom.anonymous_bind:
                style = "sev_high"
            elif label == "Machine account quota" and str(val) not in ("0", ""):
                style = "sev_low"
            sh.write([(label, "bold"), (val, style) if style else val])
        if dom.trusts:
            sh.write([("Trusts", "bold")])
            for t in dom.trusts:
                sh.write(["", f"{t.get('name')} ({t.get('direction')}, type {t.get('type')})"])
        sh.write([""])
    sh.set_col(1, 26)
    sh.set_col(2, 70)



def _build_ad_findings(wb, analysis: dict) -> None:
    """AD misconfigurations / vulnerabilities from a SharpHound import - one row per
    finding, most-severe first, each with the exact prove/abuse command."""
    findings = (analysis or {}).get("findings") or []
    if not findings:
        return
    sh = wb.add_sheet("AD Findings")
    sh.write([("Active Directory - Findings (from BloodHound/SharpHound)", "title")])
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    sh.write([("  ".join(f"{k}: {counts[k]}" for k in
               ("critical", "high", "medium", "low") if counts.get(k)), "bold")])
    sh.write([""])
    headers = ["Severity", "Category", "Finding", "Principal", "Target", "Detail",
               "Tool", "Prove / abuse command", "Remediation"]
    sh.write([(h, "bold") for h in headers])
    for f in findings:
        style = _SEV_STYLE.get(f["severity"])
        sh.write([(f["severity"].upper(), style), f["category"], f["title"],
                  f["principal"], f["target"], f["detail"], f["tool"],
                  f["command"], f["remediation"]])
    for i, w in enumerate((10, 12, 34, 26, 22, 46, 22, 70, 44), start=1):
        sh.set_col(i, w)


def _build_ad_paths(wb, analysis: dict) -> None:
    """AD attack paths (owned/low-priv principal -> Domain Admin / domain / DC) and,
    when a credential was supplied, the Kerberos actions to run for effect."""
    paths = (analysis or {}).get("paths") or []
    kerb = (analysis or {}).get("kerberos") or []
    if not paths and not kerb:
        return
    sh = wb.add_sheet("AD Attack Paths")
    sh.write([("Active Directory - Attack Paths to Domain Admin", "title")])
    sh.write([("Shortest privilege-escalation paths grounded in the collected graph. "
               "Walk each edge with the named EXISTING tool.", "sub")])
    sh.write([""])
    for i, p in enumerate(paths, start=1):
        who = "ANY authenticated user" if p.get("any_user") else p["start"]
        head = f"Path {i}: {who} -> {p['target']}  ({p['length']} hop(s))"
        sh.write([(head, "boldred" if p["length"] <= 2 else "bold")])
        sh.write(["", p["chain"]])
        for st in p["steps"]:
            sh.write(["", f"[{st['label']}] {st['src']} -> {st['dst']}:  {st['abuse']}"])
        sh.write([""])
    if kerb:
        sh.write([("Kerberos actions (for effect - with the supplied credential/hash)",
                   "title")])
        for a in kerb:
            sh.write([(a["title"], "bold")])
            sh.write(["", a["command"]])
            sh.write(["", a["why"]])
            sh.write([""])
    sh.set_col(1, 4)
    sh.set_col(2, 120)


def _write_findings_table(sh, fs) -> None:
    """The per-service 'Findings' table + 'Finding details' narrative block, shared by
    all five deep-service sheets (they wrote this identical block five times)."""
    if not fs:
        return
    sh.write([("Findings", "title")])
    sh.write([(h, "bold") for h in
              ("Severity", "Finding", "Target", "Detail", "Prove / abuse command",
               "Remediation")])
    for f in fs:
        sh.write([(f["severity"].upper(), _SEV_STYLE.get(f["severity"])),
                  f["title"], f["target"], f.get("detail", ""),
                  f.get("command", ""), f.get("remediation", "")])
    sh.write([""])
    if any(f.get("narrative") for f in fs):
        sh.write([("Finding details - what each issue enables", "title")])
        seen_narr = set()
        for f in fs:
            narr = f.get("narrative")
            key = (f["title"], f["target"])
            if not narr or key in seen_narr:
                continue
            seen_narr.add(key)
            sh.write([(f"[{f['severity'].upper()}] {f['title']}  ({f['target']})",
                       "bold")])
            sh.write(["", narr])
        sh.write([""])


def _build_mssql(wb, analysis: dict) -> None:
    """MSSQL offensive sheet: endpoints (version/encryption/access/priv), findings,
    and the credential-free + credentialed runbook with the attack chain."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import mssql as _mssql
    sh = wb.add_sheet("MSSQL")
    sh.write([("Microsoft SQL Server - offensive enumeration & attack chain", "title")])
    sh.write([("Pre-auth probes are recce's own (SQL Browser + TDS pre-login); "
               "authenticated actions reference nxc / impacket / mssqlpwner.", "sub")])
    sh.write([""])
    # How MSSQL is tested - methodology narrative so the reader understands each phase.
    sh.write([("How MSSQL is tested", "title")])
    for phase, text in _mssql.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    # Endpoints.
    sh.write([("Endpoints", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Version", "Encryption", "Access", "Privilege", "Instances")])
    for t in tgts:
        acc = "yes" if t.get("access") else ("" if t.get("access") is None else "no")
        priv = "SYSADMIN" if t.get("admin") else ("login" if t.get("access") else "")
        style = "sev_critical" if t.get("admin") else None
        sh.write([f"{t['ip']}:{t['port']}",
                  _mssql_vname(t.get("version")), t.get("encryption", ""),
                  acc, (priv, style) if style else priv,
                  ", ".join(i.get("instance", "") for i in t.get("instances") or [])])
    sh.write([""])
    _write_findings_table(sh, fs)
    # Runbook + chain, per endpoint.
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        for line in rb.get("chain") or []:
            sh.write(["", line])
        live = rb.get("live")
        if live:
            sh.write([("Live enumeration (impacket-mssqlclient)", "bold")])
            sh.write(["", f"Login: {live.get('login', '')}"
                      + ("  [SYSADMIN]" if live.get("is_sysadmin") else "")])
            if live.get("sysadmins"):
                sh.write(["", "Sysadmins: " + ", ".join(live["sysadmins"][:12])])
            if live.get("trustworthy"):
                conf = set(live.get("dbowner_confirmed") or [])
                sh.write(["", "TRUSTWORTHY DBs: " + ", ".join(
                    db + (" [db_owner - CONFIRMED privesc]" if db in conf else "")
                    for db in live["trustworthy"][:12])])
            if live.get("links"):
                sh.write(["", "Linked servers: " + ", ".join(live["links"][:12])])
            if live.get("impersonate"):
                sh.write(["", "Impersonatable: " + ", ".join(live["impersonate"][:12])])
            if live.get("config"):
                sh.write(["", "Config: " + ", ".join(f"{k}={v}"
                          for k, v in live["config"].items())])
            if live.get("hashes"):
                sh.write(["", f"Recovered {len(live['hashes'])} SQL login hash(es): "
                          + ", ".join(live["hashes"][:12])])
            if live.get("credentials"):
                sh.write(["", "Stored credentials: " + ", ".join(live["credentials"][:12])])
            if live.get("proxies"):
                sh.write(["", "Agent proxies: " + ", ".join(live["proxies"][:12])])
            if live.get("linkedlogins"):
                sh.write(["", "Linked logins: " + ", ".join(live["linkedlogins"][:12])])
        graph = rb.get("linkgraph")
        if graph:
            sa = sum(1 for n in graph if n.get("sysadmin"))
            sh.write([(f"Linked-server graph ({len(graph)} reachable, {sa} as sysadmin)",
                       "bold")])
            for n in graph:
                route = " -> ".join(["entry"] + n.get("path", []))
                tag = "  [SYSADMIN]" if n.get("sysadmin") else ""
                who = f"  as {n.get('login', '')}" if n.get("login") else ""
                sh.write(["", f"{route}   ({n.get('server', '')}{who}){tag}"])
        mined = rb.get("datamine")
        if mined:
            total = sum(len(v.get("tables") or []) for v in mined.values())
            sh.write([(f"Data mining ({len(mined)} db, {total} tables)", "bold")])
            for db, v in mined.items():
                line = f"{db}: {len(v.get('tables') or [])} table(s)"
                if v.get("interesting"):
                    line += "  |  SENSITIVE COLUMNS: " + ", ".join(v["interesting"][:10])
                sh.write(["", line])
        perms = rb.get("permmine")
        if perms:
            guest = [db for db, v in perms.items() if v.get("guest")]
            sh.write([(f"Object permissions (guest enabled in {len(guest)} db)", "bold")])
            for db, v in perms.items():
                bits = []
                if v.get("guest"):
                    bits.append("GUEST ENABLED")
                for principal, perm, obj in (v.get("grants") or [])[:8]:
                    bits.append(f"{principal}:{perm} {obj}")
                if bits:
                    sh.write(["", f"{db}: " + "  |  ".join(bits)])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"{step['step']}  [{step['tool']}]"])
            sh.write(["", f"    {step['cmd']}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _mssql_vname(ver: str) -> str:
    from . import mssql
    return mssql.version_name(ver) if ver else ""


def _build_smb(wb, analysis: dict) -> None:
    """SMB offensive sheet: per-endpoint posture (dialect / signing / SMBv1),
    findings, live anonymous share enumeration + write proofs, and the credential-
    free + credentialed runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import smb as _smb
    sh = wb.add_sheet("SMB")
    sh.write([("SMB / file sharing - offensive enumeration & attack surface", "title")])
    sh.write([("Pre-auth posture (dialect, signing, SMBv1) is recce's own stdlib "
               "negotiate probe; anonymous/credentialed enumeration references "
               "nxc / smbclient / impacket.", "sub")])
    sh.write([""])
    sh.write([("How SMB is tested", "title")])
    for phase, text in _smb.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    # Endpoints + posture.
    sh.write([("Endpoints", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Product", "Dialect", "Signing", "SMBv1")])
    for t in tgts:
        req = t.get("signing_required")
        signing = "required" if req else ("NOT REQUIRED" if req is False else "")
        sstyle = "sev_medium" if req is False else None
        v1 = t.get("smbv1")
        v1cell = ("ENABLED", "sev_high") if v1 else ("no" if v1 is False else "")
        sh.write([f"{t['ip']}:{t['port']}", t.get("product", ""),
                  t.get("dialect", ""),
                  (signing, sstyle) if sstyle else signing, v1cell])
    sh.write([""])
    _write_findings_table(sh, fs)
    # Runbook + live results, per endpoint.
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        live = rb.get("live")
        if live:
            sess = live.get("session") or ""
            if sess:
                sh.write([("Anonymous / credentialed session", "bold")])
                sh.write(["", sess])
            shares = live.get("shares") or []
            if shares:
                sh.write([(f"Shares ({len(shares)})", "bold")])
                for s in shares:
                    sh.write(["", f"{s.get('name', '')}  [{s.get('perms', '') or '-'}]"])
            writable = live.get("writable") or []
            for w in writable:
                sh.write([(f"WRITABLE share PROVEN: {w.get('share', '')}", "bold")])
                if w.get("evidence"):
                    sh.write(["", w["evidence"]])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_ftp(wb, analysis: dict) -> None:
    """FTP offensive sheet: per-endpoint posture (banner / anonymous / AUTH TLS),
    findings, and the credential-free + credentialed runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import ftp as _ftp
    sh = wb.add_sheet("FTP")
    sh.write([("FTP - offensive enumeration & attack surface", "title")])
    sh.write([("Banner, anonymous-login and AUTH-TLS posture are recce's own stdlib "
               "control-channel probe; the write proof uses stdlib ftplib.", "sub")])
    sh.write([""])
    sh.write([("How FTP is tested", "title")])
    for phase, text in _ftp.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Endpoints", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Banner", "Anonymous", "AUTH TLS", "System")])
    for t in tgts:
        anon = t.get("anonymous")
        anoncell = ("YES", "sev_high") if anon else ("no" if anon is False else "")
        tls = t.get("auth_tls")
        tlscell = "yes" if tls else ("NO", "sev_medium") if tls is False else ""
        sh.write([f"{t['ip']}:{t['port']}", t.get("banner", ""),
                  anoncell, tlscell, t.get("syst", "")])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        live = rb.get("live")
        if live and live.get("writable"):
            sh.write([("WRITABLE directory PROVEN", "bold")])
            sh.write(["", live.get("evidence", "")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_docker(wb, analysis: dict) -> None:
    """Docker offensive sheet: exposed daemons, workload inventory, findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import docker as _docker
    sh = wb.add_sheet("Docker")
    sh.write([("Docker Engine API - offensive enumeration & attack surface", "title")])
    sh.write([("An unauthenticated Docker API is remote root RCE on the host. recce "
               "reads the API (stdlib HTTP) to prove exposure; it never creates a "
               "container.", "sub")])
    sh.write([""])
    sh.write([("How Docker is tested", "title")])
    for phase, text in _docker.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Endpoints", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Exposed", "Daemon", "Host", "Containers", "Images")])
    for t in tgts:
        exp = t.get("exposed")
        expcell = ("YES", "sev_critical") if exp else ("no" if exp is False else "?")
        sh.write([f"{t['ip']}:{t['port']}", expcell, t.get("version", ""),
                  t.get("name", ""),
                  "" if t.get("containers") is None else str(t.get("containers")),
                  "" if t.get("images") is None else str(t.get("images"))])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_kubernetes(wb, analysis: dict) -> None:
    """Kubernetes offensive sheet: per-surface exposure (kubelet/apiserver/etcd),
    findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import kubernetes as _k8s
    sh = wb.add_sheet("Kubernetes")
    sh.write([("Kubernetes - offensive attack-surface enumeration", "title")])
    sh.write([("Unauthenticated reads of the kubelet, kube-apiserver and etcd (recce's "
               "own stdlib HTTP probe). recce only READS - it never execs or writes.",
               "sub")])
    sh.write([""])
    sh.write([("How Kubernetes is tested", "title")])
    for phase, text in _k8s.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Endpoints", "title")])
    sh.write([(h, "bold") for h in ("IP:Port", "Surface", "Exposure", "Detail")])
    for t in tgts:
        role = t.get("role", "")
        exposed = (t.get("anon_pods") or t.get("anon_list")
                   or t.get("v2_readable") or t.get("v3_readable"))
        expcell = ("EXPOSED", "sev_critical") if exposed else \
            ("reachable" if t.get("reachable") else "?")
        detail = ""
        if role.startswith("kubelet") and t.get("pod_count") is not None:
            detail = f"{t['pod_count']} pod(s) readable"
        elif role == "apiserver":
            detail = t.get("version", "")
            if t.get("anon_secrets"):
                detail += "  | secrets listable"
        elif role == "etcd":
            detail = t.get("etcd_version", "")
        sh.write([f"{t['ip']}:{t['port']}", role, expcell, detail])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']} ({rb.get('role', '')})", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_ldap(wb, analysis: dict) -> None:
    """LDAP / AD directory sheet: per-DC RootDSE (domain/forest/DC/functional level),
    anonymous bind + anonymous-read posture, findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import ldap as _ldap
    sh = wb.add_sheet("LDAP")
    sh.write([("LDAP / Active Directory - offensive directory enumeration", "title")])
    sh.write([("recce speaks LDAP directly (stdlib BER/ASN.1): an anonymous bind, a "
               "RootDSE read, an anonymous naming-context read, and - with creds - a "
               "paged authenticated enumeration (users/computers/domain -> Users & "
               "Accounts + AD Quick Wins). Read-only - it never writes to the directory.",
               "sub")])
    sh.write([""])
    sh.write([("How LDAP is tested", "title")])
    for phase, text in _ldap.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Directory endpoints", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Anon read", "Domain", "DC (dnsHostName)",
               "Functional level", "Enumerated (auth)")])
    for t in tgts:
        if t.get("anon_read"):
            anon = ("ANON READ", "sev_high")
        elif t.get("anon_bind"):
            anon = ("anon bind", "sev_medium")
        else:
            anon = "no"
        lvl = f"Server {t['dc_level']}" if t.get("dc_level") else ""
        if t.get("auth_ok"):
            enum = (f"{t.get('auth_users', 0)} users, {t.get('kerberoastable', 0)} kerb, "
                    f"{t.get('asrep', 0)} AS-REP, {t.get('unconstrained_deleg', 0)} uncon-deleg")
        elif t.get("auth_error"):
            enum = f"auth failed: {t['auth_error']}"
        else:
            enum = "(anonymous only - pass -u/-p to enumerate)"
        sh.write([f"{t['ip']}:{t['port']}", anon, t.get("domain", ""),
                  t.get("dc_dns", ""), lvl, enum])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_snmp(wb, analysis: dict) -> None:
    """SNMP sheet: per-agent community/RW posture, exposed users, findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import snmp as _snmp
    sh = wb.add_sheet("SNMP")
    sh.write([("SNMP - offensive UDP enumeration", "title")])
    sh.write([("recce speaks SNMP v2c directly (stdlib BER over UDP): it guesses "
               "community strings, reads sysDescr/sysName, and walks the LanMgr user "
               "table, running processes and installed software. Local accounts flow "
               "into Users & Accounts. Read-only - it never sends a SET.", "sub")])
    sh.write([""])
    sh.write([("How SNMP is tested", "title")])
    for phase, text in _snmp.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Agents", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Community", "Access", "System", "Users")])
    for t in tgts:
        comm = t.get("community")
        commcell = (comm, "sev_medium") if comm else "(no answer)"
        access = ("READ-WRITE", "sev_high") if t.get("rw_likely") else \
            ("read-only" if comm else "")
        sh.write([f"{t['ip']}:{t['port']}", commcell, access,
                  t.get("sys_name", ""),
                  "" if not t.get("users") else str(t.get("users"))])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_mongodb(wb, analysis: dict) -> None:
    """MongoDB sheet: per-instance auth posture, version, exposed databases,
    findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import mongodb as _mongo
    sh = wb.add_sheet("MongoDB")
    sh.write([("MongoDB - offensive enumeration", "title")])
    sh.write([("recce speaks the MongoDB wire protocol directly (stdlib OP_MSG/BSON): "
               "hello + buildInfo to fingerprint, then listDatabases to prove whether "
               "the instance answers privileged commands without authentication. "
               "Read-only - it never writes or drops.", "sub")])
    sh.write([""])
    sh.write([("How MongoDB is tested", "title")])
    for phase, text in _mongo.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Instances", "title")])
    sh.write([(h, "bold") for h in
              ("IP:Port", "Auth", "Version", "Databases")])
    for t in tgts:
        if t.get("unauth"):
            authcell = ("NO AUTH", "sev_critical")
        elif t.get("version"):
            authcell = ("auth required", "sev_medium")
        else:
            authcell = "?"
        sh.write([f"{t['ip']}:{t['port']}", authcell, t.get("version", ""),
                  "" if not t.get("databases") else str(t.get("databases"))])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_redis(wb, analysis: dict) -> None:
    """Redis sheet: per-instance auth posture, version, key count, findings, runbook."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import redis as _redis
    sh = wb.add_sheet("Redis")
    sh.write([("Redis - offensive enumeration", "title")])
    sh.write([("recce speaks the Redis wire protocol directly (stdlib RESP): PING + "
               "INFO to fingerprint, then INFO with no credential to prove whether the "
               "instance answers without authentication. On an exposed instance it "
               "reads (never sets) CONFIG dir/dbfilename/requirepass - the file-write "
               "-> RCE preconditions. Read-only.", "sub")])
    sh.write([""])
    sh.write([("How Redis is tested", "title")])
    for phase, text in _redis.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Instances", "title")])
    sh.write([(h, "bold") for h in ("IP:Port", "Auth", "Version", "Keys")])
    for t in tgts:
        if t.get("unauth"):
            authcell = ("NO AUTH", "sev_critical")
        elif t.get("auth_required"):
            authcell = ("auth required", "sev_medium")
        else:
            authcell = "?"
        sh.write([f"{t['ip']}:{t['port']}", authcell, t.get("version", ""),
                  "" if not t.get("keys") else str(t.get("keys"))])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_elasticsearch(wb, analysis: dict) -> None:
    """Elasticsearch sheet: per-cluster auth posture, version, index count, findings."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import elasticsearch as _es
    sh = wb.add_sheet("Elasticsearch")
    sh.write([("Elasticsearch - offensive enumeration", "title")])
    sh.write([("recce GETs the Elasticsearch HTTP API directly (stdlib http.client): / "
               "to fingerprint the cluster/version, then /_cat/indices with no "
               "credential to prove whether the cluster is exposed unauthenticated. "
               "Read-only - only GETs, never indexes/updates/deletes.", "sub")])
    sh.write([""])
    sh.write([("How Elasticsearch is tested", "title")])
    for phase, text in _es.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Clusters", "title")])
    sh.write([(h, "bold") for h in ("IP:Port", "Auth", "Version", "Indices")])
    for t in tgts:
        if t.get("unauth"):
            authcell = ("NO AUTH", "sev_critical")
        elif t.get("secured"):
            authcell = ("security enforced", "sev_medium")
        else:
            authcell = "?"
        sh.write([f"{t['ip']}:{t['port']}", authcell, t.get("version", ""),
                  "" if not t.get("indices") else str(t.get("indices"))])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_rsync(wb, analysis: dict) -> None:
    """rsync sheet: per-daemon module list, anonymous-access verdict, findings."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import rsync as _rsync
    sh = wb.add_sheet("rsync")
    sh.write([("rsync daemon - offensive enumeration", "title")])
    sh.write([("recce speaks the rsync daemon protocol directly (stdlib): it lists the "
               "modules with #list, then for each opens a fresh connection and reads "
               "the @RSYNCD: OK / AUTHREQD verdict - proving which modules are readable "
               "with no credential. Read-only - it never transfers a file.", "sub")])
    sh.write([""])
    sh.write([("How rsync is tested", "title")])
    for phase, text in _rsync.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Modules", "title")])
    sh.write([(h, "bold") for h in ("Host:Port", "Module", "Access", "Comment")])
    for t in tgts:
        pr = (analysis.get("probes") or {}).get(f"{t['ip']}:{t['port']}") or {}
        mods = pr.get("modules") or []
        if not mods:
            sh.write([f"{t['ip']}:{t['port']}", "(none listed)", "", ""])
        for m in mods:
            acc = m.get("access")
            cell = ("OPEN (no auth)", "sev_high") if acc == "open" else \
                (("auth required", "sev_medium") if acc == "auth" else "?")
            sh.write([f"{t['ip']}:{t['port']}", m.get("name", ""), cell,
                      m.get("comment", "")])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_nfs(wb, analysis: dict) -> None:
    """NFS sheet: per-host export list, world-mountable flag, findings."""
    analysis = analysis or {}
    tgts = analysis.get("targets") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not tgts and not fs:
        return
    from . import nfs as _nfs
    sh = wb.add_sheet("NFS")
    sh.write([("NFS / mountd - offensive enumeration", "title")])
    sh.write([("recce speaks ONC RPC directly (stdlib): the portmapper DUMP on 111 "
               "lists the RPC services, then MOUNTPROC_EXPORT reads every export and "
               "its client ACL (the showmount -e equivalent). An export shared to * / "
               "everyone is mountable by any host. Read-only - it never mounts.", "sub")])
    sh.write([""])
    sh.write([("How NFS is tested", "title")])
    for phase, text in _nfs.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([("Exports", "title")])
    sh.write([(h, "bold") for h in ("Host", "Export", "Shared to", "Exposure")])
    for t in tgts:
        pr = (analysis.get("probes") or {}).get(t["ip"]) or {}
        exports = pr.get("exports") or []
        if not exports:
            sh.write([t["ip"], "(none listed)", "", ""])
        for e in exports:
            groups = e.get("groups") or []
            world = _nfs._is_world(groups)
            shared = ", ".join(groups) if groups else "(everyone)"
            cell = ("WORLD-mountable", "sev_high") if world else ("restricted", "sev_low")
            sh.write([t["ip"], e.get("dir", ""), shared, cell])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 22)
    sh.set_col(2, 120)


def _build_kerberos(wb, analysis: dict) -> None:
    """Kerberos sheet: per-user AS-REP roast / validation results + findings."""
    analysis = analysis or {}
    results = analysis.get("results") or []
    fs = analysis.get("findings") or []
    runbooks = analysis.get("runbooks") or []
    if not results and not fs:
        return
    from . import kerberos as _krb
    sh = wb.add_sheet("Kerberos")
    sh.write([("Kerberos - credential-less AD roasting", "title")])
    sh.write([("recce speaks Kerberos directly (stdlib ASN.1 DER, no impacket): for "
               "each candidate user it sends a pre-auth-less AS-REQ to the DC. An "
               "AS-REP back means pre-auth is disabled - recce captures a crackable "
               "$krb5asrep$ hash with NO credential; a PREAUTH_REQUIRED error confirms "
               "a valid username. It only requests tickets - no logon, no lockouts.",
               "sub")])
    sh.write([""])
    sh.write([("How Kerberos is tested", "title")])
    for phase, text in _krb.TESTING_NARRATIVE:
        sh.write([(phase, "bold")])
        sh.write(["", text])
    sh.write([""])
    sh.write([(f"DC {analysis.get('dc_ip', '')}  realm {analysis.get('realm', '')}",
               "bold")])
    sh.write([(h, "bold") for h in ("Username", "Result", "etype")])
    _state = {"roastable": ("AS-REP ROASTABLE", "sev_high"),
              "valid": ("valid (pre-auth)", "sev_low"),
              "locked": ("valid (locked/expired)", "sev_medium"),
              "unknown_user": "does not exist", "error": "error", "no_reply": "no reply"}
    for r in results:
        cell = _state.get(r["state"], r["state"])
        sh.write([r["user"], cell, str(r.get("etype", "")) if r.get("etype") else ""])
    sh.write([""])
    _write_findings_table(sh, fs)
    for rb in runbooks:
        sh.write([(f"Runbook - {rb['target']}", "boldred")])
        cur = None
        for step in (rb.get("credfree") or []) + (rb.get("credentialed") or []):
            if step["phase"] != cur:
                cur = step["phase"]
                sh.write([(cur, "bold")])
            sh.write(["", f"[{step['tool']}]  {step.get('command', '')}"])
        sh.write([""])
    sh.set_col(1, 24)
    sh.set_col(2, 120)


# --- public entry points --------------------------------------------------------

def _spec_credentials(hosts: list[Host], creds_stored: list | None = None) -> SheetSpec:
    """The stacked credential set (auto-harvested + manually captured), ready to
    spray. Empty (sheet skipped) until there are credentials. `recce creds --plan`
    writes the users/passwords/hashes files + the netexec/impacket spray commands."""
    from . import credentials as cr
    stacked = cr.stack(hosts, creds_stored or [])
    cols = [
        ("Worked", "checkbox", 9), ("User", "data", 22), ("Domain", "data", 14),
        ("Kind", "data", 10), ("Secret", "data", 34), ("Source", "data", 14),
        ("Captured on", "data", 15), ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    rows = [{"key": f"cred:{c.dedupe_key()}", "data": {
        "User": c.username, "Domain": c.domain, "Kind": c.kind,
        "Secret": c.secret or "(blank)", "Source": c.source,
        "Captured on": c.origin_ip, "Notes": c.notes}}
        for c in stacked]
    return SheetSpec("Credentials", cols, rows, skip_if_empty=True)


def _ordered_specs(hosts: list[Host], scope: dict | None = None,
                   creds_stored: list | None = None):
    """The spec-based sheets, split into the groups build_workbook interleaves with
    the computed sheets so the final left-to-right order follows the engagement flow:

        orient -> track -> find -> per-service deep-dive -> AD -> loot -> act -> post-ex

    Returns (pre, ad_specs, tail):
      * pre  - orient/track/find: Checklist, Services, Web, Vulnerabilities, Exploits,
               Verification, Services by Product, Databases.
      * ad_specs - the two spec-based AD sheets (AD Quick Wins, Users & Accounts) that
               build_workbook slots INTO the AD cluster so it stays contiguous with the
               computed Active Directory / AD Findings / AD Attack Paths sheets.
      * tail - loot + act + post-exploitation: Credentials, Exploitation, Attack Path,
               Priv-Esc, Priv-Esc Playbook, Raw NSE. Exploitation/Attack Path precede
               Priv-Esc (you exploit -> foothold -> then escalate).

    Rationale for the pairings you flip between:
      * Checklist <-> Services  - host <-> its open ports (the working pair).
      * Services <-> Vulnerabilities <-> Verification - port -> finding -> is-it-real.
      * Vulnerabilities -> Services by Product - "who else runs this?" pivot.
      * Databases + MSSQL/SMB/FTP/Docker/Kubernetes/LDAP/SNMP/MongoDB - the per-service
        deep-dive band.
      * Active Directory <-> AD Quick Wins <-> AD Findings/Paths <-> Users & Accounts.
    """
    pre = [_spec_checklist(hosts), _spec_services(hosts), _spec_web(hosts),
           _spec_vulns(hosts), _spec_exploits(hosts), _spec_verification(hosts),
           _spec_services_by_product(hosts), _spec_databases(hosts)]
    ad_specs = {"quick_wins": _spec_quick_wins(hosts),
                "accounts": _spec_accounts(hosts)}
    tail = [_spec_credentials(hosts, creds_stored),
            _spec_exploitation(hosts), _spec_attackpath(hosts),
            _spec_privesc(hosts), _spec_privesc_playbook(hosts),
            _spec_raw_nse(hosts)]
    return pre, ad_specs, tail


def build_workbook(hosts: list[Host], out_path: str, meta: dict | None = None,
                   domains: list[Domain] | None = None,
                   tracking: Tracking | None = None,
                   order_map: dict | None = None,
                   scope: dict | None = None,
                   statuses: dict | None = None,
                   issues: list | None = None,
                   credentials: list | None = None) -> str:
    meta = meta or {}
    domains = domains or []
    tracking = tracking or {}
    order_map = order_map or {}
    statuses = statuses or {}
    wb = xlsx.Workbook()
    pre, ad_specs, tail = _ordered_specs(hosts, scope, credentials)
    quick_wins_spec, accounts_spec = ad_specs["quick_wins"], ad_specs["accounts"]
    # Which sheets will actually exist (skip_if_empty ones may not), in the SAME
    # left-to-right order they'll be emitted below, so the Overview's jump bar only
    # links to sheets that are really there. Flow: find -> per-service deep-dive ->
    # AD cluster (contiguous) -> loot/act/post-ex.
    ad_present = bool(domains or ad.domain_controllers(hosts))
    bh = meta.get("ad_bloodhound") or {}

    def _mod(key):
        m = meta.get(key) or {}
        return bool(m.get("targets") or m.get("findings"))

    def _spec_here(spec):
        return not (spec.skip_if_empty and not spec.rows)

    nav = [s.title for s in pre if _spec_here(s)]
    # Service deep-dive band (Databases is the last of `pre`, immediately before).
    for key, title in (("mssql", "MSSQL"), ("smb", "SMB"), ("ftp", "FTP"),
                       ("docker", "Docker"), ("kubernetes", "Kubernetes"),
                       ("ldap", "LDAP"), ("snmp", "SNMP"),
                       ("mongodb", "MongoDB"), ("redis", "Redis"),
                       ("elasticsearch", "Elasticsearch"), ("rsync", "rsync"),
                       ("nfs", "NFS"), ("kerberos", "Kerberos")):
        if _mod(key):
            nav.append(title)
    # AD cluster, kept contiguous.
    if ad_present:
        nav.append("Active Directory")
    if _spec_here(quick_wins_spec):
        nav.append(quick_wins_spec.title)
    if bh.get("findings"):
        nav.append("AD Findings")
    if bh.get("paths") or bh.get("kerberos"):
        nav.append("AD Attack Paths")
    if _spec_here(accounts_spec):
        nav.append(accounts_spec.title)
    nav += [s.title for s in tail if _spec_here(s)]

    # Pre-compute each host's Checklist row so the Overview can deep-link an IP
    # straight to it. Uses the SAME ordering the Checklist writer will use, so the
    # links land on the right rows. The header sits on row 1 normally, or row 2 when
    # a legend line precedes it - mirror that offset here.
    checklist_spec = next((s for s in pre if s.title == CHECKLIST_TITLE), None)
    host_rows: dict[str, int] = {}
    if checklist_spec:
        ck_keys = _ordered_keys(checklist_spec.rows, order_map.get(CHECKLIST_TITLE))
        by_key = {r["key"]: r for r in checklist_spec.rows}
        key_ip = {k: r["data"]["IP"] for k, r in by_key.items()}
        grouped = bool(checklist_spec.group_by)
        header_row = 2 if checklist_spec.legend else 1
        excel_row = header_row
        if grouped:
            # Bucket by group EXACTLY as _write_spec does: a host appended into an
            # already-seen subnet is re-grouped under it, so a linear walk of ck_keys
            # (where new keys land at the tail) would mis-count rows. Same bucketing =
            # same rows, so the Overview links always land on the right Checklist row.
            buckets: dict[str, list[str]] = {}
            for k in ck_keys:
                buckets.setdefault(by_key[k].get("group", ""), []).append(k)
            for _gv, keys in buckets.items():
                excel_row += 1                   # the subnet band row
                for k in keys:
                    excel_row += 1
                    if k in key_ip:
                        host_rows[key_ip[k]] = excel_row
        else:
            for k in ck_keys:
                excel_row += 1
                if k in key_ip:
                    host_rows[key_ip[k]] = excel_row

    def _emit(spec):
        if spec.skip_if_empty and not spec.rows:
            return
        _write_spec(wb.add_sheet(spec.title), spec, tracking,
                    order_map.get(spec.title), statuses)

    _build_guide(wb, meta)
    _build_runbook(wb, meta)
    _build_overview(wb, hosts, meta, domains, tracking, scope, issues or [], nav,
                    host_rows)
    # orient/track/find (ends on Databases).
    for spec in pre:
        _emit(spec)
    # Per-service deep-dive band, right after Databases.
    _build_mssql(wb, meta.get("mssql") or {})
    _build_smb(wb, meta.get("smb") or {})
    _build_ftp(wb, meta.get("ftp") or {})
    _build_docker(wb, meta.get("docker") or {})
    _build_kubernetes(wb, meta.get("kubernetes") or {})
    _build_ldap(wb, meta.get("ldap") or {})
    _build_snmp(wb, meta.get("snmp") or {})
    _build_mongodb(wb, meta.get("mongodb") or {})
    _build_redis(wb, meta.get("redis") or {})
    _build_elasticsearch(wb, meta.get("elasticsearch") or {})
    _build_rsync(wb, meta.get("rsync") or {})
    _build_nfs(wb, meta.get("nfs") or {})
    _build_kerberos(wb, meta.get("kerberos") or {})
    # AD cluster, kept contiguous: inventory -> quick wins -> import findings/paths
    # -> users & accounts.
    _build_active_directory(wb, hosts, domains)
    _emit(quick_wins_spec)
    _build_ad_findings(wb, bh)
    _build_ad_paths(wb, bh)
    _emit(accounts_spec)
    # loot -> act (exploit/chain) -> post-ex -> raw evidence.
    for spec in tail:
        _emit(spec)
    # Colour the computed (non-spec) sheets' tabs too, so the whole tab bar is
    # grouped into role bands.
    for sh in wb.sheets:
        if sh.tab_color is None:
            sh.tab_color = TAB_COLORS.get(sh.title)
    wb.save(out_path)
    return out_path


def update_workbook(path: str, hosts: list[Host], meta: dict | None = None,
                    domains: list[Domain] | None = None,
                    tracking: Tracking | None = None,
                    scope: dict | None = None,
                    statuses: dict | None = None,
                    issues: list | None = None,
                    credentials: list | None = None) -> str:
    """Regenerate preserving existing row order (new rows appended) + tracking.

    The tool re-lays-out the sheet each time; the operator's checkboxes, notes and
    row order are preserved via read-back. (Manual cell formatting the operator
    adds is not preserved - track via the checkbox/Notes columns.)
    """
    order_map = read_key_order(path) if os.path.exists(path) else {}
    return build_workbook(hosts, path, meta, domains, tracking, order_map, scope,
                          statuses, issues, credentials)


def _header_index(rows: list[list[str]], *must_have: str) -> int:
    """Row index of the column-header row: the first row that contains every token
    in `must_have`. Sheets normally put headers on row 0, but a legend/note line can
    push them down (e.g. the Checklist), so we locate them instead of assuming row 0.
    Falls back to 0 when nothing matches, preserving the old behaviour."""
    for i, r in enumerate(rows):
        if all(tok in r for tok in must_have):
            return i
    return 0


def read_key_order(path: str) -> dict[str, list[str]]:
    """{sheet_title: [keys in current row order]} from an existing workbook."""
    order: dict[str, list[str]] = {}
    try:
        sheets = xlsx.read_sheets(path)
    except Exception:
        return order
    for title, rows in sheets.items():
        if not rows:
            continue
        hidx = _header_index(rows, "Key")
        header = rows[hidx]
        if "Key" not in header:
            continue
        kidx = header.index("Key")
        order[title] = [r[kidx] for r in rows[hidx + 1:] if len(r) > kidx and r[kidx]]
    return order


def read_workbook_edits(path: str) -> tuple[Tracking, dict]:
    """Parse operator edits once. Returns ({key: (reviewed, notes)}, {key: status})
    where `status` holds the per-port tri-state from any Status column."""
    result: Tracking = {}
    statuses: dict = {}
    try:
        sheets = xlsx.read_sheets(path)
    except Exception:
        return result, statuses
    def as_bool(v) -> bool:
        s = str(v).strip()
        return s == xlsx.CHECK_ON or s.upper() in ("TRUE", "1", "X", "YES", "DONE")

    for title, rows in sheets.items():
        if not rows:
            continue
        # Per-host step checkboxes live only on the Checklist (other sheets have
        # a same-named "Vuln-scan" text column that must NOT be read as steps). The
        # Checklist carries a legend line above its header, so find the header row.
        if title == CHECKLIST_TITLE:
            chidx = _header_index(rows, "IP")
            cheader = rows[chidx]
            if "IP" in cheader:
                ipc = cheader.index("IP")
                step_cols = [(cheader.index(h), s) for h, s in tr.STEP_COLUMNS.items()
                             if h in cheader]
                for r in rows[chidx + 1:]:
                    if len(r) <= ipc or not r[ipc]:
                        continue
                    ip = str(r[ipc])
                    for ci, step in step_cols:
                        if ci >= len(r):
                            continue
                        cell = str(r[ci]).strip()
                        if not cell or cell == tr.STEP_NA:
                            continue  # N/A step - not a real checkbox, never an override
                        result[tr.step_key(step, ip)] = (as_bool(r[ci]), "")

        hidx = _header_index(rows, "Key")
        header = rows[hidx]
        if "Key" not in header:
            continue
        kidx = header.index("Key")
        cbidx = next((i for i, h in enumerate(header) if h in CHECKBOX_HEADERS), None)
        stidx = next((i for i, h in enumerate(header) if h in STATUS_HEADERS), None)
        nidx = header.index("Notes") if "Notes" in header else None
        for r in rows[hidx + 1:]:
            if len(r) <= kidx or not r[kidx]:
                continue
            key = str(r[kidx])
            note = r[nidx] if (nidx is not None and nidx < len(r)) else ""
            status = ""
            if stidx is not None and stidx < len(r):
                status = str(r[stidx]).strip()
            # reviewed comes from a real checkbox, or from a tri-state Status == Done.
            if cbidx is not None and cbidx < len(r):
                reviewed = as_bool(r[cbidx])
            elif status:
                reviewed = status == STATUS_DONE
            else:
                reviewed = False
            if status:
                statuses[key] = status
            # A key can appear on more than one sheet (e.g. Checklist + Hosts both
            # carry host:<ip>). Combine: reviewed if ticked anywhere; keep a note.
            prev = result.get(key)
            if prev:
                result[key] = (prev[0] or reviewed, prev[1] or note)
            else:
                result[key] = (reviewed, note)
    return result, statuses


def read_workbook_tracking(path: str) -> Tracking:
    """{key: (reviewed_bool, notes)} for every row carrying a Key value."""
    return read_workbook_edits(path)[0]
