"""Architecture / network map from the enumeration.

Turns what recce OBSERVED — hosts, subnets, service roles, AD domains and trusts —
into a directly-viewable, self-contained **SVG** (renders in any browser, no tools or
JavaScript, prints to PDF — airgap-native). It is a *logical* map: recce enumerates each
host independently and does not trace physical routing, VLANs or firewall rules, so the
only edges drawn are relationships it actually saw (a host's subnet, a DC's domain, a
domain trust). Nothing is inferred that wasn't observed.
"""
from __future__ import annotations

import re

from .models import Host
from . import ad
from . import web
from . import db as dbmod
from . import smb

_MAIL_PORTS = {25, 465, 587, 110, 143, 993, 995}
_ROLE_ORDER = ["DC", "DB", "Web", "Mail", "File/SMB", "Workstation", "Host"]


def _ipkey(ip):
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


_CLIENT_OS = ("windows 10", "windows 11", "windows 7", "windows 8",
              "windows xp", "windows vista")


def roles_for(host: Host) -> list[str]:
    """Every role tag that applies to a host, from its confirmed open services."""
    ports = host.open_ports
    is_client = any(w in (host.os_name or "").lower() for w in _CLIENT_OS)
    tags: list[str] = []
    if "Domain Controller" in (host.roles or []):
        tags.append("DC")
    if dbmod.db_ports(host):
        tags.append("DB")
    if any(web.is_web(p) for p in ports):
        tags.append("Web")
    if any(p.portid in _MAIL_PORTS for p in ports):
        tags.append("Mail")
    # SMB on a *server* OS is a File/SMB role; on a client OS it is just ordinary
    # Windows workstation sharing (445 is open on every domain-joined workstation),
    # so a plain client reads as a Workstation, not a file server — otherwise every
    # workstation in the estate is mislabelled File/SMB.
    if "DC" not in tags and not is_client and any(smb.is_smb(p) for p in ports):
        tags.append("File/SMB")
    if not tags:
        tags.append("Workstation" if is_client else "Host")
    return tags


def primary_role(host: Host) -> str:
    tags = set(roles_for(host))
    for r in _ROLE_ORDER:
        if r in tags:
            return r
    return "Host"


# --- enrichment from SharpHound / other findings --------------------------------

def ad_dc_names(ad) -> set:
    """Short, upper-cased Domain Controller names from a BloodHound analysis blob
    (the tier-0 architecture). Used to *confirm* which enumerated hosts are DCs from
    AD ground-truth — a DC that only had 445 open still gets marked."""
    arch = (ad or {}).get("architecture") or {} if isinstance(ad, dict) else {}
    out = set()
    for n in (arch.get("nodes") or {}).values():
        if n.get("dc") and n.get("label"):
            out.add(str(n["label"]).split(".")[0].upper())
    return out


def _host_short(host: Host) -> str:
    hn = host.hostname or ""
    return hn.split(".")[0].upper() if hn else ""


def role_with_ad(host: Host, dc_names: set) -> str:
    """Primary role, but promoted to DC when SharpHound says this host is a DC."""
    if dc_names and _host_short(host) in dc_names:
        return "DC"
    return primary_role(host)


_SEV_ORDER = ["critical", "high", "medium", "low"]


def worst_severity(host: Host) -> str:
    """Highest severity among the host's *confirmed* vulns (excludes unverified
    'potential' version guesses), or '' if none. Grounds the map's risk overlay."""
    best = ""
    from . import qod
    for v in getattr(host, "vulns", []) or []:
        if not qod.is_visible(v):      # single QoD authority (was: confidence == potential)
            continue
        sev = (getattr(v, "severity", "") or "").lower()
        if sev in _SEV_ORDER and (best == "" or
                                  _SEV_ORDER.index(sev) < _SEV_ORDER.index(best)):
            best = sev
    return best


def has_access(host: Host) -> bool:
    return bool(getattr(host, "access_gained", False))


def real_hostname(host: Host) -> str:
    """The host's DNS name only when it ADDS information — '' when it's empty or just
    the IP re-punctuated (e.g. '10-0-10-10'), so a tile never prints the IP twice."""
    hn = (host.hostname or "").strip()
    if not hn or hn == host.ip:
        return ""
    if re.sub(r"\D", "", hn) == re.sub(r"\D", "", host.ip or "") and re.sub(r"\D", "", hn):
        return ""                                  # same digits as the IP -> IP-derived
    return hn


def os_short(host: Host) -> str:
    """A compact OS label for a tile (no accuracy %), '' if unknown."""
    return (host.os_name or "").strip()


def summary(hosts: list[Host], domains=None, ad_data=None) -> list[str]:
    """A short, grounded description of the architecture, for the report/CLI."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ["No hosts enumerated yet."]
    dc_names = ad_dc_names(ad_data)
    subnets = sorted({h.subnet or "unknown" for h in up}, key=_ipkey)
    counts: dict[str, int] = {}
    for h in up:
        r = role_with_ad(h, dc_names)
        counts[r] = counts.get(r, 0) + 1
    roles = ", ".join(f"{n}× {r}" for r, n in
                      sorted(counts.items(), key=lambda kv: _ROLE_ORDER.index(kv[0])))
    doms = domains or ad.derive_domains(up)
    lines = [f"{len(up)} host(s) across {len(subnets)} network segment(s): {roles}."]
    # Status overlay from findings: what we own and where the risk is.
    accessed = [h for h in up if has_access(h)]
    risky = [h for h in up if worst_severity(h) in ("critical", "high")]
    status = []
    if accessed:
        status.append(f"{len(accessed)} with confirmed access")
    if risky:
        status.append(f"{len(risky)} with critical/high findings")
    if status:
        lines.append("Status: " + ", ".join(status) + ".")
    if doms:
        dparts = []
        for d in doms:
            dcs = ", ".join(d.dc_ips) if getattr(d, "dc_ips", None) else "no DC seen"
            dparts.append(f"{d.name} (DC: {dcs})")
        lines.append("AD domain(s): " + "; ".join(dparts) + ".")
    if dc_names:
        confirmed = sorted({_host_short(h) for h in up if _host_short(h) in dc_names})
        if confirmed:
            lines.append("AD-confirmed Domain Controller(s) from BloodHound: "
                         + ", ".join(confirmed) + ".")
    return lines


_ROLE_COLOR = {
    "DC": ("#fbe3e3", "#C00000"), "DB": ("#e7eefb", "#1f4e9c"),
    "Web": ("#e8f4ec", "#2E7D32"), "Mail": ("#fbf3e0", "#9C7A00"),
    "File/SMB": ("#eef1f1", "#5f6f6e"), "Workstation": ("#f3eefb", "#6b4fa0"),
    "Host": ("#ffffff", "#8a9997"),
}
_DOMAIN_COLOR = ("#fff6e6", "#C15A11")


def _x(s, n=30):
    from html import escape as _e
    s = re.sub(r"\s+", " ", (s or "").strip())
    if len(s) > n:
        s = s[: n - 1] + "…"
    return _e(s)


_SEV_DOT = {"critical": "#C00000", "high": "#E8863D"}
_ACCESS_STROKE = "#2E7D32"        # green outline for a host we hold access to
# Severity -> (colour, chip label) for the outline risk chip on a host tile.
_SEV_CHIP = {"critical": ("#C00000", "CRIT"), "high": ("#E8863D", "HIGH"),
             "medium": ("#C99A00", "MED"), "low": ("#6f7a78", "LOW")}


def host_tile(x, y, w, h, *, kind, role, ip, hostname="", subline="", stroke="#8a9997",
              fill="#ffffff", risk="", owned=False):
    """One host as a compact tile — a soft role-tinted header band (device icon + role),
    a faintly role-tinted body with the IP, an optional real hostname and a subline
    (OS or note), an outline severity chip and an 'owned' ✓. Shared by the network map
    and the reachability map so every host reads the same. Returns SVG markup."""
    from html import escape as _e
    hh, r = 22, 8
    cx = x + w / 2
    out = [
        # body: faint role tint + role-coloured border
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{stroke}" '
        f'fill-opacity="0.06"/>',
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="none" '
        f'stroke="{stroke}" stroke-width="{2 if owned else 1.4}"/>',
        # header band (rounded top only) at ~20% role wash + a hairline divider
        f'<path d="M{x},{y + hh} v-{hh - r} a{r},{r} 0 0 1 {r},-{r} h{w - 2 * r} '
        f'a{r},{r} 0 0 1 {r},{r} v{hh - r} z" fill="{stroke}" fill-opacity="0.20"/>',
        f'<line x1="{x}" y1="{y + hh}" x2="{x + w}" y2="{y + hh}" stroke="{stroke}" '
        f'stroke-opacity="0.35" stroke-width="1"/>',
        glyph(kind, x + 7, y + 3, 16, stroke),
    ]
    # right-side badges in the header: outline severity chip, then owned ✓
    rx = x + w - 6
    if risk in _SEV_CHIP:
        col, lab = _SEV_CHIP[risk]
        cw = 34
        out.append(f'<rect x="{rx - cw:.0f}" y="{y + 4}" width="{cw}" height="14" rx="7" '
                   f'fill="{fill}" stroke="{col}" stroke-width="1.2"/>')
        out.append(f'<text x="{rx - cw / 2:.0f}" y="{y + 14}" text-anchor="middle" '
                   f'font-size="9" font-weight="700" fill="{col}">{lab}</text>')
        rx -= cw + 5
    if owned:
        out.append(f'<circle cx="{rx - 7:.0f}" cy="{y + 11}" r="7" '
                   f'fill="{_ACCESS_STROKE}"/>')
        out.append(f'<text x="{rx - 7:.0f}" y="{y + 14.5:.0f}" text-anchor="middle" '
                   f'font-size="9.5" font-weight="700" fill="#fff">✓</text>')
        rx -= 18
    # role label, truncated to whatever the badges left free
    role_chars = max(4, int((rx - (x + 26)) / 7))
    out.append(f'<text x="{x + 26}" y="{y + 15}" font-size="11" font-weight="700" '
               f'fill="{stroke}">{_x(role, role_chars)}</text>')
    # body: IP, optional hostname, subline
    ty = y + hh + 18
    out.append(f'<text x="{cx:.0f}" y="{ty}" text-anchor="middle" font-size="12.5" '
               f'font-weight="700" fill="#1a2422">{_x(ip, 22)}</text>')
    if hostname:
        ty += 14
        out.append(f'<text x="{cx:.0f}" y="{ty}" text-anchor="middle" font-size="10.5" '
                   f'fill="#3a4644">{_x(hostname, 26)}</text>')
    if subline:
        ty += 14
        out.append(f'<text x="{cx:.0f}" y="{ty}" text-anchor="middle" font-size="10" '
                   f'fill="#6f7a78">{_x(subline, 30)}</text>')
    return "".join(out)


def _wrap(els, W, H, label="Network map"):
    return (f'<svg viewBox="0 0 {int(W)} {int(H)}" width="{int(W)}" height="{int(H)}" '
            f'role="img" aria-label="{label}" '
            f'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            + "".join(els) + "</svg>")


def _map_legend(x, y, any_access, any_risk):
    """Shared legend: role swatches, then a severity-chip key and the owned key.
    Returns (svg markup, bottom_y)."""
    from html import escape as _e
    out = [f'<text x="{x}" y="{y}" font-size="11" fill="#5f6f6e">Role:</text>']
    lx = x + 42
    for role in _ROLE_ORDER:
        fill, stroke = _ROLE_COLOR[role]
        out.append(f'<rect x="{lx}" y="{y - 10}" width="12" height="12" rx="2" '
                   f'fill="{fill}" stroke="{stroke}"/>')
        out.append(f'<text x="{lx + 17}" y="{y}" font-size="11" fill="#3a4644">'
                   f'{_e(role)}</text>')
        lx += 30 + len(role) * 7
    y2 = y
    if any_risk or any_access:
        y2 = y + 22
        lx = x
        if any_risk:
            out.append(f'<rect x="{lx}" y="{y2 - 11}" width="34" height="14" rx="7" '
                       f'fill="#ffffff" stroke="#C00000" stroke-width="1.2"/>')
            out.append(f'<text x="{lx + 17}" y="{y2 - 1}" text-anchor="middle" '
                       f'font-size="9" font-weight="700" fill="#C00000">CRIT</text>')
            out.append(f'<text x="{lx + 42}" y="{y2}" font-size="11" fill="#3a4644">'
                       f'worst confirmed finding (CRIT / HIGH / MED / LOW)</text>')
            lx += 340
        if any_access:
            out.append(f'<circle cx="{lx + 7}" cy="{y2 - 4}" r="7" '
                       f'fill="{_ACCESS_STROKE}"/>')
            out.append(f'<text x="{lx + 7}" y="{y2}" text-anchor="middle" '
                       f'font-size="9.5" font-weight="700" fill="#fff">✓</text>')
            out.append(f'<text x="{lx + 19}" y="{y2}" font-size="11" fill="#3a4644">'
                       f'access gained</text>')
    return "".join(out), y2


def _role_counts_line(rows, dc_names):
    counts = {}
    for h in rows:
        r = role_with_ad(h, dc_names)
        counts[r] = counts.get(r, 0) + 1
    return " · ".join(f"{counts[r]} {r}" for r in _ROLE_ORDER if r in counts)


def svg(hosts, domains=None, ad_data=None, aggregate=None):
    """A directly-viewable inline SVG network map (renders in any browser, no tools).

    Full map: each network segment is a bordered panel with its hosts laid out in a
    multi-column grid (device icon + role header, IP, hostname, OS, a severity chip and
    an owned check per host). `aggregate` None auto-collapses a large estate (>50 hosts)
    to a compact per-role overview; True/False force overview / full."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 320 60" width="320" height="60" role="img" '
                'aria-label="Network map"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    dc_names = ad_dc_names(ad_data)
    by_subnet = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)
    subnets = sorted(by_subnet, key=_ipkey)
    doms = domains or ad.derive_domains(up)
    aggregate = (len(up) > 50) if aggregate is None else aggregate
    if aggregate:
        return _svg_overview(up, by_subnet, subnets, doms, dc_names)
    return _svg_full(up, by_subnet, subnets, doms, dc_names)


def _svg_overview(up, by_subnet, subnets, doms, dc_names):
    """Compact >50-host overview: subnet columns of per-role counts + a legend."""
    from html import escape as _e
    colW, cardW, cardH, cardGap, colGap = 200, 186, 32, 10, 26
    m = 20
    any_access = any(has_access(h) for h in up)
    any_risk = any(worst_severity(h) in _SEV_CHIP for h in up)
    els = [f'<text x="{m}" y="{m + 18}" font-size="17" font-weight="700" '
           f'fill="#0f766e">Network map <tspan font-size="11.5" font-weight="400" '
           f'fill="#5f6f6e">· overview by role ({len(up)} hosts)</tspan></text>']
    top = m + 36
    max_rows = 0
    for ci, sub in enumerate(subnets):
        rows = sorted(by_subnet[sub], key=lambda z: _ipkey(z.ip))
        x = m + ci * (colW + colGap)
        els.append(f'<text x="{x}" y="{top + 14}" font-size="13" font-weight="700" '
                   f'fill="#115e59">{_x(sub, 20)} <tspan fill="#5f6f6e" '
                   f'font-weight="400">({len(rows)})</tspan></text>')
        owned = sum(1 for h in rows if has_access(h))
        if owned:
            els.append(f'<text x="{x + cardW}" y="{top + 14}" text-anchor="end" '
                       f'font-size="11" font-weight="700" fill="{_ACCESS_STROKE}">'
                       f'✓ {owned} owned</text>')
        y = top + 30
        counts = {}
        for h in rows:
            r = role_with_ad(h, dc_names)
            counts[r] = counts.get(r, 0) + 1
        k = 0
        for role in _ROLE_ORDER:
            if role not in counts:
                continue
            fill, stroke = _ROLE_COLOR[role]
            els.append(f'<rect x="{x}" y="{y}" width="{cardW}" height="{cardH}" rx="7" '
                       f'fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
            els.append(glyph(role_kind(role), x + 8, y + cardH / 2 - 8, 16, stroke))
            els.append(f'<text x="{x + 30}" y="{y + 20}" font-size="12" '
                       f'font-weight="700" fill="#1a2422">{counts[role]}× '
                       f'{_e(role)}</text>')
            y += cardH + cardGap
            k += 1
        max_rows = max(max_rows, k)
    dom_y = top + 30 + max_rows * (cardH + cardGap) + 6
    for di, d in enumerate(doms or []):
        dx = m + di * (colW + colGap)
        els.append(f'<rect x="{dx}" y="{dom_y}" width="{cardW}" height="30" rx="15" '
                   f'fill="{_DOMAIN_COLOR[0]}" stroke="{_DOMAIN_COLOR[1]}" '
                   f'stroke-width="1.4"/>')
        els.append(f'<text x="{dx + cardW / 2}" y="{dom_y + 19}" text-anchor="middle" '
                   f'font-size="11.5" font-weight="700" fill="#7a3a0a">AD: '
                   f'{_x(d.name, 22)}</text>')
    leg_y = (dom_y + 30 if doms else dom_y) + 30
    leg, y2 = _map_legend(m, leg_y, any_access, any_risk)
    els.append(leg)
    W = max(m + len(subnets) * (colW + colGap), m + 720)
    return _wrap(els, W, y2 + 18)


def _svg_full(up, by_subnet, subnets, doms, dc_names):
    """Full per-host map: one bordered panel per subnet, hosts in a multi-column grid."""
    from html import escape as _e
    cardW, cardH, gap = 186, 78, 14
    m, ppad, hbar, NCOL = 22, 16, 34, 5
    innerW = NCOL * cardW + (NCOL - 1) * gap
    PAGE_W = m * 2 + ppad * 2 + innerW
    pw = PAGE_W - 2 * m
    any_access = any(has_access(h) for h in up)
    any_risk = any(worst_severity(h) in _SEV_CHIP for h in up)

    els = []
    y = m
    els.append(f'<text x="{m}" y="{y + 20}" font-size="17" font-weight="700" '
               f'fill="#0f766e">Network map</text>')
    els.append(f'<text x="{m}" y="{y + 38}" font-size="11.5" fill="#5f6f6e">'
               f'{_x(summary(up, doms)[0], (pw - 10) // 6)}</text>')
    y += 52
    if doms:
        parts = []
        for d in doms:
            dcs = ", ".join(d.dc_ips) if getattr(d, "dc_ips", None) else "no DC seen"
            parts.append(f"{d.name} (DC: {dcs})")
        els.append(f'<rect x="{m}" y="{y}" width="{pw}" height="26" rx="6" '
                   f'fill="{_DOMAIN_COLOR[0]}" stroke="{_DOMAIN_COLOR[1]}"/>')
        els.append(f'<text x="{m + 12}" y="{y + 17}" font-size="11" font-weight="700" '
                   f'fill="#7a3a0a">AD domain(s): '
                   f'{_x("  ·  ".join(parts), (pw - 120) // 6)}</text>')
        y += 40

    for sub in subnets:
        rows = sorted(by_subnet[sub], key=lambda z: _ipkey(z.ip))
        n = len(rows)
        ncol = min(NCOL, n)
        nrow = -(-n // ncol)
        panelH = hbar + ppad + nrow * cardH + (nrow - 1) * gap + ppad
        els.append(f'<rect x="{m}" y="{y}" width="{pw}" height="{panelH}" rx="10" '
                   f'fill="#fafcfb" stroke="#dfe5e3"/>')
        els.append(f'<path d="M{m},{y + hbar} v-{hbar - 10} a10,10 0 0 1 10,-10 '
                   f'h{pw - 20} a10,10 0 0 1 10,10 v{hbar - 10} z" fill="#eef3f2"/>')
        els.append(f'<text x="{m + 14}" y="{y + 22}" font-size="13" font-weight="700" '
                   f'fill="#115e59">{_x(sub, 22)} <tspan fill="#5f6f6e" '
                   f'font-weight="400">· {n} host{"s" if n != 1 else ""}</tspan></text>')
        rl = _role_counts_line(rows, dc_names)
        owned = sum(1 for h in rows if has_access(h))
        if owned:
            rl += f"    ✓ {owned} owned"
        els.append(f'<text x="{m + pw - 14}" y="{y + 22}" text-anchor="end" '
                   f'font-size="10.5" fill="#5f6f6e">{_x(rl, (pw - 260) // 6)}</text>')
        gx0, gy0 = m + ppad, y + hbar + ppad
        for i, h in enumerate(rows):
            r, c = divmod(i, ncol)
            hx = gx0 + c * (cardW + gap)
            hy = gy0 + r * (cardH + gap)
            role = role_with_ad(h, dc_names)
            _f, stroke = _ROLE_COLOR[role]
            els.append(host_tile(hx, hy, cardW, cardH, kind=role_kind(role), role=role,
                                 ip=h.ip, hostname=real_hostname(h), subline=os_short(h),
                                 stroke=stroke, risk=worst_severity(h),
                                 owned=has_access(h)))
        y += panelH + 16

    leg, y2 = _map_legend(m, y + 6, any_access, any_risk)
    els.append(leg)
    return _wrap(els, PAGE_W, y2 + 18)


# AD tier-0 palette (fill, stroke) — distinct from the network-map roles.
_AD_DOMAIN = ("#fff6e6", "#C15A11")     # domain object
_AD_GROUP = ("#fde7ef", "#a01050")      # high-value group (Domain Admins, ...)
_AD_DC = ("#fbe3e3", "#C00000")         # Domain Controller
_AD_USER = ("#e7eefb", "#1f4e9c")       # privileged user
_AD_COMPUTER = ("#eef1f1", "#5f6f6e")   # member computer
_AD_OTHER = ("#ffffff", "#8a9997")


def _ad_color(node: dict):
    if node.get("type") == "Domain":
        return _AD_DOMAIN
    if node.get("dc"):
        return _AD_DC
    if node.get("type") == "Group" and node.get("hv"):
        return _AD_GROUP
    if node.get("type") == "User":
        return _AD_USER
    if node.get("type") == "Computer":
        return _AD_COMPUTER
    return _AD_OTHER


def ad_svg(arch: dict, owned_labels=None) -> str:
    """A directly-viewable inline SVG of the *tier-0* Active Directory architecture
    that recce derived from a BloodHound/SharpHound collection: the domain(s) on
    top, the high-value groups and Domain Controllers below, and their privileged
    members at the bottom — with MemberOf / control (ACL, DCSync) edges and domain
    trust edges. Renders in any browser and prints to PDF; no tools, no JavaScript.
    `arch` is the dict from bloodhound.architecture().

    Enriched like the network map: a tier-0 object recce **already holds** (its label
    is in `owned_labels` — usernames from captured credentials, or a DC we accessed)
    gets a bold border + ✓; a node that is the **direct target of a control edge**
    (DCSync = critical, other ACL = high) gets a risk dot."""
    from html import escape as _e
    owned = {str(x).upper() for x in (owned_labels or set())}
    nodes = (arch or {}).get("nodes") or {}
    if not nodes:
        return ('<svg viewBox="0 0 360 60" width="360" height="60" role="img" '
                'aria-label="AD architecture"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No BloodHound tier-0 graph available.</text></svg>')
    edges = (arch or {}).get("edges") or []
    trusts = (arch or {}).get("trusts") or []

    tiers: dict[int, list[str]] = {0: [], 1: [], 2: []}
    for sid, n in nodes.items():
        t = n.get("tier", 1)
        tiers.setdefault(t if t in (0, 1, 2) else 2, []).append(sid)
    for t in tiers:
        tiers[t].sort(key=lambda s: (nodes[s].get("label") or s).upper())

    boxW, boxH, hGap, vGap, m = 156, 40, 18, 96, 22
    ncols = max(1, max(len(v) for v in tiers.values()))
    width = m * 2 + ncols * (boxW + hGap) - hGap
    # Domain trust arcs are drawn ABOVE the tier-0 row; reserve headroom when any
    # exist so the arc + "trust" label don't clip against the top of the viewBox.
    top_pad = 26 if trusts else 0
    y0 = m + 24 + top_pad
    row_y = {0: y0, 1: y0 + vGap, 2: y0 + 2 * vGap}

    pos: dict[str, tuple] = {}
    for t in (0, 1, 2):
        row = tiers.get(t) or []
        if not row:
            continue
        tw = len(row) * (boxW + hGap) - hGap
        startx = max(float(m), (width - tw) / 2)
        for i, sid in enumerate(row):
            pos[sid] = (startx + i * (boxW + hGap) + boxW / 2, row_y[t])

    def anchor(sid, toward_y):
        cx, cy = pos[sid]
        if toward_y < cy:
            return cx, cy - boxH / 2
        if toward_y > cy:
            return cx, cy + boxH / 2
        return cx, cy

    # Per-node risk from incoming control edges: DCSync = critical, other ACL = high.
    # Only count edges whose target is actually drawn (in `pos`) so the risk legend
    # key never appears without a matching dot on the page.
    node_risk: dict[str, str] = {}
    for src, label, dst in edges:
        if label == "MemberOf" or dst not in pos:
            continue
        sev = "critical" if label == "DCSync" else "high"
        if node_risk.get(dst) != "critical":
            node_risk[dst] = sev
    any_owned = any((nodes[s].get("label") or "").upper() in owned for s in pos)
    any_risk = bool(node_risk)

    els: list[str] = []
    # Edges first, so the boxes sit on top of the lines.
    for src, label, dst in edges:
        if src not in pos or dst not in pos:
            continue
        x1, y1 = anchor(src, pos[dst][1])
        x2, y2 = anchor(dst, pos[src][1])
        control = label != "MemberOf"
        col = "#C00000" if control else "#9aa8a6"
        dash = ' stroke-dasharray="5 3"' if control else ""
        els.append(f'<path d="M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}" stroke="{col}" '
                   f'stroke-width="1.4" fill="none"{dash}/>')
        if control:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            els.append(f'<text x="{mx:.0f}" y="{my:.0f}" font-size="9.5" '
                       f'fill="#C00000" text-anchor="middle">{_e(label)}</text>')

    # Trust edges between domain boxes (dashed, orange), matched by label text.
    label_pos: dict[str, tuple] = {}
    for sid in tiers.get(0, []):
        label_pos[(nodes[sid].get("label") or "").upper()] = pos[sid]
    for src_name, direction, dst_name in trusts:
        a = label_pos.get((src_name or "").upper())
        b = label_pos.get((dst_name or "").upper())
        if not a or not b:
            continue
        els.append(f'<path d="M{a[0]:.0f},{a[1] - boxH / 2:.0f} '
                   f'C{a[0]:.0f},{a[1] - boxH:.0f} {b[0]:.0f},{b[1] - boxH:.0f} '
                   f'{b[0]:.0f},{b[1] - boxH / 2:.0f}" stroke="#C15A11" '
                   f'stroke-width="1.3" stroke-dasharray="4 3" fill="none"/>')
        mx = (a[0] + b[0]) / 2
        els.append(f'<text x="{mx:.0f}" y="{a[1] - boxH - 2:.0f}" font-size="9.5" '
                   f'fill="#C15A11" text-anchor="middle">trust '
                   f'{_x(direction, 14)}</text>')

    def box(sid):
        n = nodes[sid]
        cx, cy = pos[sid]
        fill, stroke = _ad_color(n)
        x, y = cx - boxW / 2, cy - boxH / 2
        rx = boxH / 2 if n.get("type") == "Domain" else 7
        tag = "DC" if n.get("dc") else n.get("type", "")
        held = (n.get("label") or "").upper() in owned
        out = [
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{boxW}" height="{boxH}" rx="{rx:.0f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{3 if held else 1.6}"/>'
            f'<text x="{cx:.0f}" y="{cy - 2:.0f}" text-anchor="middle" font-size="11.5" '
            f'font-weight="700" fill="#1a2422">{_x(n.get("label") or sid, 17)}</text>'
            f'<text x="{cx:.0f}" y="{cy + 12:.0f}" text-anchor="middle" font-size="9.5" '
            f'fill="#5f6f6e">{_x(tag, 18)}</text>']
        # Overlays (top-right): risk dot for the worst incoming control edge, then a
        # ✓ when recce already holds this principal.
        bx = x + boxW - 9
        sev = node_risk.get(sid)
        if sev in _SEV_DOT:
            out.append(f'<circle cx="{bx:.0f}" cy="{y + 9:.0f}" r="5.5" '
                       f'fill="{_SEV_DOT[sev]}" stroke="#fff" stroke-width="1"/>')
            bx -= 17
        if held:
            out.append(f'<circle cx="{bx:.0f}" cy="{y + 9:.0f}" r="7" '
                       f'fill="{_ACCESS_STROKE}" stroke="#fff" stroke-width="1"/>')
            out.append(f'<text x="{bx:.0f}" y="{y + 13:.0f}" text-anchor="middle" '
                       f'font-size="10" font-weight="700" fill="#fff">✓</text>')
        return "".join(out)

    for sid in pos:
        els.append(box(sid))

    # Legend.
    leg_y = row_y[2] + boxH / 2 + 30
    lx = m
    items = [("Domain", _AD_DOMAIN), ("HV group", _AD_GROUP), ("DC", _AD_DC),
             ("User", _AD_USER), ("Computer", _AD_COMPUTER)]
    for name, (fill, stroke) in items:
        els.append(f'<rect x="{lx}" y="{leg_y - 10:.0f}" width="12" height="12" rx="2" '
                   f'fill="{fill}" stroke="{stroke}"/>')
        els.append(f'<text x="{lx + 17}" y="{leg_y:.0f}" font-size="11" '
                   f'fill="#3a4644">{name}</text>')
        lx += 34 + len(name) * 7
    els.append(f'<text x="{m}" y="{leg_y + 18:.0f}" font-size="10.5" fill="#8a3030">'
               '— control edge (ACL / DCSync)</text>')
    els.append(f'<text x="{m + 220}" y="{leg_y + 18:.0f}" font-size="10.5" '
               f'fill="#9aa8a6">— MemberOf</text>')

    height = leg_y + 30
    # Overlay keys, only when they apply (keeps the legend honest).
    if any_owned or any_risk:
        oy = leg_y + 36
        ox = m
        if any_owned:
            els.append(f'<circle cx="{ox + 6}" cy="{oy - 4:.0f}" r="7" '
                       f'fill="{_ACCESS_STROKE}" stroke="#fff" stroke-width="1"/>')
            els.append(f'<text x="{ox + 6}" y="{oy:.0f}" text-anchor="middle" '
                       f'font-size="10" font-weight="700" fill="#fff">✓</text>')
            els.append(f'<text x="{ox + 18}" y="{oy:.0f}" font-size="10.5" '
                       f'fill="#3a4644">already held (bold border + ✓)</text>')
            ox += 240
        if any_risk:
            els.append(f'<circle cx="{ox + 6}" cy="{oy - 4:.0f}" r="5.5" fill="#C00000" '
                       'stroke="#fff" stroke-width="1"/>')
            els.append(f'<text x="{ox + 16}" y="{oy:.0f}" font-size="10.5" '
                       f'fill="#3a4644">directly seizable (DCSync=critical, ACL=high)'
                       '</text>')
        height += 24
    if (arch or {}).get("truncated"):
        els.append(f'<text x="{m}" y="{height - 2:.0f}" font-size="10" fill="#5f6f6e">'
                   'Showing the top tier-0 objects (graph truncated for legibility).</text>')
        height += 16
    return (f'<svg viewBox="0 0 {int(width)} {int(height)}" width="{int(width)}" '
            f'height="{int(height)}" role="img" aria-label="AD tier-0 architecture" '
            f'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            + "".join(els) + "</svg>")


# --- tiered lateral / reachability view -----------------------------------------

# Role -> trust tier. Tier 0 = Domain Controllers, tier 1 = servers, tier 2 = clients.
_TIER_OF = {"DC": 0, "DB": 1, "Web": 1, "Mail": 1, "File/SMB": 1,
            "Workstation": 2, "Host": 2}
_TIER_LABEL = {0: "Tier 0 · Domain Controllers", 1: "Tier 1 · Servers",
               2: "Tier 2 · Workstations & hosts"}
# Remote-auth protocols an attacker pivots over once holding a credential/hash. This is
# the *credentialed pivot surface* recce can justify from open ports — NOT a claim that
# any two hosts can route to each other (recce never tests host-to-host reachability).
_REACH = [("SMB", (445, 139)), ("WinRM", (5985, 5986)), ("RDP", (3389,)),
          ("SSH", (22,)), ("MSSQL", (1433,))]


def reach_counts(hosts: list[Host]) -> list[tuple]:
    """[(proto, host-count)] for the remote-auth pivot surface, present protocols only."""
    up = [h for h in hosts if h.is_up]
    out = []
    for name, ports in _REACH:
        n = sum(1 for h in up if {p.portid for p in h.open_ports} & set(ports))
        if n:
            out.append((name, n))
    return out


def tiered_svg(hosts: list[Host], domains=None, ad_data=None) -> str:
    """A directly-viewable inline SVG of the estate as trust tiers — Domain Controllers
    (tier 0) above servers (tier 1) above workstations/hosts (tier 2) — with the
    credentialed lateral-movement surface overlaid.

    Honest by construction: recce enumerates each host independently and does NOT test
    which hosts can route to which. So the tiers are a *logical* grouping by role, the
    upward arrows show the direction an attacker escalates (client → server → DC), and
    the pivot legend lists the services that accept remote authentication (how you move
    once you hold a credential) — none of it asserts physical/firewall reachability."""
    from html import escape as _e
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 340 60" width="340" height="60" role="img" '
                'aria-label="Tiered network map"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    dc_names = ad_dc_names(ad_data)
    tiers: dict[int, dict[str, list]] = {0: {}, 1: {}, 2: {}}
    for h in up:
        role = role_with_ad(h, dc_names)
        t = _TIER_OF.get(role, 2)
        cell = tiers[t].setdefault(role, [0, 0])
        cell[0] += 1
        if has_access(h):
            cell[1] += 1
    doms = domains or ad.derive_domains(up)
    reach = reach_counts(up)
    footholds = sum(1 for h in up if has_access(h))

    W, m = 900, 18
    bandH, gap, top = 108, 52, 46
    chipW, chipH, chipGap = 138, 42, 12
    band_y = {t: top + t * (bandH + gap) for t in (0, 1, 2)}
    H = band_y[2] + bandH + 74               # room for the pivot legend + caption
    cx = W / 2
    els = [
        '<defs><marker id="tup" markerWidth="10" markerHeight="10" refX="5" refY="8" '
        'orient="auto"><path d="M5,0 L10,8 L0,8 Z" fill="#6b4fa0"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{m}" y="26" font-size="15" font-weight="700" fill="#115e59">'
        'Tiered view — DC → servers → workstations</text>',
    ]

    # upward escalation arrows first (behind the bands), client -> server -> DC
    for t in (2, 1):
        y1 = band_y[t]
        y2 = band_y[t - 1] + bandH
        els.append(f'<line x1="{cx:.0f}" y1="{y1}" x2="{cx:.0f}" y2="{y2 + 4}" '
                   f'stroke="#b08cc0" stroke-width="2" stroke-dasharray="5 4" '
                   f'marker-end="url(#tup)"/>')
        els.append(f'<rect x="{cx + 8:.0f}" y="{(y1 + y2) / 2 - 9:.0f}" width="132" '
                   f'height="18" rx="9" fill="#f3eefb" stroke="#6b4fa0"/>')
        els.append(f'<text x="{cx + 74:.0f}" y="{(y1 + y2) / 2 + 4:.0f}" '
                   f'text-anchor="middle" font-size="10.5" fill="#6b4fa0">'
                   f'lateral / escalate</text>')

    for t in (0, 1, 2):
        y = band_y[t]
        pop = sum(c[0] for c in tiers[t].values())
        els.append(f'<rect x="{m}" y="{y}" width="{W - 2 * m}" height="{bandH}" rx="10" '
                   f'fill="#fafcfb" stroke="#e3e8e7"/>')
        els.append(f'<text x="{m + 14}" y="{y + 22}" font-size="12.5" font-weight="700" '
                   f'fill="#115e59">{_e(_TIER_LABEL[t])} '
                   f'<tspan fill="#5f6f6e" font-weight="400">({pop} host'
                   f'{"s" if pop != 1 else ""})</tspan></text>')
        if not tiers[t]:
            els.append(f'<text x="{m + 14}" y="{y + 64}" font-size="11.5" '
                       f'fill="#b7c0be">— none observed —</text>')
        cxp = m + 14
        for role in _ROLE_ORDER:
            if role not in tiers[t]:
                continue
            cnt, acc = tiers[t][role]
            fill, stroke = _ROLE_COLOR.get(role, ("#ffffff", "#8a9997"))
            cy = y + 34
            els.append(f'<rect x="{cxp}" y="{cy}" width="{chipW}" height="{chipH}" rx="8" '
                       f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
            els.append(glyph(role_kind(role), cxp + 8, cy + chipH / 2 - 8, 16, stroke))
            els.append(f'<text x="{cxp + 30}" y="{cy + 18}" font-size="12" '
                       f'font-weight="700" fill="#1a2422">{_e(role)} ×{cnt}</text>')
            sub = f"{acc} owned ✓" if acc else "&#8203;"
            els.append(f'<text x="{cxp + 30}" y="{cy + 33}" font-size="10.5" '
                       f'fill="#2E7D32">{sub}</text>')
            cxp += chipW + chipGap
        # AD domain pill in the tier-0 band, linked to it
        if t == 0 and doms:
            dn = ", ".join(d.name for d in doms if d.name)[:40] or "AD"
            dx = W - m - 210
            els.append(f'<rect x="{dx}" y="{y + 30}" width="196" height="46" rx="10" '
                       f'fill="{_DOMAIN_COLOR[0]}" stroke="{_DOMAIN_COLOR[1]}" '
                       f'stroke-width="2"/>')
            els.append(f'<text x="{dx + 12}" y="{y + 50}" font-size="11.5" '
                       f'font-weight="700" fill="#1a2422">AD domain</text>')
            els.append(f'<text x="{dx + 12}" y="{y + 67}" font-size="11" '
                       f'fill="#3a4644">{_e(dn)}</text>')

    # pivot legend
    ly = band_y[2] + bandH + 24
    parts = " · ".join(f"{p} ×{n}" for p, n in reach) or "none observed"
    els.append(f'<text x="{m}" y="{ly}" font-size="12" font-weight="700" '
               f'fill="#1a2422">Credentialed pivot surface: '
               f'<tspan font-weight="400">{_e(parts)}</tspan>'
               f'<tspan fill="#2E7D32">   ·   {footholds} foothold'
               f'{"s" if footholds != 1 else ""} held</tspan></text>')
    els.append(f'<text x="{m}" y="{ly + 20}" font-size="10.5" fill="#5f6f6e">'
               'Logical view: tiers group hosts by role and the arrows show the '
               'escalation direction. The pivot surface lists services that accept '
               'remote auth — recce does not test host-to-host network reachability.'
               '</text>')

    return (f'<svg viewBox="0 0 {W} {int(H)}" width="{W}" height="{int(H)}" role="img" '
            f'aria-label="Tiered network map" '
            f'font-family="system-ui,Segoe UI,Arial,sans-serif">'
            + "".join(els) + "</svg>")


# --- role glyphs (small inline-SVG computer icons) -------------------------------
# Three device classes, stroke-drawn so they read at ~18px and print cleanly:
#   dc          - a server tower with a star (the domain's authority)
#   server      - a rack unit with drive slots
#   workstation - a desktop monitor on a stand
def role_kind(role: str) -> str:
    if role == "DC":
        return "dc"
    if role in ("DB", "Web", "Mail", "File/SMB"):
        return "server"
    return "workstation"                      # Workstation, Host


def glyph(kind: str, x: float, y: float, s: float = 18, color: str = "#3a4644") -> str:
    """An inline-SVG device icon of size s at top-left (x, y). No fills that fight the
    card colour — thin strokes only, plus one accent for the DC star."""
    u = s / 18.0
    def P(*pts):
        return " ".join(f"{x + a * u:.1f},{y + b * u:.1f}" for a, b in pts)
    st = f'stroke="{color}" stroke-width="1.4" fill="none" ' \
         'stroke-linejoin="round" stroke-linecap="round"'
    if kind == "workstation":
        return (f'<g {st}>'
                f'<rect x="{x + 1 * u:.1f}" y="{y + 1 * u:.1f}" width="{16 * u:.1f}" '
                f'height="{11 * u:.1f}" rx="{1.5 * u:.1f}"/>'
                f'<line x1="{x + 6 * u:.1f}" y1="{y + 12 * u:.1f}" x2="{x + 6 * u:.1f}" '
                f'y2="{y + 15 * u:.1f}"/>'
                f'<line x1="{x + 12 * u:.1f}" y1="{y + 12 * u:.1f}" x2="{x + 12 * u:.1f}" '
                f'y2="{y + 15 * u:.1f}"/>'
                f'<line x1="{x + 4 * u:.1f}" y1="{y + 15.5 * u:.1f}" x2="{x + 14 * u:.1f}" '
                f'y2="{y + 15.5 * u:.1f}"/></g>')
    # dc + server share the tower body; dc adds a star accent
    body = (f'<rect x="{x + 3 * u:.1f}" y="{y + 1 * u:.1f}" width="{12 * u:.1f}" '
            f'height="{16 * u:.1f}" rx="{1.5 * u:.1f}"/>'
            f'<line x1="{x + 5.5 * u:.1f}" y1="{y + 4.5 * u:.1f}" x2="{x + 12.5 * u:.1f}" '
            f'y2="{y + 4.5 * u:.1f}"/>'
            f'<line x1="{x + 5.5 * u:.1f}" y1="{y + 7.5 * u:.1f}" x2="{x + 12.5 * u:.1f}" '
            f'y2="{y + 7.5 * u:.1f}"/>'
            f'<circle cx="{x + 6.2 * u:.1f}" cy="{y + 13 * u:.1f}" r="{1 * u:.1f}"/>')
    if kind == "dc":
        star = (f'<path d="M{x + 9 * u:.1f},{y + 9.5 * u:.1f} l{1.1 * u:.1f},{2.2 * u:.1f} '
                f'l{2.4 * u:.1f},{0.3 * u:.1f} l{-1.8 * u:.1f},{1.7 * u:.1f} '
                f'l{0.5 * u:.1f},{2.4 * u:.1f} l{-2.2 * u:.1f},{-1.2 * u:.1f} '
                f'l{-2.2 * u:.1f},{1.2 * u:.1f} l{0.5 * u:.1f},{-2.4 * u:.1f} '
                f'l{-1.8 * u:.1f},{-1.7 * u:.1f} l{2.4 * u:.1f},{-0.3 * u:.1f} z" '
                f'fill="{color}" stroke="none"/>')
        return f'<g {st}>{body}</g>{star}'
    return f'<g {st}>{body}</g>'


def glyph_legend(x: float, y: float, color: str = "#5f6f6e") -> str:
    """A one-row key for the three device glyphs, starting at (x, y)."""
    out, cx = [], x
    for kind, label in (("dc", "Domain Controller"), ("server", "Server"),
                        ("workstation", "Workstation / host")):
        out.append(glyph(kind, cx, y, 16, color))
        out.append(f'<text x="{cx + 22:.0f}" y="{y + 13:.0f}" font-size="10.5" '
                   f'fill="{color}">{label}</text>')
        cx += 40 + len(label) * 6.4
    return "".join(out)


def net_glyph(kind: str, x: float, y: float, s: float = 22, color: str = "#0f766e") -> str:
    """A network-infrastructure icon (size s at top-left x,y): 'switch' (an L2 segment),
    'router' (an L3 gateway) or 'firewall' (a filtering gateway / perimeter). Stroke-only
    so it prints cleanly."""
    u = s / 22.0
    def X(a): return x + a * u
    def Y(b): return y + b * u
    st = (f'stroke="{color}" stroke-width="1.6" fill="none" '
          'stroke-linejoin="round" stroke-linecap="round"')
    if kind == "switch":
        o = [f'<rect x="{X(1)}" y="{Y(6)}" width="{20 * u}" height="{9 * u}" '
             f'rx="{2 * u}" {st}/>']
        for px in (4, 8, 12, 16):
            o.append(f'<line x1="{X(px)}" y1="{Y(15)}" x2="{X(px)}" y2="{Y(19)}" {st}/>')
        o.append(f'<path d="M{X(6)},{Y(9)} h{7 * u} m-2,-2 l2,2 l-2,2" {st}/>')
        o.append(f'<path d="M{X(16)},{Y(12.5)} h-{7 * u} m2,-2 l-2,2 l2,2" {st}/>')
        return "<g>" + "".join(o) + "</g>"
    if kind == "router":
        o = [f'<ellipse cx="{X(11)}" cy="{Y(11)}" rx="{9 * u}" ry="{6 * u}" {st}/>']
        for d in (f'l{5 * u},-{5 * u} m0,3 v-3 h-3', f'l-{5 * u},{5 * u} m0,-3 v3 h3',
                  f'l{5 * u},{4 * u} m-3,0 h3 v-3', f'l-{5 * u},-{4 * u} m3,0 h-3 v3'):
            o.append(f'<path d="M{X(11)},{Y(11)} {d}" {st}/>')
        return "<g>" + "".join(o) + "</g>"
    if kind == "firewall":
        o = [f'<rect x="{X(1)}" y="{Y(3)}" width="{20 * u}" height="{16 * u}" '
             f'rx="{1.5 * u}" {st}/>']
        for ry in (7.3, 11.6, 15.9):
            o.append(f'<line x1="{X(1)}" y1="{Y(ry)}" x2="{X(21)}" y2="{Y(ry)}" {st}/>')
        for vx, y0, y1 in ((8, 3, 7.3), (14, 3, 7.3), (5, 7.3, 11.6), (11, 7.3, 11.6),
                           (17, 7.3, 11.6), (8, 11.6, 15.9), (14, 11.6, 15.9)):
            o.append(f'<line x1="{X(vx)}" y1="{Y(y0)}" x2="{X(vx)}" y2="{Y(y1)}" {st}/>')
        return "<g>" + "".join(o) + "</g>"
    return ""


# --- observed reachability (from on-target topology) -----------------------------

def adjacency(hosts: list[Host]) -> dict:
    """Host-to-host links OBSERVED from compromised hosts' own topology (folded in by
    `ingest`): ARP neighbours (the box demonstrably reached that L2 address) and live
    connection peers. This is ground truth, unlike the outside-in scan — recce only
    draws a link because a foothold actually contacted the other end.

    Returns {footholds:[ip], edges:[{src,dst,kind,label,dst_known}], pivots:{ip:[subnet]}}.
    `kind` is 'arp' (same-segment L2 contact) or 'conn' (a live/known connection)."""
    up = [h for h in hosts if h.is_up]
    ip_host = {h.ip: h for h in up}
    iface_ip = {}
    for h in up:
        for iface in (h.topology or {}).get("interfaces", []):
            if iface.get("ip"):
                iface_ip[iface["ip"]] = h.ip

    def resolve(ip):
        return ip_host.get(ip) and ip or iface_ip.get(ip) or (ip if ip in ip_host else "")

    footholds, edges, pivots = [], [], {}
    seen = set()
    for h in up:
        topo = h.topology or {}
        if not topo:
            continue
        footholds.append(h.ip)
        subs = sorted({i["subnet"] for i in topo.get("interfaces", []) if i.get("subnet")})
        if len(subs) > 1:
            pivots[h.ip] = subs
        for n in topo.get("neighbors", []):
            dst = resolve(n) or n
            if dst == h.ip:
                continue
            k = (h.ip, dst, "arp")
            if k in seen:
                continue
            seen.add(k)
            edges.append({"src": h.ip, "dst": dst, "kind": "arp", "label": "",
                          "dst_known": dst in ip_host})
        for p in topo.get("peers", []):
            dst = resolve(p["ip"]) or p["ip"]
            if dst == h.ip:
                continue
            k = (h.ip, dst, "conn")
            if k in seen:
                continue
            seen.add(k)
            edges.append({"src": h.ip, "dst": dst, "kind": "conn",
                          "label": str(p.get("port", "")), "dst_known": dst in ip_host})
    return {"footholds": footholds, "edges": edges, "pivots": pivots}


def reachability_svg(hosts: list[Host], ad_data=None, max_nodes: int = 60) -> str:
    """A directly-viewable inline SVG of OBSERVED host-to-host reachability, from the
    topology on-target enums brought back. Footholds (left) with solid edges to the
    ARP neighbours they reached and dashed edges to live connection peers (right).
    Pivots (dual-homed hosts bridging segments) are flagged. Renders with no tools."""
    from html import escape as _e
    adj = adjacency(hosts)
    if not adj["footholds"]:
        return ('<svg viewBox="0 0 560 60" width="560" height="60" role="img" '
                'aria-label="Observed reachability"><text x="12" y="34" font-size="13" '
                'fill="#5f6f6e">No on-target topology yet — run the enum NETWORK block '
                'and `recce ingest` its output.</text></svg>')
    up = {h.ip: h for h in hosts if h.is_up}
    dc_names = ad_dc_names(ad_data)

    def label(ip):
        h = up.get(ip)
        hn = h.hostname if h else ""
        return ip + (f"  {hn}" if hn else "")

    def kind_of(ip):
        h = up.get(ip)
        return role_kind(role_with_ad(h, dc_names)) if h else "workstation"

    foot = list(dict.fromkeys(adj["footholds"]))
    others, oseen = [], set(adj["footholds"])
    truncated = 0
    for e in adj["edges"]:
        if e["dst"] not in oseen:
            if len(others) >= max_nodes:
                truncated += 1
                continue
            oseen.add(e["dst"])
            others.append(e["dst"])
    drawn = {e for e in range(len(adj["edges"]))}

    cardW, cardH, vgap, m, colGap = 214, 76, 14, 18, 150
    top = 52
    rowsL, rowsR = len(foot), max(1, len(others))
    H = top + max(rowsL, rowsR) * (cardH + vgap) + 54
    xL, xR = m, m + cardW + colGap
    # W spans the two card columns, but the reachability legend ("… live connection")
    # runs past the right column — widen so it never clips.
    W = max(m * 2 + cardW * 2 + colGap, xR + 178 + 96 + m)
    posL = {ip: top + i * (cardH + vgap) for i, ip in enumerate(foot)}
    posR = {ip: top + i * (cardH + vgap) for i, ip in enumerate(others)}

    els = [
        '<defs><marker id="rar" markerWidth="9" markerHeight="9" refX="7" refY="3" '
        'orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#5f6f6e"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{int(H)}" fill="#ffffff"/>',
        f'<text x="{m}" y="26" font-size="15" font-weight="700" fill="#115e59">'
        'Observed reachability <tspan font-weight="400" fill="#5f6f6e">'
        '(from compromised hosts’ ARP + live connections)</tspan></text>',
        f'<text x="{xL}" y="{top - 12}" font-size="11" font-weight="700" '
        f'fill="#5f6f6e">FOOTHOLDS</text>',
        f'<text x="{xR}" y="{top - 12}" font-size="11" font-weight="700" '
        f'fill="#5f6f6e">REACHED</text>',
    ]

    # edges first (behind cards)
    for e in adj["edges"]:
        if e["src"] not in posL:
            continue
        y1 = posL[e["src"]] + cardH / 2
        if e["dst"] in posR:
            y2 = posR[e["dst"]] + cardH / 2
        elif e["dst"] in posL:
            y2 = posL[e["dst"]] + cardH / 2
        else:
            continue
        x1, x2 = xL + cardW, xR
        dash = 'stroke-dasharray="5 4" ' if e["kind"] == "conn" else ""
        col = "#1f4e9c" if e["kind"] == "conn" else "#5f6f6e"
        els.append(f'<path d="M{x1},{y1:.0f} C{x1 + 40},{y1:.0f} {x2 - 40},{y2:.0f} '
                   f'{x2 - 6},{y2:.0f}" fill="none" stroke="{col}" stroke-width="1.5" '
                   f'{dash}marker-end="url(#rar)"/>')

    def card(x, y, ip, foothold):
        h = up.get(ip)
        role = role_with_ad(h, dc_names) if h else ""
        stroke = _ROLE_COLOR.get(role, ("#ffffff", "#8a9997"))[1] if h else "#b7c0be"
        note = ""
        if ip in adj["pivots"]:
            note = "PIVOT · " + ", ".join(adj["pivots"][ip][:2])
        elif not h:
            note = "(not in scan)"
        return host_tile(x, y, cardW, cardH, kind=kind_of(ip), role=(role or "unknown"),
                         ip=ip, hostname=(real_hostname(h) if h else ""), subline=note,
                         stroke=stroke, risk=(worst_severity(h) if h else ""),
                         owned=(has_access(h) if h else False))

    for ip in foot:
        els.append(card(xL, posL[ip], ip, True))
    for ip in others:
        els.append(card(xR, posR[ip], ip, False))

    ly = H - 30
    els.append(glyph_legend(m, ly - 10))
    els.append(f'<line x1="{xR}" y1="{ly + 2:.0f}" x2="{xR + 22}" y2="{ly + 2:.0f}" '
               f'stroke="#5f6f6e" stroke-width="1.5"/>'
               f'<text x="{xR + 28}" y="{ly + 6:.0f}" font-size="10.5" fill="#5f6f6e">'
               f'ARP (same segment)</text>'
               f'<line x1="{xR + 150}" y1="{ly + 2:.0f}" x2="{xR + 172}" y2="{ly + 2:.0f}" '
               f'stroke="#1f4e9c" stroke-width="1.5" stroke-dasharray="5 4"/>'
               f'<text x="{xR + 178}" y="{ly + 6:.0f}" font-size="10.5" fill="#5f6f6e">'
               f'live connection</text>')
    if truncated:
        els.append(f'<text x="{m}" y="{H - 8:.0f}" font-size="10" fill="#5f6f6e">'
                   f'+{truncated} more reached host(s) not shown (capped for legibility).'
                   '</text>')
    return (f'<svg viewBox="0 0 {W} {int(H)}" width="{W}" height="{int(H)}" role="img" '
            f'aria-label="Observed reachability" '
            f'font-family="system-ui,Segoe UI,Arial,sans-serif">' + "".join(els) + "</svg>")


# --- logical architecture (infrastructure + segments) ----------------------------
_TIER_SEG = {0: "Edge / DMZ", 1: "Servers", 2: "Workstations"}
_SEG_W = 250
_ZONE_H = 30 + 4 * 17 + 22          # header + up to 4 role rows + a badge row


def _segment_gateway(rows: list[Host]) -> str:
    """The default-route gateway for a segment, from any host's ingested topology."""
    for h in rows:
        for rt in (getattr(h, "topology", None) or {}).get("routes", []):
            if rt.get("dest") == "default" and rt.get("gw"):
                return rt["gw"]
    return ""


def _segment_tier(sub: str, counts: dict) -> int:
    """0 = edge/DMZ, 1 = servers, 2 = workstations — a segment's place in the stack."""
    if "dmz" in sub.lower() or "edge" in sub.lower():
        return 0
    if any(counts.get(r) for r in ("DC", "DB", "File/SMB", "Mail")):
        return 1
    if counts.get("Web") and not (counts.get("Workstation") or counts.get("Host")):
        return 1
    return 2


def _segments(hosts: list[Host], dc_names: set) -> list[dict]:
    """Per-subnet summary rows (role counts, gateway, tier, owned/risk) for the map."""
    by_subnet: dict[str, list[Host]] = {}
    for h in hosts:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)
    segs = []
    for sub, rows in by_subnet.items():
        counts: dict[str, int] = {}
        for h in rows:
            counts[role_with_ad(h, dc_names)] = counts.get(role_with_ad(h, dc_names), 0) + 1
        worst = next((s for s in ("critical", "high", "medium", "low")
                      if any(worst_severity(h) == s for h in rows)), "")
        segs.append({
            "sub": sub, "n": len(rows), "counts": counts, "gw": _segment_gateway(rows),
            "owned": sum(1 for h in rows if has_access(h)), "worst": worst,
            "dc": any(role_with_ad(h, dc_names) == "DC" for h in rows),
            "tier": _segment_tier(sub, counts),
        })
    segs.sort(key=lambda z: (z["tier"], _ipkey(z["sub"].split()[0])))
    return segs


def _draw_zone(zx: float, zy: float, z: dict) -> list:
    """SVG for one segment zone box (switch header + role make-up + owned/severity)."""
    from html import escape as _e
    els = []
    acc = "#C00000" if z["dc"] else "#cdd8d6"
    els.append(f'<rect x="{zx}" y="{zy}" width="{_SEG_W}" height="{_ZONE_H}" rx="10" '
               f'fill="#ffffff" stroke="{acc}" stroke-width="{2 if z["dc"] else 1.3}"/>')
    els.append(f'<rect x="{zx}" y="{zy}" width="{_SEG_W}" height="26" rx="10" '
               f'fill="#f2f6f5"/><rect x="{zx}" y="{zy + 16}" width="{_SEG_W}" '
               f'height="10" fill="#f2f6f5"/>')
    els.append(net_glyph("switch", zx + 8, zy + 4, 17, "#5f6f6e"))
    els.append(f'<text x="{zx + 32}" y="{zy + 17}" font-size="11.5" font-weight="700" '
               f'fill="#115e59">{_x(z["sub"], 18)}</text>')
    els.append(f'<text x="{zx + _SEG_W - 10}" y="{zy + 17}" text-anchor="end" '
               f'font-size="9.5" fill="#5f6f6e">{_TIER_SEG[z["tier"]]} · {z["n"]}</text>')
    ry, shown = zy + 42, 0
    for role in _ROLE_ORDER:
        if role not in z["counts"] or shown >= 4:
            continue
        els.append(glyph(role_kind(role), zx + 14, ry - 11, 15, _ROLE_COLOR[role][1]))
        els.append(f'<text x="{zx + 36}" y="{ry}" font-size="11" fill="#3a4644">'
                   f'{z["counts"][role]} {_e(role)}</text>')
        ry += 17
        shown += 1
    by, bx = zy + _ZONE_H - 12, zx + 12
    if z["owned"]:
        els.append(f'<circle cx="{bx + 6}" cy="{by - 4}" r="7" fill="{_ACCESS_STROKE}"/>'
                   f'<text x="{bx + 6}" y="{by - 1}" text-anchor="middle" font-size="9" '
                   f'font-weight="700" fill="#fff">✓</text>')
        els.append(f'<text x="{bx + 18}" y="{by - 1}" font-size="10" fill="#3a4644">'
                   f'{z["owned"]} owned</text>')
    if z["worst"] in _SEV_CHIP:
        col, lab = _SEV_CHIP[z["worst"]]
        els.append(f'<rect x="{zx + _SEG_W - 46}" y="{by - 15}" width="34" height="14" '
                   f'rx="7" fill="#fff" stroke="{col}" stroke-width="1.2"/>'
                   f'<text x="{zx + _SEG_W - 29}" y="{by - 5}" text-anchor="middle" '
                   f'font-size="9" font-weight="700" fill="{col}">{lab}</text>')
    return els


def _ad_nodes(doms, y, m):
    """Draw AD domain node(s) at row y; returns (svg list, [anchor_x], bottom_y)."""
    els, anchors, adx = [], [], m
    for d in doms or []:
        w = 250
        els.append(f'<rect x="{adx}" y="{y}" width="{w}" height="34" rx="8" '
                   f'fill="{_DOMAIN_COLOR[0]}" stroke="{_DOMAIN_COLOR[1]}" stroke-width="1.6"/>')
        els.append(f'<text x="{adx + 12}" y="{y + 15}" font-size="12" font-weight="700" '
                   f'fill="#7a3a0a">AD domain: {_x(d.name, 24)}</text>')
        dcs = ", ".join(d.dc_ips) if getattr(d, "dc_ips", None) else "no DC seen"
        els.append(f'<text x="{adx + 12}" y="{y + 28}" font-size="10" fill="#7a3a3a">'
                   f'DCs: {_x(dcs, 32)}</text>')
        anchors.append(adx + w / 2)
        adx += w + 20
    return els, anchors, (y + 34 if doms else y)


def architecture_svg(hosts: list[Host], domains=None, ad_data=None) -> str:
    """A directly-viewable inline SVG of the *logical network architecture*.

    Without ingested topology: an AD-domain node over a routed core, each segment hung
    off the core through its gateway (router, or firewall for an edge/DMZ segment) and an
    L2 switch, stacked by tier. Every segment shown was reachable from the assessment
    host; a switch is the standard L2-segment symbol (recce does not fingerprint physical
    switches).

    **With topology ingested** (an on-target enum's routes/interfaces folded in via
    `ingest`): the generic core is replaced by the **real gateway devices** (their IPs
    from `NET-ROUTE default via …`), segments connect to their actual gateway, and
    **dual-homed pivots draw a direct segment-to-segment link** — the observed way those
    segments connect. It gets more accurate the more footholds you feed it."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 360 60" width="360" height="60" role="img" '
                'aria-label="Network architecture"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    dc_names = ad_dc_names(ad_data)
    segs = _segments(up, dc_names)
    doms = domains or ad.derive_domains(up)
    has_topo = any((getattr(h, "topology", None) or {}) for h in up)
    if has_topo:
        return _arch_topology(up, segs, doms)
    return _arch_logical(up, segs, doms)


def _svg_wrap(W, H, els, label="Network architecture"):
    return (f'<svg viewBox="0 0 {int(W)} {int(H)}" width="{int(W)}" height="{int(H)}" '
            f'role="img" aria-label="{label}" '
            f'font-family="system-ui,Segoe UI,Arial,sans-serif">'
            f'<rect width="{int(W)}" height="{int(H)}" fill="#ffffff"/>'
            + "".join(els) + "</svg>")


def _arch_logical(up, segs, doms):
    """Core-based layout used when no host topology has been ingested."""
    m, segGap, PER, chain = 26, 28, 4, 48
    ncol = min(PER, len(segs))
    nrow = -(-len(segs) // ncol)
    W = m * 2 + ncol * _SEG_W + (ncol - 1) * segGap
    els = ['<text x="26" y="24" font-size="16" font-weight="700" fill="#0f766e">'
           'Network architecture <tspan font-size="11" font-weight="400" fill="#5f6f6e">'
           '· logical — infrastructure &amp; segments</tspan></text>']
    ad_els, ad_anchors, ady = _ad_nodes(doms, 40, m)
    els += ad_els
    y = ady + (14 if doms else 0)
    coreY, coreH = y + 6, 30
    els.append(f'<rect x="{m}" y="{coreY}" width="{W - 2 * m}" height="{coreH}" rx="15" '
               f'fill="#e7efee" stroke="#0f766e" stroke-width="1.6"/>')
    els.append(f'<text x="{W / 2:.0f}" y="{coreY + 20}" text-anchor="middle" font-size="12" '
               f'font-weight="700" fill="#0f766e">Routed core — all {len(up)} host(s) '
               f'reachable from the assessment host</text>')
    for ax in ad_anchors:
        els.append(f'<line x1="{ax:.0f}" y1="{ady}" x2="{ax:.0f}" y2="{coreY}" '
                   f'stroke="{_DOMAIN_COLOR[1]}" stroke-width="1.4" stroke-dasharray="4 3"/>')
    gy0 = coreY + coreH
    for i, z in enumerate(segs):
        r, c = divmod(i, ncol)
        zx = m + c * (_SEG_W + segGap)
        chainTop = gy0 + r * (chain + _ZONE_H + 26)
        cx = zx + _SEG_W / 2
        zy = chainTop + chain
        els.append(f'<line x1="{cx:.0f}" y1="{chainTop}" x2="{cx:.0f}" y2="{zy}" '
                   f'stroke="#9fb3b0" stroke-width="1.4"/>')
        gwkind = "firewall" if z["tier"] == 0 else "router"
        gcol = "#C15A11" if gwkind == "firewall" else "#1f4e9c"
        els.append(f'<rect x="{cx - 15:.0f}" y="{chainTop + 12}" width="30" height="24" '
                   f'rx="6" fill="#ffffff" stroke="{gcol}" stroke-width="1.2"/>')
        els.append(net_glyph(gwkind, cx - 11, chainTop + 14, 20, gcol))
        gwlab = gwkind + (f" · {z['gw']}" if z["gw"] else " (gateway)")
        els.append(f'<text x="{cx + 20:.0f}" y="{chainTop + 28}" font-size="9.5" '
                   f'fill="#6f7a78">{_x(gwlab, 22)}</text>')
        els += _draw_zone(zx, zy, z)
    H = gy0 + nrow * (chain + _ZONE_H + 26) + 40
    els.append(f'<text x="{m}" y="{H - 14:.0f}" font-size="9.5" fill="#8a9997">'
               'Logical view: a switch = one L2 segment; gateways are shown per segment '
               '(feed an on-target enum\'s routes via `ingest` for real gateway IPs and '
               'inter-segment links). Every segment was reachable from the assessment host.'
               '</text>')
    return _svg_wrap(W, H, els)


def _arch_topology(up, segs, doms):
    """Topology-driven layout: real gateway devices (from ingested routes) with segments
    hung off their actual gateway, plus direct pivot links between dual-homed segments."""
    m, segGap = 26, 28
    ncol = min(5, len(segs))
    nrow = -(-len(segs) // ncol)
    W = m * 2 + ncol * _SEG_W + (ncol - 1) * segGap
    sub_index = {z["sub"]: i for i, z in enumerate(segs)}

    els = ['<text x="26" y="24" font-size="16" font-weight="700" fill="#0f766e">'
           'Network architecture <tspan font-size="11" font-weight="400" fill="#5f6f6e">'
           '· topology-driven — real gateways &amp; inter-segment links</tspan></text>']
    ad_els, ad_anchors, ady = _ad_nodes(doms, 40, m)
    els += ad_els
    backboneY = ady + (24 if doms else 6) + 18
    # zone positions
    rowGap = 84
    zoneY0 = backboneY + 58
    pos = {}
    for i, z in enumerate(segs):
        r, c = divmod(i, ncol)
        zx = m + c * (_SEG_W + segGap)
        zy = zoneY0 + r * (_ZONE_H + rowGap)
        pos[i] = (zx, zy)

    # gateways: gw_ip -> segment indices it serves (from default routes)
    gw_segs: dict[str, list[int]] = {}
    for i, z in enumerate(segs):
        if z["gw"]:
            gw_segs.setdefault(z["gw"], []).append(i)
    # backbone line + core label
    els.append(f'<line x1="{m + 30}" y1="{backboneY + 12}" x2="{W - m - 30}" '
               f'y2="{backboneY + 12}" stroke="#0f766e" stroke-width="2"/>')
    els.append(f'<text x="{m}" y="{backboneY - 4}" font-size="10.5" font-weight="700" '
               f'fill="#0f766e">Routed backbone</text>')
    # gateway nodes, centred over the zones they serve
    gw_x = {}
    for gw, idxs in gw_segs.items():
        gx = sum(pos[i][0] + _SEG_W / 2 for i in idxs) / len(idxs)
        gx = min(max(gx, m + 40), W - m - 40)
        gw_x[gw] = gx
        # firewall if it fronts any edge/DMZ segment, else router
        fw = any(segs[i]["tier"] == 0 for i in idxs)
        gcol = "#C15A11" if fw else "#1f4e9c"
        els.append(f'<line x1="{gx:.0f}" y1="{backboneY + 12}" x2="{gx:.0f}" '
                   f'y2="{backboneY + 36}" stroke="#9fb3b0" stroke-width="1.2"/>')
        els.append(f'<rect x="{gx - 15:.0f}" y="{backboneY}" width="30" height="24" rx="6" '
                   f'fill="#fff" stroke="{gcol}" stroke-width="1.3"/>')
        els.append(net_glyph("firewall" if fw else "router", gx - 11, backboneY + 2, 20, gcol))
        els.append(f'<text x="{gx:.0f}" y="{backboneY + 48}" text-anchor="middle" '
                   f'font-size="9.5" font-weight="700" fill="{gcol}">'
                   f'{"firewall" if fw else "router"} {gw}</text>')
    for ax in ad_anchors:
        els.append(f'<line x1="{ax:.0f}" y1="{ady}" x2="{ax:.0f}" y2="{backboneY + 12}" '
                   f'stroke="{_DOMAIN_COLOR[1]}" stroke-width="1.4" stroke-dasharray="4 3"/>')

    # segment -> its gateway (solid) or -> backbone if gateway unknown (dashed)
    for i, z in enumerate(segs):
        zx, zy = pos[i]
        cx = zx + _SEG_W / 2
        if z["gw"] and z["gw"] in gw_x:
            els.append(f'<path d="M{cx:.0f},{zy} C{cx:.0f},{zy - 24} '
                       f'{gw_x[z["gw"]]:.0f},{backboneY + 60} {gw_x[z["gw"]]:.0f},'
                       f'{backboneY + 36}" fill="none" stroke="#9fb3b0" stroke-width="1.4"/>')
        else:
            els.append(f'<line x1="{cx:.0f}" y1="{zy}" x2="{cx:.0f}" y2="{backboneY + 12}" '
                       f'stroke="#c3ccca" stroke-width="1.2" stroke-dasharray="3 3"/>')
            els.append(f'<text x="{cx:.0f}" y="{zy - 6}" text-anchor="middle" font-size="9" '
                       f'fill="#a3adab">gateway not observed</text>')
        els += _draw_zone(zx, zy, z)

    # pivot links: a dual-homed host bridges two segments directly (observed, ground truth)
    adj = adjacency(up)
    pivot_edges = []
    seen = set()
    for pip, subs in adj["pivots"].items():
        idxs = [sub_index[s] for s in subs if s in sub_index]
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                key = tuple(sorted((idxs[a], idxs[b])))
                if key in seen:
                    continue
                seen.add(key)
                pivot_edges.append((key[0], key[1], pip))
    for ia, ib, pip in pivot_edges:
        (xa, ya), (xb, yb) = pos[ia], pos[ib]
        cxa, cxb = xa + _SEG_W / 2, xb + _SEG_W / 2
        y1, y2 = ya + _ZONE_H, yb + _ZONE_H
        midx, midy = (cxa + cxb) / 2, max(y1, y2) + 34
        els.append(f'<path d="M{cxa:.0f},{y1} Q{midx:.0f},{midy:.0f} {cxb:.0f},{y2}" '
                   f'fill="none" stroke="#C15A11" stroke-width="1.8" stroke-dasharray="5 3"/>')
        els.append(f'<rect x="{midx - 58:.0f}" y="{midy - 20:.0f}" width="116" height="16" '
                   f'rx="8" fill="#fff6e6" stroke="#C15A11" stroke-width="1"/>')
        els.append(f'<text x="{midx:.0f}" y="{midy - 8:.0f}" text-anchor="middle" '
                   f'font-size="9.5" font-weight="700" fill="#7a3a0a">pivot · {pip}</text>')

    extra = 60 if pivot_edges else 0
    H = zoneY0 + nrow * (_ZONE_H + rowGap) + extra
    npivot = len(pivot_edges)
    els.append(f'<text x="{m}" y="{H - 14:.0f}" font-size="9.5" fill="#8a9997">'
               f'Topology-driven: gateway devices &amp; IPs are real (ingested host routes); '
               f'dashed orange = a dual-homed host bridging two segments '
               f'({npivot} observed). A switch = one L2 segment (not a fingerprinted device).'
               f'</text>')
    return _svg_wrap(W, H, els)
