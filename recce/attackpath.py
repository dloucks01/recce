"""Attack-path synthesis - the "so what".

Chains recce's CONFIRMED findings into a prioritised path an attacker would walk:
foothold -> privilege escalation -> credential access -> lateral movement -> (in
AD) domain dominance. Grounded entirely in what recce already found; every step
names the specific host and the EXISTING tool. No new scanning, no exploit code -
it reuses the exploitation actions and orders them into stages.
"""
from __future__ import annotations

import re

from .models import Host
from . import exploitplan as xp

STAGE_ORDER = ["Initial Access", "Privilege Escalation", "Credential Access",
               "Lateral Movement", "Domain Dominance"]

# playbook (post-shell) id -> attack stage. Escalation vs. credential-theft.
_PLAY_STAGE = {
    "win-seimpersonate": "Privilege Escalation",
    "win-alwaysinstallelevated": "Privilege Escalation",
    "win-unquoted": "Privilege Escalation",
    "win-writable-service": "Privilege Escalation",
    "win-sebackup": "Credential Access",
    "win-gpp-cpassword": "Credential Access",
    "win-stored-cred": "Credential Access",
    "lin-sudo": "Privilege Escalation",
    "lin-suid": "Privilege Escalation",
    "lin-writable-passwd": "Privilege Escalation",
    "lin-readable-shadow": "Credential Access",
    "lin-docker": "Privilege Escalation",
    "lin-lxd": "Privilege Escalation",
    "lin-pwnkit": "Privilege Escalation",
    "lin-dirtypipe": "Privilege Escalation",
    "lin-writable-cron": "Privilege Escalation",
    "lin-ld-preload": "Privilege Escalation",
}


def _step(stage, ip, hostname, title, tool, cmd, why, key):
    return {"stage": stage, "ip": ip, "hostname": hostname, "title": title,
            "tool": tool, "cmd": cmd, "why": why, "key": key}


def _stage_for_action(a: dict) -> str:
    kind = a["kind"]
    text = (a["finding"] or "").lower()
    if kind == "remote-msf":
        return "Initial Access"
    if kind == "remote-tool":
        if any(k in text for k in ("as-rep", "kerberoast", "relay", "ntlm")):
            return "Domain Dominance"
        return "Initial Access"
    if kind == "post-shell":
        pid = a["key"].split(":")[-1]
        return _PLAY_STAGE.get(pid, "Privilege Escalation")
    return "Privilege Escalation"


def _lateral_summary(hosts: list[Host]) -> list[dict]:
    """Scope-level lateral-movement options from the remote-access surface (used
    once you hold a credential/hash), rather than one row per host."""
    def with_port(*ports):
        return [h.ip for h in hosts
                if set(ports) & {p.portid for p in h.open_ports}]
    out = []
    smb = with_port(445, 139)
    if smb:
        out.append(_step("Lateral Movement", ", ".join(smb[:6]), "",
                         f"SMB exec / password spray ({len(smb)} host(s))",
                         "netexec / impacket (existing)",
                         "netexec smb <subnet> -u <user> -p <pass> --shares   ; "
                         "impacket-psexec <user>@<ip>  (or -hashes :<nthash> for PtH)",
                         "Reuse a captured credential/hash to authenticate and execute "
                         "across the SMB estate.", "path:lateral:smb"))
    winrm = with_port(5985, 5986)
    if winrm:
        out.append(_step("Lateral Movement", ", ".join(winrm[:6]), "",
                         f"WinRM remote shell ({len(winrm)} host(s))",
                         "evil-winrm / netexec (existing)",
                         "evil-winrm -i <ip> -u <user> -p <pass>   (or -H <nthash>)",
                         "WinRM gives a full remote PowerShell with valid creds or a "
                         "hash.", "path:lateral:winrm"))
    rdp = with_port(3389)
    if rdp:
        out.append(_step("Lateral Movement", ", ".join(rdp[:6]), "",
                         f"RDP session ({len(rdp)} host(s))", "xfreerdp (existing)",
                         "xfreerdp /v:<ip> /u:<user> /p:<pass> +clipboard",
                         "RDP is a login/pivot vector once you hold creds.",
                         "path:lateral:rdp"))
    ssh = with_port(22)
    if ssh:
        out.append(_step("Lateral Movement", ", ".join(ssh[:6]), "",
                         f"SSH access ({len(ssh)} host(s))", "ssh / sshpass (existing)",
                         "ssh <user>@<ip>   (spray a recovered key/password)",
                         "Reuse recovered SSH keys/passwords - reuse is common.",
                         "path:lateral:ssh"))
    return out


def build(hosts: list[Host]) -> list[dict]:
    """Ordered attack-path steps (by stage), grounded in confirmed findings."""
    steps: list[dict] = []
    seen: set[str] = set()
    for a in xp.all_actions(hosts):
        stage = _stage_for_action(a)
        if a["key"] in seen:
            continue
        seen.add(a["key"])
        steps.append(_step(stage, a["ip"], a["hostname"], a["finding"],
                           a["tool"], a["cmd"], a["validate"], a["key"]))
    steps.extend(_lateral_summary(hosts))
    steps.sort(key=lambda s: STAGE_ORDER.index(s["stage"]))
    return steps


def _label(s: str, n: int = 40) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    return (s[: n - 1] + "…") if len(s) > n else s


# Stage palette (fill, stroke), left-to-right through the kill chain.
_STAGE_COLOR = {
    "Initial Access": ("#e8f4ec", "#2E7D32"),
    "Privilege Escalation": ("#fbf3e0", "#9C7A00"),
    "Credential Access": ("#e7eefb", "#1f4e9c"),
    "Lateral Movement": ("#f3eefb", "#6b4fa0"),
    "Domain Dominance": ("#fbe3e3", "#C00000"),
}


def svg(hosts: list[Host], steps: list[dict] | None = None) -> str:
    """A directly-viewable inline SVG of the attack path — renders in any browser with
    no tools or JavaScript (and prints to PDF). Left-to-right stage columns of step
    cards (a device icon by role + host + finding), stage-to-stage arrows, and dashed
    same-host connectors showing one box being walked through the stages."""
    from html import escape as _e
    from . import netmap as _nm
    steps = steps if steps is not None else build(hosts)
    used = [st for st in STAGE_ORDER if any(s["stage"] == st for s in steps)]
    if not steps:
        return ('<svg viewBox="0 0 340 60" width="340" height="60" role="img" '
                'aria-label="Attack path"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No confirmed attack path yet.</text></svg>')

    ip_role = {h.ip: _nm.role_with_ad(h, set()) for h in (hosts or [])}
    m, headerH, cardW, cardH, vgap, colGap = 18, 34, 250, 60, 14, 46
    legendH = 26
    by_stage = {st: [s for s in steps if s["stage"] == st] for st in used}
    rows = max(len(v) for v in by_stage.values())
    W = m * 2 + len(used) * cardW + (len(used) - 1) * colGap
    H = m * 2 + headerH + 10 + rows * (cardH + vgap) + legendH
    geom: dict[tuple, tuple] = {}          # (ip, stage) -> (x, y, w, h)

    els = [
        '<defs>'
        '<filter id="apsh" x="-8%" y="-8%" width="116%" height="130%">'
        '<feDropShadow dx="0" dy="1" stdDeviation="1.2" flood-color="#0b1f1c" '
        'flood-opacity="0.14"/></filter>'
        '<marker id="apar" markerWidth="10" markerHeight="10" refX="7" refY="3.5" '
        'orient="auto"><path d="M0,0 L8,3.5 L0,7 Z" fill="#8a9997"/></marker>'
        '<marker id="apho" markerWidth="10" markerHeight="10" refX="7" refY="3.5" '
        'orient="auto"><path d="M0,0 L8,3.5 L0,7 Z" fill="#a273c2"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>',
    ]

    for ci, st in enumerate(used):
        x = m + ci * (cardW + colGap)
        fill, stroke = _STAGE_COLOR.get(st, ("#eef1f1", "#5f6f6e"))
        els.append(f'<rect x="{x}" y="{m}" width="{cardW}" height="{headerH - 8}" rx="7" '
                   f'fill="{stroke}"/>')
        els.append(f'<text x="{x + cardW / 2:.0f}" y="{m + 17}" text-anchor="middle" '
                   f'font-size="12.5" font-weight="700" fill="#ffffff" '
                   f'letter-spacing="0.3">{_e(st)}</text>')
        for ri, s in enumerate(by_stage[st]):
            y = m + headerH + 10 + ri * (cardH + vgap)
            geom[(s["ip"], st)] = (x, y, cardW, cardH)
            host = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
            kind = _nm.role_kind(ip_role.get(s["ip"], "Host"))
            els.append(f'<rect x="{x}" y="{y}" width="{cardW}" height="{cardH}" rx="9" '
                       f'fill="{fill}" stroke="{stroke}" stroke-width="1.5" '
                       f'filter="url(#apsh)"/>')
            els.append(f'<rect x="{x}" y="{y}" width="4" height="{cardH}" rx="2" '
                       f'fill="{stroke}"/>')            # stage accent bar
            els.append(_nm.glyph(kind, x + 12, y + cardH / 2 - 9, 18, stroke))
            els.append(f'<text x="{x + 38}" y="{y + 22}" font-size="11.5" '
                       f'font-weight="700" fill="#1a2422">{_e(_label(host, 26))}</text>')
            els.append(f'<text x="{x + 38}" y="{y + 40}" font-size="11" '
                       f'fill="#3a4644">{_e(_label(s["title"], 30))}</text>')

    # stage-to-stage flow arrows (header to header)
    for a, b in zip(range(len(used)), range(1, len(used))):
        xa = m + a * (cardW + colGap) + cardW
        xb = m + b * (cardW + colGap)
        yc = m + (headerH - 8) / 2
        els.append(f'<line x1="{xa + 6}" y1="{yc:.0f}" x2="{xb - 8}" y2="{yc:.0f}" '
                   f'stroke="#8a9997" stroke-width="2.2" marker-end="url(#apar)"/>')

    # same-host continuity across consecutive stages (dashed), right edge -> left edge
    for h in {s["ip"] for s in steps}:
        chain = [st for st in used if (h, st) in geom]
        for sa, sb in zip(chain, chain[1:]):
            xa, ya, wa, ha = geom[(h, sa)]
            xb, yb, _wb, hb = geom[(h, sb)]
            els.append(f'<path d="M{xa + wa},{ya + ha / 2:.0f} '
                       f'C{xa + wa + 24},{ya + ha / 2:.0f} {xb - 24},{yb + hb / 2:.0f} '
                       f'{xb - 6},{yb + hb / 2:.0f}" fill="none" stroke="#a273c2" '
                       f'stroke-width="1.6" stroke-dasharray="4 3" marker-end="url(#apho)"/>')

    # device-icon legend + same-host key
    ly = H - 9
    els.append(_nm.glyph_legend(m, ly - 13))
    els.append(f'<text x="{W - m:.0f}" y="{ly:.0f}" text-anchor="end" font-size="10.5" '
               f'fill="#a273c2">– – ▸ same host walked across stages</text>')

    body = "".join(els)
    return (f'<svg viewBox="0 0 {W} {int(H)}" width="{W}" height="{int(H)}" role="img" '
            f'aria-label="Attack path" font-family="system-ui,Segoe UI,Arial,sans-serif">'
            f'{body}</svg>')


def narrative(hosts: list[Host], steps: list[dict] | None = None) -> list[str]:
    """A short, grounded summary of the likely path (for the CLI + report)."""
    steps = steps if steps is not None else build(hosts)
    by_stage = {st: [s for s in steps if s["stage"] == st] for st in STAGE_ORDER}
    used = [st for st in STAGE_ORDER if by_stage[st]]
    lines = [f"{len(steps)} attack step(s) across {len(used)} stage(s): "
             f"{', '.join(used)}." if steps else "No confirmed attack path yet - "
             "run vulns / ingest to confirm findings."]
    if not steps:
        return lines
    dc = [h for h in hosts if "Domain Controller" in (h.roles or [])]
    ia = by_stage["Initial Access"]
    if ia:
        chain = [f"foothold via {ia[0]['title']} on {ia[0]['ip']}"]
        if by_stage["Privilege Escalation"]:
            chain.append("escalate locally to SYSTEM/root")
        if by_stage["Credential Access"]:
            chain.append("harvest credentials/hashes")
        if by_stage["Lateral Movement"]:
            chain.append("reuse them to move laterally")
        if dc and by_stage["Domain Dominance"]:
            chain.append(f"pivot to domain compromise ({dc[0].ip})")
        lines.append("Likely path: " + " -> ".join(chain) + ".")
    elif dc and by_stage["Domain Dominance"]:
        lines.append(f"AD attack surface on the DC ({dc[0].ip}): "
                     + "; ".join(s["title"] for s in by_stage["Domain Dominance"][:3]) + ".")
    return lines
