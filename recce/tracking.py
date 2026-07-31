"""Coverage-tracking primitives shared by the store, reports and CLI.

Every trackable item (host, service, vuln, AD quick-win, account, subnet) has a
stable string key. The same key is:
  - written into a hidden "Key" column in each workbook sheet,
  - read back from an operator-edited workbook,
  - stored in the datastore's `tracking` table,
  - used to compute live coverage percentages.

Keeping the key logic in one place guarantees generation, read-back and coverage
never drift apart.
"""

from __future__ import annotations

from typing import Any

# Categories that count toward coverage %, in display order.
COVERAGE_CATEGORIES = ["hosts", "services", "web", "vulns", "exploits", "quick_wins", "accounts"]

# Per-host workflow steps shown as checkboxes on the Checklist: header -> step id.
# Two kinds of step:
#   * auto surfaces  - the tool fills them in (enum/vuln/web/db), shown only where
#     that surface exists on the host (else N/A). The long tail of services
#     (SMB, remote access, mail, SNMP, ...) is tracked per-port on the Services
#     tab instead of adding a column here.
#   * manual markers - operator sign-offs the tool can't detect: AD review and
#     the kill-chain (access -> priv-esc -> creds -> lateral). These start
#     unchecked and you tick them as you go.
# Order follows the natural engagement flow.
STEP_COLUMNS = {"Enumerated": "enum", "Vuln-scan": "vuln", "Web": "web",
                "AD": "ad", "DB": "db", "Access": "access", "Priv-esc": "privesc",
                "Creds": "creds", "Lateral": "lateral"}

# Steps whose value is a pure manual operator sign-off (never auto-completed).
# Steps the tool can never complete for you - pure operator sign-offs (amber on the
# Checklist). `access` used to live here, but recce now auto-derives it (valid creds
# / local admin / a foothold the operator recorded), so it auto-ticks like a phase.
MANUAL_STEPS = {"ad", "creds", "lateral"}

# What a step cell shows when the step does not apply to a host (e.g. no web
# server -> no Web box; a non-DC host -> no AD box). Rendered instead of a
# checkbox and never counted as done or outstanding.
STEP_NA = "—"   # em dash


def access_from_findings(host) -> str:
    """A short description of a foothold recce can read from this host's findings,
    or '' if none. Keys only off STABLE, recce-generated script_ids (credenum /
    SSH), never title text - modules that know access at run time (mssql access
    matrix) set host.access_gained directly, so this only needs to catch the
    credential-based footholds that always carry a fixed id."""
    for v in getattr(host, "vulns", []):
        sid = (getattr(v, "script_id", "") or "").lower()
        if sid.startswith("cred-smb-admin"):
            return "SMB local admin (Pwn3d!)"
        if sid == "cred-secretsdump":
            return "SMB admin - secretsdump"
        if sid in ("ssh-sudo", "ssh-suid"):
            return "SSH foothold (credentialed enum ran)"
    return ""

# Ports/service hints used to decide which per-surface steps apply to a host.
_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443, 3000, 5000}
_WEB_SVC_HINTS = ("http", "https", "www")
# Directory / AD endpoints (a DC, not merely an SMB file server): LDAP, Kerberos,
# Global Catalog, kpasswd. SMB (139/445) is deliberately NOT here - a standalone
# SMB server is tracked per-port on Services, not as an AD host.
_AD_PORTS = {88, 389, 636, 3268, 3269, 464}
_AD_SVC_HINTS = ("ldap", "kerberos", "globalcat", "msft-gc")


def step_key(step: str, ip: str) -> str:
    return f"step:{step}:{ip}"


def _web_ports(host) -> list:
    out = []
    for p in host.open_ports:
        svc = (p.service or "").lower()
        if p.portid in _WEB_PORTS or any(k in svc for k in _WEB_SVC_HINTS):
            out.append(p)
    return out


def _has_ad_surface(host) -> bool:
    """True for domain/directory hosts (DCs) - where AD attack-path review applies."""
    if any("domain controller" in r.lower() or "directory" in r.lower()
           for r in host.roles):
        return True
    for p in host.open_ports:
        svc = (p.service or "").lower()
        if p.portid in _AD_PORTS or any(k in svc for k in _AD_SVC_HINTS):
            return True
    return False


def step_applies(host, step: str) -> bool:
    """Whether a step is relevant to this host at all.

    Non-applicable steps render as N/A on the Checklist rather than a checkbox,
    so a checked box always means real work happened (a non-DC host gets no AD
    box, a host with no database gets no DB box, etc.).
    """
    if step == "enum":
        return True
    if step in ("vuln", "access", "creds", "lateral"):
        # Anything with an open port can be vuln-scanned / attacked / looted /
        # pivoted from; a live host with nothing open has no such surface.
        return bool(host.open_ports)
    if step == "web":
        return bool(_web_ports(host))
    if step == "ad":
        return _has_ad_surface(host)
    if step == "db":
        from . import db as dbmod
        return bool(dbmod.db_ports(host))
    if step == "privesc":
        # Only relevant once there's a foothold to escalate from - which the tool
        # learns about when the priv-esc phase is actually run against the host.
        return host.privesc_checked
    return False


def step_auto(host, step: str) -> bool:
    """Tool-completion (done) state for an APPLICABLE step - the checkbox default.

    Only meaningful when step_applies(host, step) is true; callers render N/A for
    steps that don't apply. Manual steps (AD review, access/creds/lateral) always
    return False - they're operator sign-offs the tool can't complete for you.
    The operator can override any box on the sheet.
    """
    # A truncated sweep (host-timeout) left a PARTIAL port list, so the host is
    # not actually fully enumerated/vuln-scanned - don't auto-tick it done (it
    # stays outstanding, matching the ⚠ PARTIAL marker). Operator can override.
    complete = host.enumerated and not getattr(host, "incomplete_scan", False)
    if step == "enum":
        return complete
    if step == "vuln":
        op = host.open_ports
        return complete and bool(op) and all(p.vuln_scanned for p in op)
    if step == "web":
        wp = _web_ports(host)
        return complete and bool(wp) and all(p.vuln_scanned for p in wp)
    if step == "db":
        return host.db_scanned
    if step == "privesc":
        return host.privesc_checked
    if step == "access":
        # Auto-derived: recce confirmed a foothold (valid creds / local admin /
        # unauth RCE) or the operator recorded one. Still operator-overridable.
        return getattr(host, "access_gained", False)
    if step in MANUAL_STEPS:
        return False
    return False


def host_key(ip: str) -> str:
    return f"host:{ip}"


def svc_key(ip: str, proto: str, port: int) -> str:
    return f"svc:{ip}:{proto}:{port}"


def web_key(ip: str, port: int) -> str:
    return f"web:{ip}:{port}"


def vuln_key(ip: str, port: Any, script_id: str) -> str:
    return f"vuln:{ip}:{port or 0}:{script_id}"


def vuln_row_key(v: Any) -> str:
    """The single canonical key for a Vulnerabilities-sheet row, used by BOTH the
    sheet writer and coverage counting so a triaged finding is actually counted.
    (The two sites used different keys - script_id vs script_id+title - so the
    Triaged tick was invisible to compute_coverage.) Keys live in one place.

    The title slice must match models.Vuln.key's (60 chars): the store dedups
    vulns on title[:60], so a coarser key here would collapse two store-distinct
    findings into one Vulnerabilities row and undercount coverage."""
    return vuln_key(v.ip, v.port, f"{v.script_id}:{(v.title or '')[:60]}")


def exploit_key(ip: str, port: Any, edb_id: str) -> str:
    return f"exploit:{ip}:{port or 0}:{edb_id}"


def acct_key(source: str, kind: str, domain: str, name: str, rid: str = "") -> str:
    # The store dedups accounts on (source, kind, name, domain, rid), so the key
    # must include rid or two accounts identical but for their RID collapse to one
    # Users & Accounts row and undercount. Appended only when present, so existing
    # rid-less keys stay stable across an upgrade.
    base = f"acct:{source}:{kind}:{domain}:{name}"
    return f"{base}:{rid}" if rid else base


def prod_key(product_version_key: str) -> str:
    return f"prod:{product_version_key}"


def subnet_key(subnet: str) -> str:
    return f"subnet:{subnet}"


def item_keys(hosts: list) -> dict[str, list[str]]:
    """All trackable keys grouped by category (order-stable, deduplicated)."""
    from . import ad

    out: dict[str, list[str]] = {c: [] for c in COVERAGE_CATEGORIES}
    subnets: set[str] = set()
    seen: set[str] = set()

    def push(cat: str, key: str) -> None:
        if key not in seen:
            seen.add(key)
            out[cat].append(key)

    from . import web

    for h in hosts:
        # Only CONFIRMED-up hosts get a reviewable "hosts"/subnet key - the Checklist
        # (the sheet that carries those cells) renders up hosts only. Counting an
        # unconfirmed -Pn phantom here inflates the denominator with a key on no sheet,
        # so review coverage could never reach 100%. (Per-finding keys below are still
        # emitted for any host that carries them - those live on their own sheets.)
        if h.is_up:
            push("hosts", host_key(h.ip))
            subnets.add(h.subnet or "unknown")
        for p in h.open_ports:
            push("services", svc_key(h.ip, p.protocol, p.portid))
            if web.is_web(p):
                push("web", web_key(h.ip, p.portid))
        for v in h.vulns:
            push("vulns", vuln_row_key(v))
        for e in h.exploits:
            push("exploits", exploit_key(e.ip, e.port, e.edb_id))
        for a in h.accounts:
            push("accounts", acct_key(a.source, a.kind, a.domain, a.name, a.rid))

    for qw in ad.quick_wins(hosts):
        push("quick_wins", qw["key"])

    out["subnets"] = [subnet_key(s) for s in sorted(subnets)]
    return out


def compute_coverage(hosts: list, tracking: dict[str, tuple]) -> dict[str, dict]:
    """Return {category: {total, done, pct}} plus an 'overall' roll-up."""
    keys = item_keys(hosts)
    cov: dict[str, dict] = {}
    grand_total = grand_done = 0
    for cat in COVERAGE_CATEGORIES:
        ks = keys.get(cat, [])
        total = len(ks)
        done = sum(1 for k in ks if tracking.get(k, (False, ""))[0])
        cov[cat] = {"total": total, "done": done,
                    "pct": (100 * done // total if total else 100)}
        grand_total += total
        grand_done += done
    cov["overall"] = {"total": grand_total, "done": grand_done,
                      "pct": (100 * grand_done // grand_total if grand_total else 100)}
    return cov


def subnet_coverage(hosts: list, tracking: dict[str, tuple]) -> dict[str, dict]:
    """Per-subnet host-review coverage (confirmed-up hosts only, matching the
    Checklist and the Overview's Live-hosts table)."""
    agg: dict[str, dict] = {}
    for h in hosts:
        if not h.is_up:
            continue
        s = h.subnet or "unknown"
        a = agg.setdefault(s, {"total": 0, "done": 0})
        a["total"] += 1
        if tracking.get(host_key(h.ip), (False, ""))[0]:
            a["done"] += 1
    for s, a in agg.items():
        a["pct"] = 100 * a["done"] // a["total"] if a["total"] else 0
    return agg
