"""Cross-service "users known to this engagement" builder.

Every enumeration path that produces user names (LDAP, BloodHound, SMB SAMR,
SNMP LanMan MIB, netexec user enum) lands them as `Account(kind="user")` rows
on a Host in the store. This module unions those into one prioritized list
that other capability probes can consume — the same principle as the
credential-stack that feeds the spray, but for username-only surfaces.

The immediate consumer is the IPMI RAKP sweep: rather than the 8 hardcoded
BMC defaults, it now sees every user recce has learned about + those
defaults. The design generalises to future consumers:
  * SMB user enum against unknown DCs (add known names to the RID-cycle set)
  * SSH username spray (before hashcat has cracked anything)
  * SNMPv3 user enumeration via engineID discovery

Volume is bounded by `cap`, prioritized so a BloodHound import of 3000 users
does not blow up a scan against one BMC:
  1. Admin accounts (adminCount=1, "domain admins" in memberOf, well-known
     admin names)
  2. Service-y accounts (svc*, sql*, iis*, backup*, sccm* — these usually
     have IPMI/BMC delegated access)
  3. Everything else
Duplicates are collapsed case-insensitively but the first-seen casing wins,
because BMCs vary in whether they upper-case the name.
"""
from __future__ import annotations

import re

from ..core.models import Host


_ADMIN_NAME_HINT = re.compile(r"^(?:administrator|admin|root|da_|sa_)", re.I)
_SERVICE_NAME_HINT = re.compile(r"^(?:svc|sql|iis|backup|sccm|scom|nagios|"
                                r"veeam|hpom|ilo|ipmi|bmc|drac)_?", re.I)
# memberOf lands as an LDAP DN chain — cn=Domain Admins,dc=corp — so the group
# name is bounded by = and , rather than whitespace. Match on the group-name
# body, not on word boundaries.
_ADMIN_GROUP_HINT = re.compile(r"(?:domain admins|enterprise admins|"
                               r"administrators|schema admins|backup operators)",
                               re.I)


def _priority(name: str, attrs: dict) -> int:
    """Lower number = tried sooner. 0 = admin, 1 = service, 2 = other."""
    if str(attrs.get("admincount") or "") == "1":
        return 0
    if _ADMIN_NAME_HINT.match(name or ""):
        return 0
    memberof = str(attrs.get("memberof") or "")
    if memberof and _ADMIN_GROUP_HINT.search(memberof):
        return 0
    if _SERVICE_NAME_HINT.match(name or ""):
        return 1
    return 2


def collect_user_accounts(hosts: list[Host]) -> list[dict]:
    """Every user-kind Account across every host, deduped by lowercase name.

    Returns [{"name", "domain", "priority", "sources": [source]}] ordered by
    priority then insertion. First-seen casing wins for the display name.
    """
    by_key: dict[str, dict] = {}
    for h in hosts:
        for a in getattr(h, "accounts", None) or []:
            if a.kind != "user" or not a.name:
                continue
            # Local-account naming quirk: SMB SAMR sometimes surfaces
            # DOMAIN\name; strip the domain prefix so RID cycling and BMC
            # sweeps do not treat it as literally that whole string.
            name = a.name.split("\\", 1)[-1]
            key = name.lower()
            entry = by_key.get(key)
            if entry is None:
                entry = {"name": name, "domain": a.domain or "",
                         "priority": _priority(name, a.attrs or {}),
                         "sources": []}
                by_key[key] = entry
            else:
                # Re-evaluate priority — a later source may add adminCount/memberof.
                p = _priority(name, a.attrs or {})
                if p < entry["priority"]:
                    entry["priority"] = p
            if a.source and a.source not in entry["sources"]:
                entry["sources"].append(a.source)
    return sorted(by_key.values(), key=lambda x: (x["priority"], x["name"].lower()))


def known_users(hosts: list[Host], cap: int = 25,
                extras: list[str] | None = None) -> dict:
    """Prioritized user list for a probe with `cap` request budget.

    Returns:
      {"users":       [str, ...],     # names to actually probe, size ≤ cap
       "capped":      bool,           # True if `known` exceeded the cap
       "total_known": int,            # total unique users the store carried
       "sources":     [str, ...]}     # union of source labels contributing

    `extras` is prepended verbatim (typically the vendor-default BMC list for
    IPMI, or an operator-supplied `--rakp-users` argument). Extras always
    fit — the cap applies to what recce ADDS from the store.
    """
    extras = list(extras or [])
    accounts = collect_user_accounts(hosts)
    total = len(accounts)
    sources = sorted({s for a in accounts for s in a["sources"]})

    have = {n.lower() for n in extras}
    picked: list[str] = list(extras)
    added = 0
    for a in accounts:
        if a["name"].lower() in have:
            continue
        if added >= cap:
            break
        picked.append(a["name"])
        have.add(a["name"].lower())
        added += 1
    return {"users": picked, "capped": total > added,
            "total_known": total, "sources": sources}
