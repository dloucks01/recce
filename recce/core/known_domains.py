"""Cross-service "AD/Kerberos domains known to this engagement" reader.

Every enumeration path that touches an AD DC surfaces a domain string:

  * LDAP defaultNamingContext -> DNS domain (`dc=corp,dc=local` -> corp.local)
  * NTLM Type 2 target-info AV pairs -> both DNS and NetBIOS names
  * MSSQL windows-auth NTLM handshake -> same AV pairs
  * SMB session-setup -> workstation + primary domain
  * Kerberos AS-REP -> realm
  * BloodHound / netexec output -> per-account domain
  * Operator-supplied via `recce --domain CORP.LOCAL` -> store meta

Individual consumers today reach into whichever storage site is closest
(`h.ntlm.get("dns_domain")`, `store.get_meta("domain")`, iterating creds
for a `.domain`) and each one implements the "which domain is THE domain"
tiebreak differently.

This reader unions them, preserves the DNS <-> NetBIOS mapping (`corp.local`
and `CORP` are one domain, two names), and picks the engagement's primary
by count. That's what a fresh `recce ad kerberos` command needs when the
operator didn't pass `--domain` — right now it errors out; wired to this
reader, it picks the most-common domain across DC-flagged hosts.
"""
from __future__ import annotations

import re

from .models import Credential, Host


# NetBIOS domain names are 1-15 chars, uppercased, no dots. DNS domains
# have at least one dot. Both may appear in the same source — the reader
# doesn't guess based on the string alone; it uses whichever *key* the
# producer put the value under.
_NETBIOS_LEGAL = re.compile(r"^[A-Za-z0-9!@#$%^()\-_'{}.~]{1,15}$")


def _norm_dns(name: str) -> str:
    """Lowercase, strip trailing dot, strip any URL trappings."""
    n = (name or "").strip().rstrip(".").lower()
    if "/" in n:
        n = n.split("/", 1)[0]
    return n


def _norm_netbios(name: str) -> str:
    """Uppercase, strip whitespace. NetBIOS is case-insensitive but the
    universal convention is UPPERCASE — reports read wrong otherwise."""
    return (name or "").strip().upper()


def _dns_from_dn(dn: str) -> str:
    """`dc=corp,dc=local,dc=uk` -> `corp.local.uk`. Ignore RDNs that
    aren't DC=. Case-insensitive per RFC 4514."""
    parts = []
    for rdn in (dn or "").split(","):
        rdn = rdn.strip()
        if rdn.lower().startswith("dc="):
            parts.append(rdn[3:].strip())
    return ".".join(parts) if parts else ""


def _collect_from_host(host: Host) -> list[tuple[str, str, str]]:
    """(dns, netbios, source) tuples this host contributes. Empty strings
    mean 'this source didn't know that half'."""
    out: list[tuple[str, str, str]] = []
    ntlm = getattr(host, "ntlm", None) or {}
    if isinstance(ntlm, dict):
        # NTLM Type 2 AV pairs — the authoritative pair, matched on ONE
        # exchange so DNS↔NetBIOS map together.
        dns = _norm_dns(str(ntlm.get("dns_domain") or ""))
        nb = _norm_netbios(str(ntlm.get("netbios_domain") or ""))
        if dns or nb:
            out.append((dns, nb, "ntlm"))
        # Some NTLM implementations also surface a `dns_tree` (forest root
        # for domain-joined servers); record it as an unmatched DNS half.
        tree = _norm_dns(str(ntlm.get("dns_tree") or ""))
        if tree and tree != dns:
            out.append((tree, "", "ntlm-forest"))
    # LDAP defaultNamingContext lands the DN in host.ntlm too when
    # ldap.py runs; convert it to a dotted DNS form. Producer wrote it
    # under `default_naming_context` when present.
    if isinstance(ntlm, dict):
        dnc = str(ntlm.get("default_naming_context") or "")
        if dnc:
            dns = _dns_from_dn(dnc)
            if dns:
                out.append((dns, "", "ldap"))
    return out


def _collect_from_creds(creds: list[Credential] | None) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for c in (creds or []):
        d = (c.domain or "").strip()
        if not d:
            continue
        if "." in d:
            out.append((_norm_dns(d), "", c.source or "cred"))
        else:
            out.append(("", _norm_netbios(d), c.source or "cred"))
    return out


def known_domains(hosts: list[Host],
                  creds: list[Credential] | None = None,
                  operator_domain: str = "") -> dict:
    """Engagement-wide AD/Kerberos domain view.

    `operator_domain` is what the user passed on the CLI or seeded in
    store meta — always considered authoritative and always the primary
    when provided (an operator override beats guessed frequency).

    Returns:
      {"domains": [{"dns", "netbios", "sources", "host_count",
                    "cred_count", "is_primary"}],
       "primary_dns":     str,      # forest realm the operator should use
       "primary_netbios": str,
       "operator_domain": str,      # verbatim what was passed in
       "by_ip":           {ip: {"dns", "netbios"}},
       "total_known":     int}
    """
    tuples: list[tuple[str, str, str]] = []
    by_ip: dict[str, dict[str, str]] = {}
    # Track (dns_key, nb_key) SETS of hosts / cred-indices rather than raw
    # counters, so a host that surfaces BOTH DNS and NetBIOS for the same
    # domain is counted once when we later roll the NetBIOS half into the
    # DNS entry.
    hosts_by_dns: dict[str, set[str]] = {}
    hosts_by_nb: dict[str, set[str]] = {}
    creds_by_dns: dict[str, int] = {}
    creds_by_nb: dict[str, int] = {}

    for h in hosts:
        contribs = list(_collect_from_host(h))
        for a in getattr(h, "accounts", None) or []:
            d = (a.domain or "").strip()
            if not d:
                continue
            if "." in d:
                contribs.append((_norm_dns(d), "", a.source or "account"))
            elif _NETBIOS_LEGAL.match(d):
                contribs.append(("", _norm_netbios(d), a.source or "account"))
        for dns, nb, source in contribs:
            tuples.append((dns, nb, source))
            if dns:
                hosts_by_dns.setdefault(dns, set()).add(h.ip)
            if nb:
                hosts_by_nb.setdefault(nb, set()).add(h.ip)
            if dns or nb:
                slot = by_ip.setdefault(h.ip, {"dns": "", "netbios": ""})
                if dns and not slot["dns"]:
                    slot["dns"] = dns
                if nb and not slot["netbios"]:
                    slot["netbios"] = nb

    for dns, nb, _s in _collect_from_creds(creds):
        if dns:
            creds_by_dns[dns] = creds_by_dns.get(dns, 0) + 1
        if nb:
            creds_by_nb[nb] = creds_by_nb.get(nb, 0) + 1
        tuples.append((dns, nb, _s))

    # Build the merged (dns, netbios) mapping. When NTLM saw both in one
    # exchange we already have a pair; otherwise we do the safe thing and
    # keep DNS-only and NetBIOS-only entries separate — matching a bare
    # NetBIOS "CORP" to "corp.local" without evidence is a guess.
    pair_by_dns: dict[str, str] = {}
    pair_by_nb: dict[str, str] = {}
    sources_by_key: dict[tuple[str, str], set[str]] = {}
    for dns, nb, source in tuples:
        if dns and nb:
            pair_by_dns.setdefault(dns, nb)
            pair_by_nb.setdefault(nb, dns)
        key = (dns, nb)
        sources_by_key.setdefault(key, set()).add(source)

    # Merge singletons into pairs when the same producer eventually
    # supplied the missing half. Everything else stays as its own entry.
    all_dns = set(hosts_by_dns) | set(creds_by_dns) | set(pair_by_dns)
    all_nb = set(hosts_by_nb) | set(creds_by_nb) | set(pair_by_nb)
    entries: dict[tuple[str, str], dict] = {}
    for dns in all_dns:
        nb = pair_by_dns.get(dns, "")
        key = (dns, nb)
        # Union the host-sets so a host that surfaced both halves for the
        # same domain counts once, not twice.
        host_ips = set(hosts_by_dns.get(dns, set()))
        if nb:
            host_ips |= hosts_by_nb.get(nb, set())
        cred_c = creds_by_dns.get(dns, 0) + (creds_by_nb.get(nb, 0) if nb else 0)
        entries[key] = {"dns": dns, "netbios": nb,
                        "sources": set(),
                        "host_count": len(host_ips),
                        "cred_count": cred_c}
    for nb in all_nb:
        if pair_by_nb.get(nb, ""):
            key = (pair_by_nb[nb], nb)
            if key in entries:
                continue
        key = ("", nb)
        entries.setdefault(key, {"dns": "", "netbios": nb,
                                 "sources": set(), "host_count": 0,
                                 "cred_count": 0})
        entries[key]["host_count"] = max(entries[key]["host_count"],
                                         len(hosts_by_nb.get(nb, set())))
        entries[key]["cred_count"] += creds_by_nb.get(nb, 0)

    for (dns, nb), sources in sources_by_key.items():
        for k, v in entries.items():
            if (v["dns"] and v["dns"] == dns) or \
               (v["netbios"] and v["netbios"] == nb) or \
               ((dns, nb) == k):
                v["sources"].update(sources)

    # Primary selection. Operator supplied name wins outright; then most
    # hosts; then most creds; then whichever DNS entry exists at all.
    op = operator_domain or ""
    op_norm_dns = _norm_dns(op) if "." in op else ""
    op_norm_nb = _norm_netbios(op) if "." not in op else ""

    def _score(e: dict) -> tuple:
        # Prefer entries carrying a DNS name (Kerberos realms are DNS).
        return (bool(e["dns"]), e["host_count"], e["cred_count"])

    ranked = sorted(entries.values(), key=_score, reverse=True)
    primary_dns = ""
    primary_netbios = ""
    if op_norm_dns or op_norm_nb:
        # Try to match a known entry; else the operator name IS the primary.
        matched = False
        for e in ranked:
            if op_norm_dns and e["dns"] == op_norm_dns:
                primary_dns = e["dns"]
                primary_netbios = e["netbios"]
                e["is_primary"] = True
                matched = True
                break
            if op_norm_nb and e["netbios"] == op_norm_nb:
                primary_dns = e["dns"]
                primary_netbios = e["netbios"]
                e["is_primary"] = True
                matched = True
                break
        if not matched:
            primary_dns = op_norm_dns
            primary_netbios = op_norm_nb
    elif ranked:
        e = ranked[0]
        primary_dns = e["dns"]
        primary_netbios = e["netbios"]
        e["is_primary"] = True

    # Finalize serialization: sets -> sorted lists, is_primary present on
    # every entry (default False).
    final: list[dict] = []
    for e in ranked:
        final.append({
            "dns": e["dns"],
            "netbios": e["netbios"],
            "sources": sorted(e["sources"]),
            "host_count": e["host_count"],
            "cred_count": e["cred_count"],
            "is_primary": bool(e.get("is_primary")),
        })

    return {"domains": final,
            "primary_dns": primary_dns,
            "primary_netbios": primary_netbios,
            "operator_domain": op,
            "by_ip": by_ip,
            "total_known": len(final)}


def domain_for(host: Host, all_hosts: list[Host] | None = None) -> dict:
    """One host's best-known (dns, netbios) pair.

    Falls back to the engagement primary when the host itself carries
    neither — a member server that only speaks SMB may not surface its
    domain in the NTLM AV pairs, but its DC did.
    """
    single = known_domains([host])
    if single["primary_dns"] or single["primary_netbios"]:
        return {"dns": single["primary_dns"],
                "netbios": single["primary_netbios"]}
    if all_hosts:
        eng = known_domains(all_hosts)
        return {"dns": eng["primary_dns"], "netbios": eng["primary_netbios"]}
    return {"dns": "", "netbios": ""}


def kerberos_realm(hosts: list[Host], operator_domain: str = "") -> str:
    """The realm string to put in a Kerberos AS-REQ / TGS-REQ sname.

    Kerberos realms are conventionally uppercased DNS form (`CORP.LOCAL`).
    Returns empty string when no domain has been enumerated — the caller
    must decide whether to error ("no realm known, pass --domain") or
    fall back to a heuristic.
    """
    kd = known_domains(hosts, operator_domain=operator_domain)
    if kd["primary_dns"]:
        return kd["primary_dns"].upper()
    if kd["primary_netbios"]:
        # NetBIOS-only is rare in a real AD environment (NTLM would have
        # given us the DNS name too) but if that's all we have, upper it.
        return kd["primary_netbios"]
    return ""
