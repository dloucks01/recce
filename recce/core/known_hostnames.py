"""Cross-service "hostnames known to this engagement" reader.

Every enumeration path that produces DNS names for a host — nmap PTR, LDAP
`dnsHostName`, NTLM Type 2 target-info, SMB session-setup workstation,
Kerberos SPN, on-target enum, manual `-H`, mDNS, cert SAN — lands them in
`Host.hostnames` (short names and FQDNs both). Individual consumers today
tend to reach into `Host.hostnames` directly, but for cross-host uses
(vhost fuzzing, SPN construction against an unknown target, cert-coverage
audit) the wanted view is:

  * for THIS host, the prioritized list of names (FQDN-first, then shorts)
  * for the WHOLE engagement, the union — so a name learned from server A
    can be tried against server B when a virtual-hosted service could
    live on either

This module is that reader. It never invents names — the store is the
authority — and it deduplicates case-insensitively with first-seen casing
winning, since DNS is case-insensitive but tools display what they receive.

The `spn_candidates()` helper is the first cross-service reader: given a
host and a Kerberos service class ("HTTP", "MSSQLSvc", "CIFS", ...), it
constructs the SPN strings the KDC will accept — `{svc}/{fqdn}` and
`{svc}/{fqdn}:{port}` — from every FQDN known for the host. That's what
kerberoast/S4U2Self attacks need to build the sname of a TGS request.
"""
from __future__ import annotations

import re

from .models import Host


# An FQDN has at least one dot AND its labels look DNS-shaped (RFC 1035
# label = letter/digit start, letter/digit/hyphen inside, letter/digit
# end, ≤63 chars). Reject `foo.local:8080`, `hostname.`, or `[fe80::1]`.
_LABEL = re.compile(r"^(?=.{1,63}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_fqdn(name: str) -> bool:
    if "." not in name or name.endswith("."):
        return False
    labels = name.strip(".").split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL.match(lbl) for lbl in labels)


def _clean(name: str) -> str:
    """Lower-case, strip trailing dot, strip port suffix if any."""
    n = (name or "").strip().rstrip(".").lower()
    if ":" in n and not n.startswith("["):
        # `host:port` variant from parsed URLs — drop the port
        n = n.split(":", 1)[0]
    return n


def hostnames_for(host: Host, *, only_fqdn: bool = False) -> list[str]:
    """Names carried directly on this host, FQDNs first then shorts.

    Preserves first-seen casing (name comparisons stay case-insensitive
    but tools display what they saw). NTLM-learned FQDN is pulled in from
    `host.ntlm['fqdn']` if present, since not every producer folds that
    into `host.hostnames`.
    """
    picked: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        n = (raw or "").strip().rstrip(".")
        if not n:
            return
        key = _clean(n)
        if key and key not in seen:
            seen.add(key)
            picked.append(n)

    # NTLM-derived FQDN is the most authoritative — the server told us
    # this is its own name — so surface it first when present.
    ntlm = getattr(host, "ntlm", None) or {}
    for k in ("fqdn", "dns_computer", "dns_domain"):
        v = ntlm.get(k) if isinstance(ntlm, dict) else None
        if v:
            _add(str(v))
    for h in (host.hostnames or []):
        _add(h)

    if only_fqdn:
        picked = [n for n in picked if _is_fqdn(n)]

    # Stable priority: FQDNs first (routable, cert-relevant), then shorts.
    return sorted(picked, key=lambda n: (0 if _is_fqdn(n) else 1,
                                         picked.index(n)))


def known_hostnames(hosts: list[Host], *, only_fqdn: bool = False,
                    cap: int = 500) -> dict:
    """Engagement-wide name union across every host.

    Returns:
      {"names":       [str, ...],     # deduped, FQDN-first
       "by_host":     {ip: [str, ...]},
       "total_known": int,
       "capped":      bool}
    """
    by_host: dict[str, list[str]] = {}
    all_names: list[str] = []
    seen_all: set[str] = set()
    for h in hosts:
        picked = hostnames_for(h, only_fqdn=only_fqdn)
        if picked:
            by_host[h.ip] = picked
        for n in picked:
            key = _clean(n)
            if key not in seen_all:
                seen_all.add(key)
                all_names.append(n)
    names = sorted(all_names, key=lambda n: (0 if _is_fqdn(n) else 1,
                                             all_names.index(n)))
    total = len(names)
    capped = total > cap
    return {"names": names[:cap], "by_host": by_host,
            "total_known": total, "capped": capped}


def cert_covers(cert_sans: list[str], want: str) -> bool:
    """RFC 6125 dNSName coverage: exact match or single-label wildcard.

    `*.example.com` covers `foo.example.com` but NOT `foo.bar.example.com`
    (wildcard consumes exactly one label, per RFC 6125 §6.4.3) and NOT
    `example.com` itself. Comparison is case-insensitive per RFC 4343.
    """
    want_l = _clean(want)
    if not want_l or "." not in want_l:
        return False
    for san in cert_sans or []:
        san_l = _clean(san)
        if not san_l:
            continue
        if san_l == want_l:
            return True
        if san_l.startswith("*."):
            base = san_l[2:]
            # wildcard must consume EXACTLY one label
            if want_l.endswith("." + base):
                head = want_l[:-(len(base) + 1)]
                if head and "." not in head:
                    return True
    return False


def spn_candidates(host: Host, service: str, port: int | None = None,
                   *, include_short: bool = False) -> list[str]:
    """Kerberos SPN strings the KDC will accept for this host.

    RFC 4120: SPN is `{service}/{instance}[:{port}][/{name}]`. Windows
    KDCs also register short-name SPNs but the fully-qualified form is
    the reliable one — the short form is off by default here because it
    generates duplicate TGS requests when both forms map to the same
    account.

    Examples:
      spn_candidates(dc, "HTTP")             → ["HTTP/dc01.corp.local"]
      spn_candidates(sql, "MSSQLSvc", 1433)  → ["MSSQLSvc/sql01.corp.local:1433"]
    """
    if not service or "/" in service:
        return []
    out: list[str] = []
    for name in hostnames_for(host, only_fqdn=True):
        instance = f"{service}/{name}"
        if port is not None:
            instance = f"{instance}:{port}"
        if instance not in out:
            out.append(instance)
    if include_short:
        for name in hostnames_for(host):
            if _is_fqdn(name):
                continue
            instance = f"{service}/{name}"
            if port is not None:
                instance = f"{instance}:{port}"
            if instance not in out:
                out.append(instance)
    return out
