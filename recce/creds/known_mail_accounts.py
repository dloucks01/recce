"""Cross-service "mail identities known to this engagement" reader.

Every enumeration path that leaks a valid mail account name — SMTP VRFY /
EXPN / RCPT (RFC 5321 §3.5 / §4.1.1.7 / §4.1.1.3), IMAP LOGIN response
differential (RFC 3501 §6.2.3), POP3 USER-before-PASS response differential
(RFC 1939 §5) — surfaces a `user@domain` identity. Consumers today read
each service's probe blob directly, so an SMTP-enumerated `alice` on box A
never gets tried against IMAP on box B, and a POP3 hit on box C never seeds
an SMTP recipient probe on box D. The three protocols share one account
namespace by design (RFC 8314); recce should treat them that way.

This reader unions them into one list so a spray hit on any one transport
auto-retries the other two. Duplicates collapse case-insensitively — RFC
5321 §2.3.11 permits case-sensitive local parts but every real MTA / IMAP /
POP3 server compares them case-insensitively, and mixing "Alice" and
"alice" as two accounts wastes budget. First-seen casing wins for display.
Domains compare case-insensitively per RFC 4343.

The AD bridge is `mail_users_for_ad(hosts, ad_domains)`: when a mail
account's domain matches an AD domain from known_domains, the username is a
first-class AD spray candidate (Exchange / M365 mail identity is the same
sAMAccountName), so the returned names feed known_users on the next pass.
"""
from __future__ import annotations

from ..core.models import Account, Host


_MAIL_KIND = "mail"


def _norm_domain(d: str) -> str:
    return (d or "").strip().rstrip(".").lower()


def _mail_domain_for_host(host: Host) -> str:
    """Best-guess mail domain for accounts LOCAL to this server.

    Strip the leading label off the host's first FQDN — `mail.corp.local`
    becomes `corp.local` — since a VRFY / LOGIN hit on the server names an
    account inside that server's own domain. Bare short-name hosts (no
    FQDN known) return "" and the account is recorded domain-less. The
    reader still cross-links those by username, so the "retry across
    transports" workflow works even with no domain.
    """
    from ..core.known_hostnames import hostnames_for
    fqdns = hostnames_for(host, only_fqdn=True)
    if not fqdns:
        return ""
    parts = fqdns[0].split(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def record_mail_account(host: Host, user: str, domain: str,
                        source: str) -> None:
    """Attach a mail-kind Account to `host` at enumeration time.

    Called from smtp/imap/pop3 probe paths. Idempotent: the same (user,
    domain) tuple already on the host has the new `source` merged in,
    never a duplicate row. First-seen casing wins for the display name.
    """
    u = (user or "").strip().split("\\", 1)[-1]
    d = (domain or "").strip().rstrip(".")
    if not u:
        return
    key_u = u.lower()
    key_d = d.lower()
    src = (source or "mail").strip()
    for a in host.accounts:
        if a.kind != _MAIL_KIND or not a.name:
            continue
        if a.name.lower() != key_u:
            continue
        if _norm_domain(a.domain) != key_d:
            continue
        # De-dupe sources — `a.source` is a comma-joined list, since
        # Account.source is a bare string. Order-preserving union.
        cur = [s for s in (a.source or "").split(",") if s]
        if src and src not in cur:
            cur.append(src)
            a.source = ",".join(cur)
        return
    host.accounts.append(Account(ip=host.ip, source=src, kind=_MAIL_KIND,
                                 name=u, domain=d))


def known_mail_accounts(hosts: list[Host]) -> dict:
    """Engagement-wide union of mail identities across every host.

    Returns:
      {"accounts": [{"user", "domain", "sources": [str], "hosts": [ip]}],
       "by_user":  {user_lower: [domain, ...]}}

    Ordering is stable — (user_lower, domain_lower) — so callers can diff
    two runs without churn. `hosts` on each entry is the IPs the identity
    was seen at (usually one, but a shared-mailbox address can surface on
    every transport it fronts).
    """
    by_key: dict[tuple[str, str], dict] = {}
    for h in hosts:
        for a in getattr(h, "accounts", None) or []:
            if a.kind != _MAIL_KIND or not a.name:
                continue
            key = (a.name.lower(), _norm_domain(a.domain))
            entry = by_key.get(key)
            if entry is None:
                entry = {"user": a.name, "domain": a.domain or "",
                         "sources": [], "hosts": []}
                by_key[key] = entry
            for s in (a.source or "").split(","):
                s = s.strip()
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)
            if h.ip and h.ip not in entry["hosts"]:
                entry["hosts"].append(h.ip)
    accounts = sorted(by_key.values(),
                      key=lambda x: (x["user"].lower(),
                                     _norm_domain(x["domain"])))
    by_user: dict[str, list[str]] = {}
    for e in accounts:
        u = e["user"].lower()
        bucket = by_user.setdefault(u, [])
        d = e["domain"]
        if d and d not in bucket:
            bucket.append(d)
    return {"accounts": accounts, "by_user": by_user}


def mail_users_for_ad(hosts: list[Host],
                      ad_domains: list[str]) -> list[str]:
    """Usernames whose mail domain matches an AD domain from known_domains.

    Exchange / M365 mail identities share the AD sAMAccountName, so a
    mail-side enumeration hit against `alice@corp.local` is a first-class
    AD spray candidate. Empty when `ad_domains` is empty or no mail
    identity is scoped to a known AD domain.

    Case-insensitive on both sides (RFC 4343). Preserves first-seen
    casing for the username so the AD wire displays what the mail server
    actually returned.
    """
    if not ad_domains:
        return []
    wanted = {_norm_domain(d) for d in ad_domains if d}
    wanted.discard("")
    if not wanted:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for e in known_mail_accounts(hosts)["accounts"]:
        if _norm_domain(e["domain"]) not in wanted:
            continue
        key = e["user"].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(e["user"])
    return out
