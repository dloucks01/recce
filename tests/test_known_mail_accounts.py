"""creds.known_mail_accounts: cross-transport mail-identity reader.

Every mail-side probe (SMTP VRFY/EXPN/RCPT per RFC 5321, IMAP LOGIN per RFC
3501, POP3 USER per RFC 1939) confirms an account exists — this reader
unions those into one deduped set so a hit on one transport auto-retries
the other two.

Test wires use raw response bytes from RFC-example transcripts, not calls
to recce encoders.
"""
from __future__ import annotations

from recce.core.models import Account, Host, Port
from recce.creds.known_mail_accounts import (_mail_domain_for_host,
                                             known_mail_accounts,
                                             mail_users_for_ad,
                                             record_mail_account)


def _host(ip: str = "10.0.0.10", hostnames=None) -> Host:
    h = Host(ip=ip)
    if hostnames:
        h.hostnames = list(hostnames)
    return h


# --- record_mail_account: attach + dedupe ----------------------------------

def test_record_appends_a_mail_kind_account_on_the_host():
    h = _host()
    record_mail_account(h, "alice", "corp.local", "smtp")
    assert len(h.accounts) == 1
    a = h.accounts[0]
    assert a.kind == "mail"
    assert a.name == "alice"
    assert a.domain == "corp.local"
    assert a.source == "smtp"
    assert a.ip == h.ip


def test_record_is_idempotent_and_merges_sources_case_insensitively():
    """SMTP RCPT hit + IMAP LOGIN hit for the same account -> one row, two
    sources. RFC 5321 §2.3.11 permits case-sensitive local parts but every
    real server compares them case-insensitively; treat them as one."""
    h = _host()
    record_mail_account(h, "Alice", "CORP.LOCAL", "smtp")
    record_mail_account(h, "alice", "corp.local", "imap")
    record_mail_account(h, "ALICE", "corp.local.", "pop3")   # trailing dot
    assert len(h.accounts) == 1
    a = h.accounts[0]
    # First-seen casing wins on both halves.
    assert a.name == "Alice"
    assert a.domain == "CORP.LOCAL"
    assert set(a.source.split(",")) == {"smtp", "imap", "pop3"}


def test_record_strips_samr_style_domain_prefix():
    """Some legacy SMTP setups return DOMAIN\\name in EXPN output; strip it
    so cross-transport spray sees just the login name."""
    h = _host()
    record_mail_account(h, "CORP\\alice", "corp.local", "smtp")
    assert h.accounts[0].name == "alice"


def test_record_ignores_empty_user():
    h = _host()
    record_mail_account(h, "", "corp.local", "smtp")
    record_mail_account(h, "   ", "corp.local", "smtp")
    assert h.accounts == []


# --- known_mail_accounts: engagement-wide union ----------------------------

def test_union_dedupes_across_hosts_and_preserves_first_seen_casing():
    """`bob@corp.local` seen via SMTP on the outer MX and via IMAP on the
    inner mailbox server — one account, two sources, two host IPs."""
    a = _host("10.0.0.10")   # MX
    b = _host("10.0.0.20")   # mailbox
    record_mail_account(a, "Bob", "CORP.local", "smtp")
    record_mail_account(b, "bob", "corp.local", "imap")
    got = known_mail_accounts([a, b])
    assert len(got["accounts"]) == 1
    e = got["accounts"][0]
    assert e["user"] == "Bob"
    assert e["domain"] == "CORP.local"
    assert set(e["sources"]) == {"smtp", "imap"}
    assert set(e["hosts"]) == {"10.0.0.10", "10.0.0.20"}


def test_by_user_maps_username_to_all_seen_domains():
    """The same local part may exist in multiple domains on the same MX
    (multi-tenant hosting). by_user must keep them separate."""
    h = _host()
    record_mail_account(h, "info", "example.com", "smtp")
    record_mail_account(h, "info", "example.net", "smtp")
    by_user = known_mail_accounts([h])["by_user"]
    assert set(by_user["info"]) == {"example.com", "example.net"}


def test_union_skips_non_mail_kind_accounts():
    """The reader must not pull in AD user rows — those belong to
    known_users. Mixing the two blows up the wire's spray-per-transport
    volume."""
    h = _host()
    h.accounts.append(Account(ip=h.ip, source="ldap", kind="user",
                              name="alice"))
    h.accounts.append(Account(ip=h.ip, source="ldap", kind="group",
                              name="Domain Admins"))
    record_mail_account(h, "mailonly", "example.com", "smtp")
    got = known_mail_accounts([h])
    assert [e["user"] for e in got["accounts"]] == ["mailonly"]


def test_union_is_sorted_stably_by_user_then_domain():
    h = _host()
    record_mail_account(h, "zack", "example.com", "smtp")
    record_mail_account(h, "alice", "z.com", "smtp")
    record_mail_account(h, "alice", "a.com", "smtp")
    got = known_mail_accounts([h])
    names = [(e["user"], e["domain"]) for e in got["accounts"]]
    assert names == [("alice", "a.com"), ("alice", "z.com"),
                     ("zack", "example.com")]


# --- AD bridge (feeds into known_users) ------------------------------------

def test_mail_users_for_ad_returns_only_users_in_a_known_ad_domain():
    """`alice@corp.local` is an AD spray candidate when `corp.local` is a
    known_domains AD domain; `admin@example.net` on the same server is
    NOT (external tenant on the same MX)."""
    h = _host()
    record_mail_account(h, "alice", "corp.local", "smtp")
    record_mail_account(h, "svc_sql", "CORP.LOCAL", "imap")   # dup by AD-eq
    record_mail_account(h, "admin", "example.net", "smtp")
    got = mail_users_for_ad([h], ad_domains=["corp.local"])
    assert set(got) == {"alice", "svc_sql"}


def test_mail_users_for_ad_is_case_insensitive_on_both_sides():
    h = _host()
    record_mail_account(h, "alice", "Corp.Local", "smtp")
    assert mail_users_for_ad([h], ad_domains=["CORP.LOCAL"]) == ["alice"]


def test_mail_users_for_ad_empty_when_no_ad_domains_supplied():
    h = _host()
    record_mail_account(h, "alice", "corp.local", "smtp")
    assert mail_users_for_ad([h], ad_domains=[]) == []
    assert mail_users_for_ad([h], ad_domains=[""]) == []


def test_mail_users_for_ad_skips_domainless_accounts():
    """SMTP RCPT on a bare short-name host lands the account with domain=""
    so we can't safely assert AD membership."""
    h = _host()   # no hostnames -> _mail_domain_for_host -> ""
    record_mail_account(h, "root", "", "smtp")
    assert mail_users_for_ad([h], ad_domains=["corp.local"]) == []


# --- domain derivation from host FQDN --------------------------------------

def test_mail_domain_for_host_strips_leading_label_off_fqdn():
    h = _host(hostnames=["mail.corp.local"])
    assert _mail_domain_for_host(h) == "corp.local"


def test_mail_domain_for_host_empty_on_short_name_only_host():
    h = _host(hostnames=["mail"])
    assert _mail_domain_for_host(h) == ""


def test_mail_domain_for_host_empty_on_host_with_no_hostnames():
    assert _mail_domain_for_host(_host()) == ""


# --- producer wire: smtp.analyze() populates the reader --------------------

def test_smtp_analyze_records_mail_accounts_from_enum_hits(monkeypatch):
    """The wire: an SMTP enum hit (VRFY/EXPN/RCPT) lands on the host as a
    mail-kind Account, so known_mail_accounts sees it after analyze runs."""
    from recce.services import smtp

    # Fake the network layer: probe returns EHLO-reachable, enum_users
    # returns real users. Byte shape mimics the RFC 5321 §4.2.2 250 replies
    # a real Postfix returns.
    def _fake_probe(ip, port, timeout=6.0):
        return {"reachable": True, "banner": "220 mx.corp.local ESMTP Postfix",
                "esmtp": True, "starttls": False, "vrfy": True,
                "open_relay": False, "auth": "", "error": ""}

    def _fake_enum(ip, port, timeout=6.0, users=None):
        # As if the server returned 250 Ok for these; 550 no such user for
        # the rest of the default list.
        return {"vrfy": ["root", "postmaster"], "expn": [],
                "rcpt": ["postmaster"]}

    monkeypatch.setattr(smtp, "probe", _fake_probe)
    monkeypatch.setattr(smtp, "enum_users", _fake_enum)

    # Skip the actual probe iteration timing.
    from recce.services import svcprobe

    def _straight_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fn(t)

    monkeypatch.setattr(svcprobe, "iter_probe", _straight_iter)

    h = Host(ip="10.0.0.10", hostnames=["mx.corp.local"],
             ports=[Port(portid=25, protocol="tcp", state="open",
                         service="smtp")])
    smtp.analyze([h], active=True)

    got = known_mail_accounts([h])
    users = {e["user"] for e in got["accounts"]}
    assert users == {"root", "postmaster"}
    # Domain was derived from the host FQDN's parent.
    assert all(e["domain"] == "corp.local" for e in got["accounts"])
    # Source label on every entry says smtp.
    assert all("smtp" in e["sources"] for e in got["accounts"])


# --- producer wire: imap.analyze() populates the reader --------------------

def test_imap_analyze_records_mail_accounts_from_login_differential(monkeypatch):
    """IMAP LOGIN-differential hit lands as a mail-kind Account too. The
    real enum path opens a raw socket per user; we stub the whole
    enum_users call rather than replaying the wire byte-by-byte (that path
    is covered by test_imap.py's own enum test)."""
    from recce.services import imap

    def _fake_probe(ip, port=143, timeout=6.0):
        # 993 branch means the plaintext_login guard is skipped and the enum
        # path always runs (see analyze()); return preauth=False so the enum
        # runs.
        return {"reachable": True, "banner": "* OK Dovecot ready.",
                "starttls": True, "plaintext_login": "accepted",
                "preauth": False, "sasl": [], "logindisabled": False}

    def _fake_enum(ip, port, users=None, timeout=6.0):
        return {"responses": {}, "distinguishes": True,
                "existing": ["alice", "svc_sql"]}

    monkeypatch.setattr(imap, "probe", _fake_probe)
    monkeypatch.setattr(imap, "enum_users", _fake_enum)
    monkeypatch.setattr(imap, "try_login", lambda *a, **k: False)
    monkeypatch.setattr(imap, "_spray_defaults", lambda *a, **k: None)

    from recce.services import svcprobe

    def _straight_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fn(t)

    monkeypatch.setattr(svcprobe, "iter_probe", _straight_iter)

    h = Host(ip="10.0.0.20", hostnames=["mail.corp.local"],
             ports=[Port(portid=143, protocol="tcp", state="open",
                         service="imap")])
    imap.analyze([h], active=True)

    got = known_mail_accounts([h])
    users = {e["user"] for e in got["accounts"]}
    assert users == {"alice", "svc_sql"}
    assert all("imap" in e["sources"] for e in got["accounts"])
    assert all(e["domain"] == "corp.local" for e in got["accounts"])


def test_cross_transport_union_bridges_smtp_hit_to_imap_retry(monkeypatch):
    """End-to-end wire the reader exists to enable: SMTP enumerated `alice`
    on the MX; IMAP on the mailbox server should be able to see `alice` as
    a spray candidate via known_mail_accounts, WITHOUT the IMAP module
    having to re-enumerate."""
    mx = Host(ip="10.0.0.10", hostnames=["mx.corp.local"])
    mbox = Host(ip="10.0.0.20", hostnames=["mail.corp.local"])
    # SMTP producer wired the hit onto the MX host.
    record_mail_account(mx, "alice", "corp.local", "smtp")
    # IMAP consumer reads the engagement-wide view.
    view = known_mail_accounts([mx, mbox])
    assert "alice" in view["by_user"]
    assert view["by_user"]["alice"] == ["corp.local"]
    # AD bridge picks it up when corp.local is a known AD domain.
    assert mail_users_for_ad([mx, mbox], ad_domains=["corp.local"]) == ["alice"]
