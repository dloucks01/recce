"""Deep SMTP enumeration (stdlib smtplib, read-only-ish).

Tests the classic unauthenticated SMTP exposures without ever sending a message:
  * OPEN RELAY - the server accepts an envelope (MAIL FROM + RCPT TO) for a non-local
    recipient with no auth (we stop before DATA, so nothing is ever delivered).
  * VRFY / EXPN user enumeration.
  * cleartext posture - no STARTTLS offered on 25/587.

Findings fold into the severity totals / Vulnerabilities sheet (source="smtp").
"""
from __future__ import annotations

import re
import smtplib
import socket

from ..core.models import Host, Port

_PORTS = (25, 465, 587, 2525)
_DEFAULT_PORT = 25
_TIMEOUT = 6.0
_EXTERNAL = "relay-test@example.net"      # a non-local recipient -> relaying if accepted


def is_smtp(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "smtp" in svc or svc == "submission"


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    res = {"reachable": False, "banner": "", "esmtp": False, "starttls": False,
           "vrfy": False, "open_relay": False, "auth": "", "error": ""}
    try:
        cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        srv = cls(timeout=timeout)
        srv.connect(ip, port)
    except (OSError, smtplib.SMTPException) as e:
        res["error"] = str(e)
        return res
    try:
        res["reachable"] = True
        code, msg = srv.ehlo("recce-scan.local")
        text = (msg or b"").decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)
        res["banner"] = text.splitlines()[0][:200] if text else ""
        res["esmtp"] = code == 250
        feats = getattr(srv, "esmtp_features", {}) or {}
        res["starttls"] = "starttls" in feats
        res["auth"] = (feats.get("auth") or "").strip()
        # VRFY user enumeration (250 confirmed / 252 will-attempt)
        try:
            vcode, _ = srv.docmd("VRFY", "root")
            res["vrfy"] = vcode in (250, 252)
        except smtplib.SMTPException:
            pass
        # Open-relay test: envelope only, NEVER DATA. A 250/251 on an external RCPT
        # from an unauthenticated session is relaying.
        try:
            srv.docmd("RSET")
            srv.docmd("MAIL", "FROM:<recce-probe@example.com>")
            rcode, _ = srv.docmd("RCPT", f"TO:<{_EXTERNAL}>")
            res["open_relay"] = rcode in (250, 251)
            srv.docmd("RSET")
        except smtplib.SMTPException:
            pass
        try:
            srv.quit()
        except smtplib.SMTPException:
            srv.close()
        return res
    except (OSError, smtplib.SMTPException, socket.error) as e:
        res["error"] = str(e)
        try:
            srv.close()
        except Exception:
            pass
        return res


# Small set of usernames that pentesters and admins historically probe first
# on an SMTP user-enum. Kept short on purpose — a bigger list turns into brute
# force and looks like an attack. This is a "did anyone leave the classic
# accounts open" check, not a mail-account audit.
_SMTP_ENUM_USERS = [
    "root", "admin", "administrator", "postmaster", "mail", "mailer-daemon",
    "webmaster", "info", "test", "user", "guest", "backup", "sysadmin",
    "operator", "support",
]


def enum_users(ip: str, port: int, timeout: float = _TIMEOUT,
               users: list[str] | None = None) -> dict:
    """Probe each candidate username via VRFY, EXPN, and RCPT TO. Returns
    {vrfy:[names], expn:[names], rcpt:[names]} — each list is the subset of
    users the server confirmed exist via that command.

    RCPT-based enum is the workhorse: even servers with VRFY disabled often
    leak user existence through RCPT response codes (250 = exists, 550/551 =
    doesn't). We do envelope-only, no DATA — nothing gets sent.

    Bounded runtime: len(users) * 3 commands * ~200ms = ~10s worst case for
    the default 15-user list. Skips silently on transport errors."""
    users = users if users is not None else _SMTP_ENUM_USERS
    out = {"vrfy": [], "expn": [], "rcpt": []}
    try:
        cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        srv = cls(timeout=timeout)
        srv.connect(ip, port)
    except (OSError, smtplib.SMTPException):
        return out
    try:
        srv.ehlo("recce-enum.local")
        for u in users:
            try:
                vcode, _ = srv.docmd("VRFY", u)
                if vcode in (250, 251, 252):
                    out["vrfy"].append(u)
            except smtplib.SMTPException:
                pass
            try:
                ecode, _ = srv.docmd("EXPN", u)
                if ecode == 250:
                    out["expn"].append(u)
            except smtplib.SMTPException:
                pass
            # RCPT-based: fresh envelope per attempt so a persistent MAIL
            # FROM doesn't inherit the previous RCPT's error state.
            try:
                srv.docmd("RSET")
                srv.docmd("MAIL", "FROM:<recce-enum@example.com>")
                rcode, _ = srv.docmd("RCPT", f"TO:<{u}@localhost>")
                if rcode in (250, 251):
                    out["rcpt"].append(u)
                srv.docmd("RSET")
            except smtplib.SMTPException:
                pass
        try:
            srv.quit()
        except smtplib.SMTPException:
            srv.close()
    except (OSError, smtplib.SMTPException):
        try:
            srv.close()
        except Exception:
            pass
    return out


def smtp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_smtp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "smtp", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind, "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_smtp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("open_relay"):
                out.append(_finding(
                    "high", "SMTP open relay", tgt,
                    "The server accepted an envelope (MAIL FROM + RCPT TO) for an "
                    f"external recipient ({_EXTERNAL}) with no authentication - it will "
                    "relay mail for anyone (spam / phishing / spoofing).",
                    f"swaks --server {h.ip}:{p.portid} --from x@example.com "
                    f"--to {_EXTERNAL}",
                    "Restrict relaying to authenticated senders / trusted networks "
                    "(smtpd_relay_restrictions / mynetworks).",
                    ["CWE-269", "CWE-16"], kind="smtp_open_relay",
                    exploit_note=(
                        "swaks --server IP:PORT --from x@example.com --to "
                        "your-test@controlled.tld --header 'Subject: recce-relay-canary' "
                        "; verify inbound at the collector. Or: nmap --script "
                        "smtp-open-relay -p25 IP."),
                    depth_tier="t1"))
            if pr.get("vrfy"):
                out.append(_finding(
                    "low", "SMTP VRFY user enumeration", tgt,
                    "VRFY returned a positive response, so valid local usernames can be "
                    "enumerated over SMTP (feeds password spraying).",
                    f"for u in root admin postmaster; do echo VRFY $u | nc {h.ip} {p.portid}; done",
                    "Disable VRFY/EXPN (disable_vrfy_command = yes).",
                    ["CWE-200"], kind="smtp_vrfy"))
            # Enumerated users — merge VRFY/EXPN/RCPT hits, dedup, and
            # report each as a name a spray attack now knows exists on
            # this box. RCPT-based enum in particular still works on
            # servers with VRFY disabled, so keeping it separate as a
            # channel signal helps the tester know how it was leaked.
            enum = pr.get("enum") or {}
            all_users = sorted(set(enum.get("vrfy", []))
                               | set(enum.get("expn", []))
                               | set(enum.get("rcpt", [])))
            if all_users:
                channels = []
                if enum.get("vrfy"): channels.append(f"VRFY:{','.join(enum['vrfy'])}")
                if enum.get("expn"): channels.append(f"EXPN:{','.join(enum['expn'])}")
                if enum.get("rcpt"): channels.append(f"RCPT:{','.join(enum['rcpt'])}")
                out.append(_finding(
                    "medium", "SMTP user enumeration hits", tgt,
                    f"{len(all_users)} valid local usernames enumerated: "
                    f"{', '.join(all_users)}. Channels: {'; '.join(channels)}. "
                    f"These names now seed password-spray attempts against SSH, SMB, "
                    f"AD, and web-app login.",
                    f"smtp-user-enum -M RCPT -U users.txt -t {h.ip} -p {p.portid}",
                    "Restrict user existence leakage: disable VRFY/EXPN; return the "
                    "same 250 response for any RCPT regardless of user existence "
                    "(smtpd_reject_unlisted_recipient = no on some MTAs) or accept "
                    "and drop non-existent recipients.",
                    ["CWE-200", "CWE-203"], kind="smtp_user_enum"))
            if not pr.get("starttls") and p.portid in (25, 587):
                out.append(_finding(
                    "low", "SMTP without STARTTLS (cleartext)", tgt,
                    "The server does not offer STARTTLS on this port, so mail and any "
                    "AUTH credentials cross the wire in cleartext.",
                    f"openssl s_client -starttls smtp -connect {h.ip}:{p.portid}",
                    "Offer/require STARTTLS; require TLS before AUTH.",
                    ["CWE-319"], kind="smtp_cleartext"))
            # AUTH mech deep-parse: RFC 4954 §4 forbids AUTH before STARTTLS
            # (credential-in-cleartext), and RFC 6409 §4.3 sharpens that on
            # the submission port (587). Also flag deprecated / offline-
            # crackable mechs, and info-disclosure-y NTLM/GSSAPI challenges.
            mechs = _split_auth_mechs(pr.get("auth", ""))
            if mechs and not pr.get("starttls"):
                sev = "high" if p.portid == 587 else "medium"
                rfc = ("RFC 6409 §4.3" if p.portid == 587
                       else "RFC 4954 §4")
                out.append(_finding(
                    sev, "SMTP AUTH offered without STARTTLS", tgt,
                    f"The server advertises AUTH mechanisms ({', '.join(mechs)}) "
                    f"before offering STARTTLS. Credentials submitted here cross "
                    f"the wire in cleartext, violating {rfc}.",
                    f"openssl s_client -starttls smtp -connect {h.ip}:{p.portid}",
                    "Require STARTTLS and only advertise AUTH after a TLS session "
                    "is established (smtpd_tls_auth_only = yes on Postfix; "
                    "REQUIRETLS on submission).",
                    ["CWE-319", "CWE-522"], kind="smtp_auth_before_tls"))
            weak = [m for m in mechs if m in _WEAK_AUTH_MECHS
                    and m not in ("PLAIN", "LOGIN")]
            if weak:
                out.append(_finding(
                    "low", "SMTP AUTH offers deprecated challenge mechs", tgt,
                    f"AUTH mechanisms advertised include {', '.join(weak)}. "
                    f"CRAM-MD5 and DIGEST-MD5 use MD5-based challenge/response "
                    f"whose captured (challenge, response) pair is offline-"
                    f"crackable with a modest wordlist.",
                    f"openssl s_client -starttls smtp -connect {h.ip}:{p.portid}",
                    "Disable CRAM-MD5 / DIGEST-MD5; require SCRAM-SHA-256 or "
                    "AUTH PLAIN over TLS.",
                    ["CWE-327", "CWE-916"], kind="smtp_auth_weak_mech"))
            leaky = [m for m in mechs if m in _LEAKY_AUTH_MECHS]
            if leaky:
                out.append(_finding(
                    "medium", "SMTP AUTH advertises NTLM/GSSAPI (info-disclosure primitive)",
                    tgt,
                    f"AUTH {', '.join(leaky)} is advertised. Sending an NTLM "
                    f"Type-1 unsolicited returns a Type-2 CHALLENGE_MESSAGE whose "
                    f"AV pairs leak NetBIOS computer/domain, DNS computer/domain, "
                    f"forest, and OS build with no authentication required.",
                    f"nmap -p{p.portid} --script smtp-ntlm-info {h.ip}",
                    "Restrict AUTH NTLM to internal network segments; prefer AUTH "
                    "PLAIN/EXTERNAL over TLS.",
                    ["CWE-200"], kind="smtp_auth_ntlm_leak"))
            # Banner fingerprint -> product + version-gated CVEs.
            fp = pr.get("fingerprint") or {}
            for c in (fp.get("cves") or []):
                out.append(_finding(
                    c.get("severity", "high"), c["title"], tgt,
                    f"Banner identifies {fp.get('product','')} "
                    f"{fp.get('version','')}. {c['id']} affects this version "
                    f"per vendor advisory.",
                    f"searchsploit {fp.get('product','').lower()} "
                    f"{fp.get('version','')}",
                    c.get("rem", "Apply vendor patch."),
                    c.get("cwes", []) + [c["id"]], kind="smtp_cve",
                    exploit_note=(
                        "For Exim < 4.92: use exim_4.87-4.91 metasploit module "
                        "(exploit/unix/smtp/exim4_dovecot_exec) OR public "
                        "CVE-2019-10149 PoC delivering an OAST callback "
                        "(interact.sh). Confirm shell before running any secondary "
                        "payload."),
                    depth_tier="t0"))
            # EXPN alias expansion: a single 250 body naming N mailboxes on
            # `all`, `everyone`, `staff` etc — the highest-yield single-shot
            # user-roster leak on legacy /etc/aliases-driven MTAs.
            ea = pr.get("expn_aliases") or {}
            if ea:
                lines = []
                total = 0
                for alias, members in sorted(ea.items()):
                    lines.append(f"EXPN {alias} -> {len(members)}: "
                                 f"{', '.join(members[:8])}"
                                 + (" ..." if len(members) > 8 else ""))
                    total += len(members)
                out.append(_finding(
                    "medium",
                    "SMTP EXPN alias expansion leaks user roster",
                    tgt,
                    f"EXPN on {len(ea)} well-known list alias(es) expanded to "
                    f"{total} member address(es). "
                    + " | ".join(lines) + ". "
                    "Each member is now a spray target across SSH / SMB / "
                    "web-app / mail-transport logins.",
                    f"for a in all everyone staff users; do echo EXPN $a "
                    f"| nc {h.ip} {p.portid}; done",
                    "Disable EXPN (disable_vrfy_command = yes on Postfix "
                    "also blocks EXPN; smtpd_discard_ehlo_keywords = expn), "
                    "or return 550 for list aliases.",
                    ["CWE-200"], kind="smtp_expn_alias_leak"))
    return out


# Well-known list aliases that historically expand to full user rosters in
# one shot on Sendmail/qmail/Postfix with an /etc/aliases file. RFC 5321
# §3.5.2 allows EXPN to return a list of mailbox addresses.
_EXPN_ALIASES = ("all", "everyone", "staff", "users", "root", "wheel",
                 "postmaster", "abuse", "mailer-daemon")

# EXPN reply body: continuation lines begin with `250-`, final `250 `.
# smtplib.docmd() concatenates the reply body across lines with `\n`, so we
# just split and extract each addr/local name.
_EXPN_ADDR = re.compile(r"([A-Za-z0-9._%+\-]+(?:@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})?)")

# AUTH mechs the SASL/RFC record marks as deprecated or offline-crackable
# once the challenge/response is captured. Anonymous/plain-without-TLS is
# handled by the AUTH-before-STARTTLS check separately.
_WEAK_AUTH_MECHS = ("CRAM-MD5", "DIGEST-MD5", "LOGIN", "PLAIN")
# Mechs whose challenge alone leaks NetBIOS/DNS/OS info (MS-NLMP §2.2.1.2).
_LEAKY_AUTH_MECHS = ("NTLM", "GSSAPI")


def _split_auth_mechs(auth_str: str) -> list[str]:
    """EHLO's `auth` feature is a space-separated (sometimes `=`-prefixed)
    mech list per RFC 4954 §3. Some servers use commas; some prefix `=`."""
    s = (auth_str or "").strip()
    if not s:
        return []
    s = s.lstrip("=").replace(",", " ")
    return [m.upper() for m in s.split() if m]


# Fingerprint patterns keyed to banner substrings that appear in the first
# 220 line of well-known MTAs. Version regexes are conservative — only match
# a real `x.y[.z]` — because a spurious digit sequence would put us over the
# CVE gate.
_EXIM_RE = re.compile(r"\bExim\s+(\d+\.\d+(?:\.\d+)?)", re.I)
_SENDMAIL_RE = re.compile(r"\bSendmail\s+(\d+\.\d+(?:\.\d+)?)", re.I)
_EXCH_RE = re.compile(r"Microsoft ESMTP MAIL Service.*?(\d+\.\d+\.\d+(?:\.\d+)?)", re.I)


def _ver_tuple(v: str) -> tuple:
    out: list[int] = []
    for p in v.split("."):
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return tuple(out)


def _fingerprint(banner: str) -> dict:
    """Parse a captured 220-line for product + version + version-gated CVEs.

    Returns {product, version, cves:[{id, cwes, severity, title, rem}]}.
    A CVE is emitted ONLY when the version was definitively parsed AND is
    at or below the fixed-in threshold; else the caller still gets a bare
    product/version fingerprint with no CVE claim.
    """
    b = banner or ""
    out: dict = {"product": "", "version": "", "cves": []}
    m = _EXIM_RE.search(b)
    if m:
        v = m.group(1)
        out["product"], out["version"] = "Exim", v
        vt = _ver_tuple(v)
        if vt and vt < (4, 92):
            out["cves"].append({
                "id": "CVE-2019-10149", "cwes": ["CWE-77"],
                "severity": "critical",
                "title": "Exim <4.92 remote code execution (CVE-2019-10149)",
                "rem": "Upgrade Exim to 4.92 or later."})
        if vt and vt < (4, 94, 2):
            out["cves"].append({
                "id": "CVE-2020-28017", "cwes": ["CWE-787", "CWE-190"],
                "severity": "critical",
                "title": "Exim <4.94.2 '21Nails' memory-corruption cluster",
                "rem": "Upgrade Exim to 4.94.2 or later (21Nails patchset)."})
        if vt and vt < (4, 97, 1):
            out["cves"].append({
                "id": "CVE-2024-39929", "cwes": ["CWE-451"],
                "severity": "high",
                "title": "Exim <4.97.1 MIME filter bypass (CVE-2024-39929)",
                "rem": "Upgrade Exim to 4.97.1 or later."})
        return out
    m = _SENDMAIL_RE.search(b)
    if m:
        out["product"], out["version"] = "Sendmail", m.group(1)
        return out
    m = _EXCH_RE.search(b)
    if m:
        out["product"], out["version"] = "Microsoft Exchange", m.group(1)
        return out
    # Product-only fingerprints (no version -> no CVE gate).
    for needle, prod in (("Postfix", "Postfix"), ("Zimbra", "Zimbra"),
                         ("IronPort", "Cisco IronPort"), ("qmail", "qmail"),
                         ("Microsoft ESMTP", "Microsoft Exchange")):
        if needle.lower() in b.lower():
            out["product"] = prod
            return out
    return out


def _parse_expn_members(msg: bytes | str) -> list[str]:
    """Extract the member addresses from an EXPN reply body."""
    text = msg.decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)
    members: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # smtplib strips the leading `250-/250 ` code prefix already; each
        # line body is of the form `Full Name <addr@host>` or `addr@host`
        # or a bare local name. Pick the tightest addr-like token per line.
        m = re.search(r"<([^>]+)>", line)
        if m:
            members.append(m.group(1).strip())
            continue
        # Bare token: grab the last address-shaped run on the line.
        for tok in reversed(_EXPN_ADDR.findall(line)):
            if tok and not tok.isdigit():
                members.append(tok)
                break
    # Dedup preserving order, case-insensitive.
    seen: set[str] = set()
    uniq: list[str] = []
    for m in members:
        k = m.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(m)
    return uniq


def expn_aliases(ip: str, port: int, timeout: float = _TIMEOUT,
                 aliases: tuple[str, ...] | list[str] | None = None) -> dict:
    """Probe well-known list aliases via EXPN; return {alias: [members]}.

    Only aliases that yielded ≥1 member (250 response with a parsable
    address body) are included. Skips silently on transport errors."""
    aliases = tuple(aliases) if aliases is not None else _EXPN_ALIASES
    out: dict[str, list[str]] = {}
    try:
        cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        srv = cls(timeout=timeout)
        srv.connect(ip, port)
    except (OSError, smtplib.SMTPException):
        return out
    try:
        srv.ehlo("recce-expn.local")
        for a in aliases:
            try:
                code, msg = srv.docmd("EXPN", a)
            except smtplib.SMTPException:
                continue
            if code != 250:
                continue
            members = _parse_expn_members(msg)
            if members:
                out[a] = members
        try:
            srv.quit()
        except smtplib.SMTPException:
            srv.close()
    except (OSError, smtplib.SMTPException):
        try:
            srv.close()
        except Exception:
            pass
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Test open relay (envelope only, no DATA)",
             "cmd": f"swaks --server {ip}:{port} --from x@example.com --to {_EXTERNAL} --quit-after RCPT"},
            {"step": "User enumeration",
             "cmd": f"smtp-user-enum -M VRFY -U users.txt -t {ip} -p {port}"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "smtp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            wordlist: str | None = None, **_ignored) -> dict:
    """`wordlist` = optional path to a user-supplied username list, one
    per line; augments the bundled `_SMTP_ENUM_USERS`."""
    from . import svcprobe
    from .wordlists import load_wordlist
    extra_users = load_wordlist(wordlist)
    enum_list = _SMTP_ENUM_USERS + [u for u in extra_users
                                     if u not in _SMTP_ENUM_USERS]
    from ..creds.known_mail_accounts import (_mail_domain_for_host,
                                             record_mail_account)
    targets = smtp_targets(hosts)
    by_ip = {h.ip: h for h in hosts}
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["open_relay"] = pr.get("open_relay", False)
                t["vrfy"] = pr.get("vrfy", False)
                t["version"] = pr.get("banner", "") or t.get("version", "")
                # Only run the user-enum sweep on servers that answered EHLO.
                # A dead port shouldn't burn the extra commands.
                if pr.get("reachable") and pr.get("esmtp"):
                    pr["enum"] = enum_users(t["ip"], t["port"], users=enum_list)
                    pr["expn_aliases"] = expn_aliases(t["ip"], t["port"])
                    pr["fingerprint"] = _fingerprint(pr.get("banner", ""))
                    # Cross-transport wire: every VRFY / EXPN / RCPT hit lands
                    # on the host as a mail-kind Account so imap.py / pop3.py
                    # can retry it via known_mail_accounts.
                    host = by_ip.get(t["ip"])
                    if host is not None:
                        dom = _mail_domain_for_host(host)
                        for u in ((pr["enum"].get("vrfy") or [])
                                  + (pr["enum"].get("expn") or [])
                                  + (pr["enum"].get("rcpt") or [])):
                            record_mail_account(host, u, dom, "smtp")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
