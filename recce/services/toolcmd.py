"""Raw external-tool command for each recce operation — the "what does this
actually run" answer, so an operator can drive the underlying tool by hand
(airgapped box, no recce, or just preference) instead of the recce wrapper.

recce's service modules are mostly stdlib probes; this maps each command to the
canonical Kali tool + syntax a pentester would type for the same job, matching
what recce/scripts/services/*.sh drive. Placeholders: <target> host/IP, <port>
the service port (a sensible default is shown), <user>/<pass> credentials.

Single source of truth, surfaced across the workbench tabs (Scan palette /
launch drawer, Exploit action cards). Keep additions accurate — a wrong command
in a pentest tool is worse than none; unknown commands return "" and the UI
falls back to the recce command alone.
"""
from __future__ import annotations

# recce command name -> (raw tool command template, default port or "").
# {t} = target, {p} = port. Creds shown as literal <user>/<pass> placeholders.
_CMD: dict[str, tuple[str, str]] = {
    # --- discovery / broad ------------------------------------------------
    "enum":   ("nmap -Pn -sV -sC -p- -oA scan {t}", ""),
    "scan":   ("nmap -Pn -sV -sC -p- {t}  &&  nmap -Pn --script vuln -p<open> {t}", ""),
    "vulns":  ("nmap -Pn -sV --script vuln -p <ports> {t}", ""),
    "sweep":  ("nmap -Pn -sV -p- {t}   # then per-service tools below", ""),
    # --- databases --------------------------------------------------------
    "redis":       ("redis-cli -h {t} -p {p} INFO   # unauth check; then CONFIG GET dir", "6379"),
    "mysql":       ("mysql -h {t} -P {p} -u root --password=   # empty-root; nmap --script mysql-empty-password", "3306"),
    "postgres":    ("psql 'postgresql://postgres@{t}:{p}/postgres'   # trust-auth check", "5432"),
    "mssql":       ("impacket-mssqlclient <user>:<pass>@{t} -windows-auth   # then enable_xp_cmdshell", "1433"),
    "mongodb":     ("mongosh 'mongodb://{t}:{p}' --eval 'db.adminCommand({listDatabases:1})'", "27017"),
    "elasticsearch": ("curl -s http://{t}:{p}/_cat/indices?v   # unauth data exposure", "9200"),
    "memcached":   ("nc {t} {p} <<< 'stats'   # unauth stats + amplification", "11211"),
    "couchdb":     ("curl -s http://{t}:{p}/_all_dbs   # then /_utils, admin-party", "5984"),
    "cassandra":   ("cqlsh {t} {p} -e 'DESCRIBE KEYSPACES'", "9042"),
    "oracle":      ("odat all -s {t} -p {p}   # or nmap --script oracle-sid-brute", "1521"),
    "influxdb":    ("curl -s 'http://{t}:{p}/query?q=SHOW+DATABASES'", "8086"),
    "db2":         ("nmap -Pn -sV -p {p} {t}   # db2 discover; then db2 client", "50000"),
    # --- web --------------------------------------------------------------
    "web":    ("whatweb http://{t}:{p}/  ;  curl -sI http://{t}:{p}/  ;  nuclei -u http://{t}:{p}/", "80"),
    "api":    ("curl -s http://{t}:{p}/openapi.json  ||  curl -s http://{t}:{p}/swagger.json", "80"),
    # --- windows / AD -----------------------------------------------------
    "smb":    ("nxc smb {t} -u '<user>' -p '<pass>' --shares   # anon: -u '' -p ''", "445"),
    "winrm":  ("nxc winrm {t} -u '<user>' -p '<pass>'   # then: evil-winrm -i {t} -u <user> -p <pass>", "5985"),
    "rdp":    ("nxc rdp {t} -u '<user>' -p '<pass>'   # then: xfreerdp /v:{t} /u:<user>", "3389"),
    "ldap":   ("ldapsearch -x -H ldap://{t}:{p} -s base   # RootDSE; -b '<base>' for anon read", "389"),
    "kerberos": ("impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip {t}   # AS-REP", "88"),
    "certipy": ("certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip {t} -vulnerable -stdout", ""),
    "msrpc":  ("impacket-rpcdump {t}  ;  rpcclient -U '' -N {t}", "135"),
    "netbios": ("nbtscan {t}  ;  nmblookup -A {t}", "139"),
    # --- unix / network services -----------------------------------------
    "ssh":    ("ssh <user>@{t} -p {p}   # nxc ssh {t} -u users.txt -p passwords.txt", "22"),
    "ftp":    ("curl ftp://{t}:{p}/ --user anonymous:anon   # anon check", "21"),
    "telnet": ("telnet {t} {p}", "23"),
    "smtp":   ("smtp-user-enum -M VRFY -U users.txt -t {t}   # + swaks open-relay test", "25"),
    "dns":    ("dig @{t} <domain> AXFR   # zone transfer; + dig @{t} version.bind chaos txt", "53"),
    "snmp":   ("onesixtyone {t} -c community.txt  ;  snmpwalk -v2c -c public {t}", "161"),
    "nfs":    ("showmount -e {t}   # then mount -t nfs {t}:/<share> /mnt", "2049"),
    "rsync":  ("rsync rsync://{t}:{p}/   # list modules", "873"),
    "vnc":    ("nmap -Pn -p {p} --script realvnc-auth-bypass,vnc-info {t}", "5900"),
    "ipmi":   ("nmap -Pn -sU -p 623 --script ipmi-version,ipmi-cipher-zero {t}", "623"),
    "ntp":    ("ntpq -c rv {t}  ;  nmap -sU -p 123 --script ntp-monlist {t}", "123"),
    "sip":    ("svmap {t}  ;  nmap -sU -p {p} --script sip-methods {t}", "5060"),
    "mqtt":   ("mosquitto_sub -h {t} -p {p} -t '#' -v   # unauth subscribe", "1883"),
    "tftp":   ("nmap -Pn -sU -p 69 --script tftp-enum {t}", "69"),
    "docker": ("curl -s http://{t}:{p}/version   # then docker -H tcp://{t}:{p} ps", "2375"),
    "kubernetes": ("kubectl --server https://{t}:{p} --insecure-skip-tls-verify get pods -A", "6443"),
    # --- credentials ------------------------------------------------------
    "credenum": ("nxc smb {t} -u '<user>' -p '<pass>'   # then --sam --lsa --dpapi", "445"),
}

_DEFAULT_PORTS = {k: v for k, (_, v) in _CMD.items()}


def _base_dn(domain: str) -> str:
    """corp.local -> DC=corp,DC=local (LDAP base DN)."""
    parts = [p for p in (domain or "").split(".") if p]
    return ",".join(f"DC={p}" for p in parts)


# Commands that authenticate with a Windows/AD account, where a captured DOMAIN
# credential is the correct thing to try domain-wide. For every other command a
# domain cred is NOT assumed valid — only a credential captured from the exact
# target host is prefilled (see _pick_credential).
_AD_CRED_CMDS = {"smb", "winrm", "rdp", "mssql", "ldap", "credenum", "credsweep"}


def _usable_creds(creds):
    # Plaintext only — a hash doesn't paste into these tools as -p. Skip empties.
    return [c for c in (creds or [])
            if (getattr(c, "kind", "") or "").lower() in ("", "password", "plaintext", "cleartext")
            and getattr(c, "secret", "")]


def _pick_credential(command: str, target: str, creds):
    """The credential that is CORRECT to prefill for this command+target, or None.
    A wrong credential is worse than a placeholder, so this never guesses:
      1. one captured FROM this exact host (origin_ip == target) — unambiguous, or
      2. a DOMAIN credential, but only for domain-authenticated commands.
    A bare local/service credential is never applied to a host it didn't come from.
    """
    usable = _usable_creds(creds)
    if target and target not in ("", "<target>", "engagement", "active-directory"):
        for c in usable:
            if getattr(c, "origin_ip", "") == target:
                return c
    if (command or "").lower() in _AD_CRED_CMDS:
        for c in usable:
            if getattr(c, "domain", ""):
                return c
    return None


def for_command(command: str, target: str = "<target>", port: str | int = "", *,
                creds=None, domain: str = "", ports: str = "") -> str:
    """Raw external-tool command for a recce scan/service command, or "" if none.

    Fills every placeholder it safely can so the command is copy-paste-ready:
    <target>, the service port, <domain>/<base> from the discovered AD realm (a
    fact), and <ports> from the host's open ports. <user>/<pass> are filled ONLY
    from a credential that is correct for this command+target (see
    _pick_credential) — a guessed credential is never inserted; the placeholder
    stays so the operator supplies the right one.
    """
    entry = _CMD.get((command or "").lower())
    if not entry:
        return ""
    tmpl, default_port = entry
    out = tmpl.replace("{t}", target or "<target>")
    out = out.replace("{p}", str(port) if port else (default_port or "<port>"))
    cred = _pick_credential(command, target, creds)
    if cred:
        out = out.replace("<user>", cred.username or "<user>")
        out = out.replace("<pass>", cred.secret or "<pass>")
        if getattr(cred, "domain", ""):
            domain = cred.domain
    if domain:
        out = out.replace("<domain>", domain)
        out = out.replace("<base>", _base_dn(domain))
    if ports:
        out = out.replace("<ports>", ports)
    return out


def has_command(command: str) -> bool:
    return (command or "").lower() in _CMD


# recce command -> the netexec protocol to spray it with (credential reuse test).
_SPRAY_PROTO = {"smb": "smb", "winrm": "winrm", "ldap": "ldap", "mssql": "mssql",
                "rdp": "rdp", "ssh": "ssh", "credenum": "smb", "credsweep": "smb"}


def spray_candidates(command: str, target: str, creds) -> str:
    """A ready, lockout-safe spray of the engagement's found secrets against this
    host+service — the way to CONFIRM whether a password captured elsewhere is
    reused here. "" when not applicable (non-sprayable command, no target, or no
    captured passwords). Distinct from a prefilled cred: these are *candidates* to
    test, never asserted as valid."""
    proto = _SPRAY_PROTO.get((command or "").lower())
    if not proto or not target or target in ("<target>", "engagement", "active-directory"):
        return ""
    usable = _usable_creds(creds)
    users = sorted({c.username for c in usable if c.username})
    passwords = sorted({c.secret for c in usable if c.secret})
    if not passwords:
        return ""
    # Inline the small found set so the command is self-contained; fall back to the
    # spray-plan files (recce creds --plan) when there are too many to read inline.
    u = " ".join(users[:8]) if 0 < len(users) <= 8 else "users.txt"
    p = (" ".join(f"'{x}'" for x in passwords[:8]) if len(passwords) <= 8
         else "passwords.txt")
    return (f"nxc {proto} {target} -u {u} -p {p} --no-bruteforce --continue-on-success"
            f"   # spray {len(passwords)} found password(s) here to test reuse")


def discovered_domain(hosts, creds) -> str:
    """The engagement's AD realm (a discovered fact, safe to fill for <domain>/
    <base>), from a domain-scoped credential or known_domains. "" if none."""
    for c in _usable_creds(creds):
        if getattr(c, "domain", ""):
            return c.domain
    try:
        from ..core.known_domains import known_domains
        return (known_domains(hosts, creds).get("primary_dns") or "").strip()
    except Exception:  # noqa: BLE001 — best effort
        return ""


_TLS_PORTS = {443, 636, 989, 990, 993, 995, 3269, 5986, 8443, 2376}


def pick_cred(creds, target: str = ""):
    """The best plaintext credential to prefill: one captured FROM this target
    (origin match) first, else any DOMAIN credential, else the first usable one.
    Returns None when there's nothing usable. Never a hash (won't paste as -p)."""
    usable = _usable_creds(creds)
    if target:
        for c in usable:
            if getattr(c, "origin_ip", "") == target:
                return c
    for c in usable:
        if getattr(c, "domain", ""):
            return c
    return usable[0] if usable else None


def fill_tokens(text: str, *, target: str = "", port="", domain: str = "",
                dc_ip: str = "", cred=None, lhost: str = "", lport="",
                ports: str = "") -> str:
    """Substitute engagement facts into ANY command string — chains, playbooks,
    prove/verify lines — so <ip>/<dc>/<domain>/<base>/<user>/<pass>/<lhost>/{t}/{p}
    come back runnable instead of as template stubs. Only tokens with a known
    value are replaced; anything we lack stays a visible placeholder (never
    guessed). Case-insensitive for the <..> tokens."""
    import re as _re
    if not text or ("<" not in text and "{" not in text):
        return text
    try:
        pnum = int(port)
    except (TypeError, ValueError):
        pnum = 0
    reps = {
        "{t}": target, "{p}": str(port or ""),
        "<ip>": target, "<target>": target, "<host>": target,
        "<dc>": dc_ip or target, "<dc-ip>": dc_ip or target,
        "<domain>": domain, "<realm>": domain.upper() if domain else "",
        "<base>": _base_dn(domain), "<naming-context>": _base_dn(domain),
        "<lhost>": lhost, "<lport>": str(lport or ""),
        "<ports>": ports, "<scheme>": "https" if pnum in _TLS_PORTS else "http",
        "<community>": "public",
    }
    if cred is not None:
        u, p = getattr(cred, "username", "") or "", getattr(cred, "secret", "") or ""
        for k in ("<user>", "<u>", "<username>"):
            reps[k] = u
        for k in ("<pass>", "<password>"):
            reps[k] = p
    out = text
    for tok, val in reps.items():
        if not val:
            continue
        if tok.startswith("{"):
            out = out.replace(tok, val)
        else:
            out = _re.sub(_re.escape(tok), lambda _m, v=val: v, out, flags=_re.IGNORECASE)
    return out
