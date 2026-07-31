"""Active Directory enumeration and analysis.

Two tiers:

1. Credential-free analysis of data nmap already collected (roles, SMB signing /
   NTLM-relay targets, domain facts, password policy from NSE). Always runs.
2. Optional credentialed LDAP enumeration via ldap3 (users, SPNs/kerberoastable,
   AS-REP-roastable, computers, privileged groups, delegation, trusts, password
   policy). Runs only when the operator supplies credentials.

Nothing here scans on import; callers drive it explicitly.
"""

from __future__ import annotations

import base64
import re
import shutil
import subprocess

from .models import Account, Domain, Host

# --- User-Account-Control flags -------------------------------------------------
UAC = {
    "ACCOUNTDISABLE": 0x0002,
    "LOCKOUT": 0x0010,
    "PASSWD_NOTREQD": 0x0020,
    "NORMAL_ACCOUNT": 0x0200,
    "DONT_EXPIRE_PASSWORD": 0x10000,
    "TRUSTED_FOR_DELEGATION": 0x80000,          # unconstrained delegation
    "TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,  # constrained delegation
    "DONT_REQ_PREAUTH": 0x400000,               # AS-REP roastable
}

_FUNC_LEVEL = {
    "0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
    "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016",
}

# Well-known highly privileged groups worth flagging.
PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "account operators", "backup operators", "server operators", "print operators",
    "dnsadmins", "group policy creator owners", "cert publishers",
    "enterprise key admins", "key admins",
}


# --- tier 1: credential-free analysis of collected NSE data ---------------------

def _script_map(host: Host) -> dict[str, str]:
    """All NSE script outputs on the host keyed by script id (port + host scope)."""
    out: dict[str, str] = {}
    for s in host.host_scripts:
        out[s.id] = s.output
    for p in host.ports:
        for s in p.scripts:
            # Port-scoped scripts take precedence if the same id appears twice.
            out[s.id] = s.output
    return out


def identify_roles(host: Host) -> None:
    """Tag AD-relevant roles based on open ports and NSE output (in place)."""
    open_ports = {p.portid for p in host.open_ports}
    roles = set(host.roles)

    is_dc = 88 in open_ports and (389 in open_ports or 636 in open_ports)
    if not is_dc:
        # Fall back to NSE hints (ldap rootdse / smb-os-discovery 'Domain controller').
        for p in host.ports:
            for s in p.scripts:
                # `namingContexts` is a standard RootDSE attribute on EVERY LDAP
                # server (OpenLDAP, AD LDS/ADAM), so it tagged any 389/636 host as a
                # Domain Controller. Require an AD-DC-specific RootDSE marker instead.
                low = s.output.lower()
                if s.id.startswith("ldap") and (
                        "domaincontrollerfunctionality" in low
                        or "dsservicename" in low
                        or "1.2.840.113556.1.4.800" in low):   # LDAP_CAP_ACTIVE_DIRECTORY_OID
                    is_dc = True
    if is_dc:
        roles.add("Domain Controller")
    if 3268 in open_ports or 3269 in open_ports:
        roles.add("Global Catalog")
    if 53 in open_ports and is_dc:
        roles.add("DNS")
    if {389, 636, 3268} & open_ports and not is_dc:
        roles.add("LDAP server")
    if 445 in open_ports or 139 in open_ports:
        roles.add("SMB server")
    if 1433 in open_ports:
        roles.add("MSSQL")
    if 5985 in open_ports or 5986 in open_ports:
        roles.add("WinRM")
    if 3389 in open_ports:
        roles.add("RDP")
    host.roles = sorted(roles)


def parse_signing_and_ntlm(host: Host) -> None:
    """Derive SMB signing posture and NTLM/domain facts from NSE output (in place)."""
    smap = _script_map(host)

    # SMB signing -> NTLM relay candidacy.
    signing = "unknown"
    for sid in ("smb2-security-mode", "smb-security-mode"):
        text = smap.get(sid, "").lower()
        if not text:
            continue
        if "not required" in text or "signing disabled" in text or \
           re.search(r"message_signing:\s*disabled", text):
            signing = "not required"
            break
        if "required" in text or "enabled and required" in text:
            signing = "required"
    host.smb_signing = signing

    # NTLM info (domain / fqdn / os build) from rdp-ntlm-info / smb-os-discovery.
    ntlm = dict(host.ntlm)
    for sid in ("rdp-ntlm-info", "smb-os-discovery", "smb2-time"):
        text = smap.get(sid, "")
        for key, pat in (
            ("dns_domain", r"(?:DNS_Domain_Name|Domain name|Domain):\s*(\S+)"),
            ("dns_computer", r"(?:DNS_Computer_Name|FQDN):\s*(\S+)"),
            ("netbios_domain", r"(?:NetBIOS_Domain_Name|NetBIOS domain):\s*(\S+)"),
            ("os_build", r"(?:Product_Version|OS):\s*(.+)"),
        ):
            m = re.search(pat, text)
            if m and key not in ntlm:
                ntlm[key] = m.group(1).strip()
    host.ntlm = ntlm


def parse_password_policy(host: Host) -> dict:
    """Extract a password policy dict from smb-enum-domains NSE output, if present."""
    smap = _script_map(host)
    text = smap.get("smb-enum-domains", "")
    if not text:
        return {}
    policy: dict = {}
    m = re.search(r"min(?:imum)? password length:\s*(\d+)", text, re.I)
    if m:
        policy["min_length"] = int(m.group(1))
    m = re.search(r"max(?:imum)? password age:\s*([^\n;]+)", text, re.I)
    if m:
        policy["max_age"] = m.group(1).strip()
    m = re.search(r"password history(?:\s*length)?:\s*(\d+)", text, re.I)
    if m:
        policy["history"] = int(m.group(1))
    if re.search(r"lockout.*disabled", text, re.I):
        policy["lockout_threshold"] = 0
    else:
        m = re.search(r"lockout threshold:\s*(\d+)", text, re.I)
        if m:
            policy["lockout_threshold"] = int(m.group(1))
    return policy


def analyze_hosts(hosts: list[Host]) -> None:
    """Run all credential-free AD tagging across a host set (in place)."""
    for h in hosts:
        identify_roles(h)
        parse_signing_and_ntlm(h)


# --- derived target lists (used by the reports) ---------------------------------

def domain_controllers(hosts: list[Host]) -> list[Host]:
    return [h for h in hosts if "Domain Controller" in h.roles]


def relay_targets(hosts: list[Host]) -> list[Host]:
    """Hosts where SMB signing is not required -> NTLM relay candidates."""
    return [h for h in hosts
            if h.smb_signing == "not required"
            and any(p.portid in (139, 445) for p in h.open_ports)]


def smbv1_hosts(hosts: list[Host]) -> list[Host]:
    out = []
    for h in hosts:
        smap = _script_map(h)
        if "smb-vuln-ms17-010" in smap or "smbv1" in smap.get("smb-protocols", "").lower():
            out.append(h)
    return out


def kerberoastable(hosts: list[Host]) -> list[Account]:
    """Accounts carrying an SPN (excluding krbtgt) -> Kerberoasting targets."""
    out = []
    for h in hosts:
        for a in h.accounts:
            if a.attrs.get("spn") and a.name.lower() != "krbtgt":
                out.append(a)
    return out


def asrep_roastable(hosts: list[Host]) -> list[Account]:
    return [a for h in hosts for a in h.accounts
            if a.attrs.get("asrep_roastable") == "yes"]


def delegation_accounts(hosts: list[Host]) -> list[Account]:
    return [a for h in hosts for a in h.accounts if a.attrs.get("delegation")]


def quick_wins(hosts: list[Host]) -> list[dict]:
    """Single source of truth for AD 'quick win' rows (report + coverage tracking).

    Each row: {category, target, detail, why, key}.
    """
    rows: list[dict] = []

    def add(cat: str, target: str, detail: str, why: str) -> None:
        rows.append({"category": cat, "target": target, "detail": detail,
                     "why": why, "key": f"qw:{cat}:{target}"})

    for h in domain_controllers(hosts):
        add("Domain Controller", f"{h.ip} {h.hostname}".strip(),
            ", ".join(h.roles), "Primary AD target; hosts NTDS, Kerberos, LDAP.")
    for h in relay_targets(hosts):
        add("NTLM relay target", f"{h.ip} {h.hostname}".strip(),
            "SMB signing not required",
            "Relay coerced/captured NTLM auth to this host (ntlmrelayx).")
    for h in smbv1_hosts(hosts):
        add("SMBv1 / MS17-010", f"{h.ip} {h.hostname}".strip(),
            "SMBv1 enabled or ms17-010 flagged", "Potential unauthenticated RCE.")
    for a in kerberoastable(hosts):
        add("Kerberoastable", f"{a.domain}\\{a.name}".strip("\\"),
            a.attrs.get("spn", ""),
            "Request TGS and crack service-account password offline.")
    for a in asrep_roastable(hosts):
        add("AS-REP roastable", f"{a.domain}\\{a.name}".strip("\\"),
            "DONT_REQ_PREAUTH set",
            "Request AS-REP without preauth and crack offline (no creds needed).")
    for a in delegation_accounts(hosts):
        add("Delegation", f"{a.domain}\\{a.name}".strip("\\"),
            a.attrs.get("delegation", ""),
            "Abuse (un)constrained delegation for privesc / impersonation.")
    for a in privileged_accounts(hosts):
        add("Privileged account", f"{a.domain}\\{a.name}".strip("\\"),
            a.attrs.get("memberof", "") or "adminCount=1",
            "High-value credential; prioritise for compromise / protection.")
    return rows


def privileged_accounts(hosts: list[Host]) -> list[Account]:
    out = []
    for h in hosts:
        for a in h.accounts:
            if a.attrs.get("admincount") == "1":
                out.append(a)
                continue
            # Exact per-group membership: `memberof` is a "; "-joined list of group
            # CNs. A loose substring test flagged members of "Helpdesk Administrators"
            # / "SQL Administrators" / "DHCP Administrators" as tier-0 privileged
            # because those contain "administrators".
            groups = {g.strip().lower() for g in (a.attrs.get("memberof") or "").split(";")}
            if groups & {"domain admins", "enterprise admins", "administrators"}:
                out.append(a)
    return out


# --- domain assembly ------------------------------------------------------------

def derive_domains(hosts: list[Host]) -> list[Domain]:
    """Assemble Domain records from credential-free NSE data."""
    by_name: dict[str, Domain] = {}

    def get(name: str) -> Domain:
        key = name.lower()
        if key not in by_name:
            by_name[key] = Domain(name=name, sources=["nse"])
        return by_name[key]

    for h in hosts:
        dns_domain = h.ntlm.get("dns_domain", "")
        for a in h.accounts:
            if a.kind == "domain" and (a.domain or dns_domain):
                dns_domain = a.domain or dns_domain
        if not dns_domain:
            continue
        dom = get(dns_domain)
        nb = h.ntlm.get("netbios_domain", "")
        if nb and not dom.netbios:
            dom.netbios = nb
        if "Domain Controller" in h.roles and h.ip not in dom.dc_ips:
            dom.dc_ips.append(h.ip)
        pol = parse_password_policy(h)
        if pol and not dom.password_policy:
            dom.password_policy = pol
    return list(by_name.values())


def merge_domain(old: Domain, new: Domain) -> Domain:
    old.netbios = old.netbios or new.netbios
    old.forest = old.forest or new.forest
    old.functional_level = old.functional_level or new.functional_level
    old.naming_context = old.naming_context or new.naming_context
    old.machine_account_quota = old.machine_account_quota or new.machine_account_quota
    old.anonymous_bind = old.anonymous_bind or new.anonymous_bind
    old.dc_ips = sorted(set(old.dc_ips) | set(new.dc_ips))
    if new.password_policy:
        old.password_policy = {**old.password_policy, **new.password_policy}
    seen = {(t.get("name"), t.get("direction")) for t in old.trusts}
    for t in new.trusts:
        if (t.get("name"), t.get("direction")) not in seen:
            old.trusts.append(t)
    old.sources = sorted(set(old.sources) | set(new.sources))
    return old


# --- tier 2: credentialed LDAP enumeration (optional, via ldap3) -----------------

def _ldap3_present() -> bool:
    import importlib.util
    return importlib.util.find_spec("ldap3") is not None


def ldap_available() -> bool:
    """True if we can enumerate LDAP - either the ldap3 package or, on an
    airgapped Kali box, the ldapsearch binary (ldap-utils)."""
    return _ldap3_present() or shutil.which("ldapsearch") is not None


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _uac_flags(value: int) -> list[str]:
    return [name for name, bit in UAC.items() if value & bit]


def _func_level(val: str) -> str:
    return _FUNC_LEVEL.get(str(val), str(val))


def ldap_enumerate(
    dc_ip: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    use_ssl: bool = False,
    anonymous: bool = False,
) -> tuple[Domain, list[Account]]:
    """Enumerate a domain over LDAP. Returns (Domain, accounts).

    Uses the ldap3 package when installed; otherwise falls back to the Kali
    `ldapsearch` binary (airgapped-friendly). Raises RuntimeError if neither is
    available or the bind fails.
    """
    if not _ldap3_present():
        if _have("ldapsearch"):
            return _enum_ldapsearch(dc_ip, domain, username, password, use_ssl, anonymous)
        raise RuntimeError("LDAP enumeration needs the ldap3 package or the "
                           "ldapsearch binary (apt install ldap-utils).")
    return _enum_ldap3(dc_ip, domain, username, password, use_ssl, anonymous)


def _enum_ldap3(
    dc_ip: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    use_ssl: bool = False,
    anonymous: bool = False,
) -> tuple[Domain, list[Account]]:
    try:
        from ldap3 import ALL, Connection, NTLM, SUBTREE, Server
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "credentialed LDAP needs the ldapsearch binary (apt install ldap-utils) "
            "for airgapped use, or the ldap3 Python module") from e

    port = 636 if use_ssl else 389
    server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)
    if anonymous:
        conn = Connection(server, auto_bind=True)
    else:
        user = f"{domain}\\{username}" if domain else username
        conn = Connection(server, user=user, password=password,
                          authentication=NTLM, auto_bind=True)

    dom = Domain(name=domain, sources=["ldap"], dc_ips=[dc_ip])
    dom.anonymous_bind = anonymous

    # rootDSE + naming context.
    base_dn = ""
    try:
        info = server.info
        if info and info.other:
            ncs = info.other.get("defaultNamingContext") or info.naming_contexts
            base_dn = ncs[0] if isinstance(ncs, (list, tuple)) else str(ncs)
            fl = info.other.get("domainFunctionality", [""])
            dom.functional_level = _func_level(fl[0] if isinstance(fl, list) else fl)
            ffl = info.other.get("forestFunctionality", [""])
            dom.forest = _func_level(ffl[0] if isinstance(ffl, list) else ffl)
        dom.naming_context = base_dn
    except Exception:
        pass
    if not base_dn and domain:
        base_dn = ",".join(f"DC={p}" for p in domain.split("."))
        dom.naming_context = base_dn
    if not base_dn:
        conn.unbind()
        raise RuntimeError("Could not determine LDAP base DN; supply --domain.")

    accounts: list[Account] = []

    # Domain object -> password policy + machine account quota.
    try:
        conn.search(base_dn, "(objectClass=domain)", search_scope="BASE",
                    attributes=["minPwdLength", "lockoutThreshold", "maxPwdAge",
                                "minPwdAge", "pwdHistoryLength",
                                "ms-DS-MachineAccountQuota"])
        if conn.entries:
            e = conn.entries[0]
            pol = {}
            if "minPwdLength" in e:
                pol["min_length"] = int(e.minPwdLength.value or 0)
            if "lockoutThreshold" in e:
                pol["lockout_threshold"] = int(e.lockoutThreshold.value or 0)
            if "pwdHistoryLength" in e:
                pol["history"] = int(e.pwdHistoryLength.value or 0)
            if "maxPwdAge" in e and e.maxPwdAge.value:
                pol["max_age"] = str(e.maxPwdAge.value)
            dom.password_policy = pol
            maq = e["ms-DS-MachineAccountQuota"].value if "ms-DS-MachineAccountQuota" in e else None
            if maq is not None:
                dom.machine_account_quota = str(maq)
    except Exception:
        pass

    # Users.
    try:
        conn.search(base_dn,
                    "(&(objectCategory=person)(objectClass=user))",
                    search_scope=SUBTREE,
                    attributes=["sAMAccountName", "userAccountControl",
                                "servicePrincipalName", "adminCount", "memberOf",
                                "description", "pwdLastSet"],
                    paged_size=500)
        accounts += _accounts_from_entries(conn, dc_ip, domain, kind="user")
    except Exception:
        pass

    # Computers (delegation + OS).
    try:
        conn.search(base_dn, "(objectClass=computer)", search_scope=SUBTREE,
                    attributes=["sAMAccountName", "dNSHostName", "operatingSystem",
                                "operatingSystemVersion", "userAccountControl"],
                    paged_size=500)
        accounts += _accounts_from_entries(conn, dc_ip, domain, kind="computer")
    except Exception:
        pass

    # Privileged groups + members.
    try:
        conn.search(base_dn, "(objectClass=group)", search_scope=SUBTREE,
                    attributes=["sAMAccountName", "member", "adminCount", "description"],
                    paged_size=500)
        for e in conn.entries:
            name = str(e.sAMAccountName.value or "")
            if name.lower() in PRIVILEGED_GROUPS or (
                    "adminCount" in e and str(e.adminCount.value) == "1"):
                members = e.member.values if "member" in e else []
                accounts.append(Account(
                    ip=dc_ip, source="ldap", kind="group", name=name, domain=domain,
                    detail=f"{len(members)} member(s)",
                    attrs={"members": "; ".join(_cn(m) for m in members),
                           "admincount": "1"}))
    except Exception:
        pass

    # Trusts.
    try:
        conn.search(base_dn, "(objectClass=trustedDomain)", search_scope=SUBTREE,
                    attributes=["trustPartner", "trustDirection", "trustType"])
        _dir = {"1": "inbound", "2": "outbound", "3": "bidirectional"}
        for e in conn.entries:
            dom.trusts.append({
                "name": str(e.trustPartner.value or ""),
                "direction": _dir.get(str(e.trustDirection.value), str(e.trustDirection.value)),
                "type": str(e.trustType.value or ""),
            })
    except Exception:
        pass

    conn.unbind()
    return dom, accounts


def _cn(dn: str) -> str:
    m = re.match(r"CN=([^,]+)", dn or "")
    return m.group(1) if m else (dn or "")


def _accounts_from_entries(conn, dc_ip, domain, kind):
    """Convert ldap3 search results into Account objects with useful attrs."""
    out: list[Account] = []
    for e in conn.entries:
        name = str(e.sAMAccountName.value or "") if "sAMAccountName" in e else ""
        if not name:
            continue
        attrs: dict = {}
        uac = 0
        if "userAccountControl" in e and e.userAccountControl.value is not None:
            uac = int(e.userAccountControl.value)
            flags = _uac_flags(uac)
            attrs["enabled"] = "no" if "ACCOUNTDISABLE" in flags else "yes"
            if "DONT_REQ_PREAUTH" in flags:
                attrs["asrep_roastable"] = "yes"
            if "TRUSTED_FOR_DELEGATION" in flags:
                attrs["delegation"] = "unconstrained"
            elif "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
                attrs["delegation"] = "constrained"
            if "PASSWD_NOTREQD" in flags:
                attrs["passwd_notreqd"] = "yes"
        if "servicePrincipalName" in e and e.servicePrincipalName.value:
            spn = e.servicePrincipalName.value
            attrs["spn"] = "; ".join(spn) if isinstance(spn, list) else str(spn)
        if "adminCount" in e and str(e.adminCount.value) == "1":
            attrs["admincount"] = "1"
        if "memberOf" in e and e.memberOf.value:
            mo = e.memberOf.value
            attrs["memberof"] = "; ".join(_cn(m) for m in
                                          (mo if isinstance(mo, list) else [mo]))
        if "description" in e and e.description.value:
            attrs["description"] = str(e.description.value)
        if "operatingSystem" in e and e.operatingSystem.value:
            attrs["os"] = str(e.operatingSystem.value)
        if "dNSHostName" in e and e.dNSHostName.value:
            attrs["fqdn"] = str(e.dNSHostName.value)
        out.append(Account(ip=dc_ip, source="ldap", kind=kind, name=name,
                           domain=domain, attrs=attrs))
    return out


# --- ldapsearch (airgapped) path ------------------------------------------------

def _parse_ldif(text: str) -> list[dict]:
    """Parse ldapsearch LDIF output into a list of {attr: [values]} entries.

    Assumes `-o ldif-wrap=no` (no line folding). Handles base64 (attr:: b64).
    """
    entries: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        if not line.strip():
            if cur:
                entries.append(cur)
                cur = None
            continue
        if line.startswith("#") or ":" not in line:
            continue
        if line.lower().startswith("dn:"):
            if cur:
                entries.append(cur)
            cur = {}
        if cur is None:
            cur = {}
        attr, _, val = line.partition(":")
        attr = attr.strip()
        if val.startswith(":"):  # base64-encoded value
            try:
                val = base64.b64decode(val[1:].strip()).decode("utf-8", "replace")
            except Exception:
                val = val[1:].strip()
        else:
            val = val.strip()
        cur.setdefault(attr, []).append(val)
    if cur:
        entries.append(cur)
    return entries


def _run_ldapsearch(dc_ip, base, filt, attrs, scope, username, password, domain, ssl):
    proto = "ldaps" if ssl else "ldap"
    cmd = ["ldapsearch", "-x", "-o", "ldif-wrap=no", "-LLL",
           "-H", f"{proto}://{dc_ip}", "-s", scope, "-b", base]
    if username:
        bind = f"{username}@{domain}" if domain else username
        cmd += ["-D", bind, "-w", password or ""]
    cmd.append(filt)
    cmd += attrs
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=180)
    except (subprocess.TimeoutExpired, OSError, ValueError) as e:
        raise RuntimeError(f"ldapsearch failed: {e}")
    if proc.returncode not in (0, 4):  # 4 = size-limit exceeded (partial results)
        err = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else f"ldapsearch exit {proc.returncode}")
    return _parse_ldif(proc.stdout)


def _first(entry: dict, key: str, default: str = "") -> str:
    vals = entry.get(key) or entry.get(key.lower())
    return vals[0] if vals else default


def _acc_from_ldif(entry: dict, dc_ip: str, domain: str, kind: str) -> Account | None:
    name = _first(entry, "sAMAccountName")
    if not name:
        return None
    attrs: dict = {}
    uac_s = _first(entry, "userAccountControl")
    if uac_s.isdigit():
        flags = _uac_flags(int(uac_s))
        attrs["enabled"] = "no" if "ACCOUNTDISABLE" in flags else "yes"
        if "DONT_REQ_PREAUTH" in flags:
            attrs["asrep_roastable"] = "yes"
        if "TRUSTED_FOR_DELEGATION" in flags:
            attrs["delegation"] = "unconstrained"
        elif "TRUSTED_TO_AUTH_FOR_DELEGATION" in flags:
            attrs["delegation"] = "constrained"
    spns = entry.get("servicePrincipalName")
    if spns:
        attrs["spn"] = "; ".join(spns)
    if _first(entry, "adminCount") == "1":
        attrs["admincount"] = "1"
    memberof = entry.get("memberOf")
    if memberof:
        attrs["memberof"] = "; ".join(_cn(m) for m in memberof)
    desc = _first(entry, "description")
    if desc:
        attrs["description"] = desc
    os_ = _first(entry, "operatingSystem")
    if os_:
        attrs["os"] = os_
    return Account(ip=dc_ip, source="ldap", kind=kind, name=name, domain=domain, attrs=attrs)


def _enum_ldapsearch(dc_ip, domain, username, password, use_ssl, anonymous):
    user = "" if anonymous else username
    base = ",".join(f"DC={p}" for p in domain.split(".")) if domain else ""

    dom = Domain(name=domain, sources=["ldapsearch"], dc_ips=[dc_ip],
                 anonymous_bind=anonymous)

    # rootDSE for base DN + functional levels (anonymous bind is fine here).
    try:
        root = _run_ldapsearch(dc_ip, "", "(objectclass=*)",
                               ["defaultNamingContext", "domainFunctionality",
                                "forestFunctionality"], "base", "", "", "", use_ssl)
        if root:
            base = _first(root[0], "defaultNamingContext") or base
            dom.naming_context = base
            dom.functional_level = _func_level(_first(root[0], "domainFunctionality"))
            dom.forest = _func_level(_first(root[0], "forestFunctionality"))
    except RuntimeError:
        pass
    if not base:
        raise RuntimeError("Could not determine LDAP base DN; supply --domain.")

    accounts: list[Account] = []

    def q(filt, attrs, kind=None):
        try:
            entries = _run_ldapsearch(dc_ip, base, filt, attrs, "sub", user,
                                      password, domain, use_ssl)
        except RuntimeError:
            return []
        if kind:
            return [a for e in entries if (a := _acc_from_ldif(e, dc_ip, domain, kind))]
        return entries

    accounts += q("(&(objectCategory=person)(objectClass=user))",
                  ["sAMAccountName", "userAccountControl", "servicePrincipalName",
                   "adminCount", "memberOf", "description"], kind="user")
    accounts += q("(objectClass=computer)",
                  ["sAMAccountName", "dNSHostName", "operatingSystem",
                   "userAccountControl"], kind="computer")

    for e in q("(objectClass=group)", ["sAMAccountName", "member", "adminCount"]):
        gname = _first(e, "sAMAccountName")
        if gname.lower() in PRIVILEGED_GROUPS or _first(e, "adminCount") == "1":
            members = e.get("member", [])
            accounts.append(Account(ip=dc_ip, source="ldap", kind="group", name=gname,
                                    domain=domain, detail=f"{len(members)} member(s)",
                                    attrs={"members": "; ".join(_cn(m) for m in members),
                                           "admincount": "1"}))

    _dir = {"1": "inbound", "2": "outbound", "3": "bidirectional"}
    for e in q("(objectClass=trustedDomain)",
               ["trustPartner", "trustDirection", "trustType"]):
        dom.trusts.append({"name": _first(e, "trustPartner"),
                           "direction": _dir.get(_first(e, "trustDirection"),
                                                 _first(e, "trustDirection")),
                           "type": _first(e, "trustType")})

    # Domain object -> password policy + machine account quota.
    for e in q("(objectClass=domain)", ["minPwdLength", "lockoutThreshold",
                                        "pwdHistoryLength", "maxPwdAge",
                                        "ms-DS-MachineAccountQuota"]):
        pol = {}
        if _first(e, "minPwdLength").isdigit():
            pol["min_length"] = int(_first(e, "minPwdLength"))
        if _first(e, "lockoutThreshold").isdigit():
            pol["lockout_threshold"] = int(_first(e, "lockoutThreshold"))
        if _first(e, "pwdHistoryLength").isdigit():
            pol["history"] = int(_first(e, "pwdHistoryLength"))
        dom.password_policy = pol
        maq = _first(e, "ms-DS-MachineAccountQuota")
        if maq:
            dom.machine_account_quota = maq
        break

    return dom, accounts
