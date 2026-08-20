#!/usr/bin/env python3
"""Generate a high-fidelity mock engagement for UI/dev/testing.

Unlike a random seed, this builds *realistic* host archetypes - a Windows domain
controller, member servers, Linux web/DB boxes, workstations, network gear - each
with real service banners and findings that carry actual output, remediation,
structured evidence, QoD tiers, CVEs, KEV/EPSS, plus AD accounts and captured
credentials. The result exercises every corner of the workbench (detail drawer,
dashboard, targets tracker, report export) the way a real engagement would.

    python3 tools/mock_engagement.py /path/to/eng --hosts 60
    # or, from tests / code:
    from tools.mock_engagement import build
    stats = build(eng_dir, hosts=24, seed=1337)

Deterministic for a given (hosts, seed) so tests can assert on it.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce.models import Account, Credential, Evidence, Host, Port, Vuln  # noqa: E402


def _v(ip, port, script_id, title, severity, *, output, remediation, source,
       qod, qod_type, confidence, ids=None, cwes=None, evidence=None,
       kev=False, epss=0.0, protocol="tcp") -> Vuln:
    return Vuln(
        ip=ip, port=port, protocol=protocol, script_id=script_id,
        state="VULNERABLE", title=title, output=output, severity=severity,
        ids=ids or [], cwes=cwes or [], source=source, remediation=remediation,
        confidence=confidence, qod=qod, qod_type=qod_type,
        evidence=[Evidence(**e) for e in (evidence or [])], kev=kev, epss=epss,
    )


def _p(portid, service, product="", version="", **kw) -> Port:
    return Port(portid=portid, service=service, product=product, version=version, **kw)


# --- domain controller -------------------------------------------------------

def _dc(ip, hostname, domain, realm) -> Host:
    ports = [
        _p(53, "domain", "Simple DNS Plus"),
        _p(88, "kerberos-sec", "Microsoft Windows Kerberos"),
        _p(135, "msrpc", "Microsoft Windows RPC"),
        _p(139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
        _p(389, "ldap", "Microsoft Windows Active Directory LDAP", extrainfo=f"Domain: {realm}"),
        _p(445, "microsoft-ds", "Windows Server 2019 Standard", version="17763",
           banner="SMB 3.1.1"),
        _p(464, "kpasswd5"),
        _p(636, "ldapssl", "Microsoft Windows Active Directory LDAP"),
        _p(3268, "ldap", "Microsoft Windows Active Directory LDAP"),
        _p(3389, "ms-wbt-server", "Microsoft Terminal Services", tunnel="ssl"),
        _p(5985, "http", "Microsoft HTTPAPI httpd", version="2.0", banner="WinRM"),
    ]
    for p in ports:
        p.vuln_scanned = True
    vulns = [
        _v(ip, 445, "smb-vuln-zerologon", "Zerologon — Netlogon privilege escalation",
           "critical", ids=["CVE-2020-1472"], cwes=["CWE-330"], source="nse", kev=True, epss=0.944,
           qod=98, qod_type="active_vuln", confidence="confirmed",
           output=("The DC accepted a Netlogon ServerAuthenticate3 with a zero client\n"
                   "credential and zero flags after 256 attempts — the machine account\n"
                   "password can be reset to empty (impacket zerologon PoC succeeded)."),
           remediation="Apply the August 2020 CU (KB4565349+) and enable enforcement mode "
                       "(FullSecureChannelProtection). Rotate the DC machine account password twice.",
           evidence=[{"kind": "live-probe", "detail": "ServerAuthenticate3 succeeded with zero creds", "positive": True},
                     {"kind": "nse", "detail": "smb-vuln-zerologon: VULNERABLE", "positive": True}]),
        _v(ip, 88, "krb5-enum-spn", "Kerberoastable service account (svc_sql)",
           "high", source="probe", qod=90, qod_type="active_enum", confidence="confirmed",
           output=("GetUserSPNs returned an RC4-HMAC TGS for svc_sql (SPN MSSQLSvc/sql01."
                   f"{domain}:1433).\nHash captured — offline-crackable ($krb5tgs$23$...)."),
           remediation="Set a 25+ char random password on svc_sql, or move to a (Group) Managed "
                       "Service Account; disable RC4 for the account.",
           evidence=[{"kind": "on-target", "detail": "TGS-REP etype 23 (RC4-HMAC) captured", "positive": True}]),
        _v(ip, 389, "ldap-anon-bind", "LDAP allows anonymous bind",
           "medium", cwes=["CWE-287"], source="nse", qod=95, qod_type="active_vuln",
           confidence="confirmed",
           output="Anonymous bind to ldap://%s:389 succeeded; rootDSE + naming contexts readable." % ip,
           remediation="Set dsHeuristics to deny anonymous LDAP operations (bit 7 = 2).",
           evidence=[{"kind": "live-probe", "detail": "anonymous bind → 0 result code", "positive": True}]),
        _v(ip, 445, "smb-signing", "SMB signing not required is FALSE (good) — signing enforced",
           "info", source="probe", qod=80, qod_type="remote_banner", confidence="likely",
           output="Negotiated SMB 3.1.1; message signing required and enabled.",
           remediation="No action — signing is correctly enforced on the DC."),
    ]
    h = Host(ip=ip, up_reason="arp-response", hostnames=[hostname],
             os_name="Windows Server 2019 Standard 17763", os_family="Windows",
             ports=ports, vulns=vulns, roles=["Domain Controller"],
             smb_signing="required", enumerated=True, cred_enumerated=True,
             access_gained=True, access_detail="kerberoast → cracked svc_sql, DA via Zerologon",
             defenses=["Microsoft Defender AV"])
    # A real smb-os-discovery NSE probe reports the NetBIOS short name alongside the
    # DNS domain; derive_domains() reads it from here (h.ntlm), not from an Account.
    h.ntlm = {"netbios_domain": realm.split(".")[0], "dns_domain": domain}
    # attrs use recce's canonical shapes: "; "-joined strings for memberof/spn/members,
    # "1"/"yes"/"no" strings for flags (see recce/ad.py). Kerberoastable is *derived*
    # from an spn being present (not a flag), matching ad.kerberoastable().
    h.accounts = [
        # ad.derive_domains() keys off .domain (matching the real smb-os-discovery
        # parser's Account(kind="domain", domain=...) shape) - without it the DC
        # never resolves to a Domain record, silently dropping the "Domain contoso.
        # local" line from the markdown report and the whole Key information section
        # from assets.html.
        Account(ip=ip, source="ldap", kind="domain", domain=domain, name=realm,
                detail="functionalLevel: 2016"),
        Account(ip=ip, source="ldap", kind="user", name="Administrator", domain=domain,
                rid="500", attrs={"enabled": "yes", "admincount": "1", "memberof": "Domain Admins"}),
        Account(ip=ip, source="ldap", kind="user", name="svc_sql", domain=domain, rid="1104",
                attrs={"enabled": "yes", "spn": f"MSSQLSvc/sql01.{domain}:1433"}),
        Account(ip=ip, source="ldap", kind="user", name="svc_backup", domain=domain, rid="1108",
                attrs={"enabled": "yes", "asrep_roastable": "yes"}),
        Account(ip=ip, source="ldap", kind="group", name="Domain Admins", domain=domain, rid="512",
                attrs={"members": "Administrator; j.harmon", "admincount": "1"}),
        Account(ip=ip, source="smb-enum-shares", kind="share", name="SYSVOL",
                detail="READ — GPP cpassword found in Groups.xml"),
    ]
    return h


# --- windows member server ---------------------------------------------------

def _win_member(ip, hostname, domain, *, old=False) -> Host:
    ports = [
        _p(135, "msrpc", "Microsoft Windows RPC"),
        _p(139, "netbios-ssn", "Microsoft Windows netbios-ssn"),
        _p(445, "microsoft-ds",
           "Windows Server 2012 R2" if old else "Windows Server 2019 Standard",
           version="9600" if old else "17763"),
        _p(3389, "ms-wbt-server", "Microsoft Terminal Services", tunnel="ssl"),
    ]
    for p in ports:
        p.vuln_scanned = True
    vulns = [
        _v(ip, 445, "smb-security-mode", "SMB signing not required (NTLM relay)",
           "medium", cwes=["CWE-287"], source="probe", qod=80, qod_type="remote_banner",
           confidence="likely",
           output="Server negotiated SMB signing = enabled but NOT required — relayable.",
           remediation="Set 'Microsoft network server: Digitally sign communications (always)' "
                       "via GPO to require signing."),
    ]
    if old:
        vulns.append(_v(ip, 445, "smb-vuln-ms17-010",
            "EternalBlue — remote code execution in SMBv1", "critical",
            ids=["CVE-2017-0143", "CVE-2017-0144"], cwes=["CWE-119"], source="nse",
            kev=True, epss=0.975, qod=97, qod_type="active_vuln", confidence="confirmed",
            output=("smb-vuln-ms17-010: VULNERABLE — the host responded to a crafted\n"
                    "SMB1 trans2 request with STATUS_INSUFF_SERVER_RESOURCES."),
            remediation="Apply MS17-010. Disable SMBv1 entirely (it is deprecated).",
            evidence=[{"kind": "nse", "detail": "trans2 probe → INSUFF_SERVER_RESOURCES", "positive": True}]))
        vulns.append(_v(ip, 3389, "rdp-vuln-ms12-020",
            "BlueKeep — RDP remote code execution (pre-auth)", "critical",
            ids=["CVE-2019-0708"], cwes=["CWE-416"], source="nse", kev=True, epss=0.87,
            qod=75, qod_type="remote_banner", confidence="likely",
            output="Target is running an RDP stack (Windows Server 2012 R2) missing the "
                   "May 2019 fix; MS_T120 channel bind reachable pre-auth.",
            remediation="Apply the May 2019 CU; enable Network Level Authentication (NLA)."))
    h = Host(ip=ip, up_reason="syn-ack", hostnames=[hostname],
             os_name="Windows Server 2012 R2" if old else "Windows Server 2019 Standard",
             os_family="Windows", ports=ports, vulns=vulns,
             smb_signing="not required", enumerated=True,
             defenses=["Microsoft Defender AV"] if not old else [])
    return h


# --- linux web server --------------------------------------------------------

def _linux_web(ip, hostname, *, log4shell=False, heartbleed=False) -> Host:
    ports = [
        _p(22, "ssh", "OpenSSH", version="8.9p1 Ubuntu 3ubuntu0.6", banner="SSH-2.0-OpenSSH_8.9p1"),
        _p(80, "http", "nginx", version="1.18.0"),
        _p(443, "ssl/http", "nginx", version="1.18.0", tunnel="ssl"),
        _p(8080, "http", "Apache Tomcat", version="9.0.30"),
    ]
    for p in ports:
        p.vuln_scanned = True
    vulns = [
        _v(ip, 443, "ssl-enum-ciphers", "TLS 1.0/1.1 enabled (deprecated)",
           "low", cwes=["CWE-327"], source="nse", qod=98, qod_type="active_vuln",
           confidence="confirmed",
           output="Accepted protocols: TLSv1.0, TLSv1.1, TLSv1.2. TLS 1.0/1.1 are deprecated.",
           remediation="Disable TLS 1.0/1.1; serve TLS 1.2+ only with a modern cipher suite."),
        _v(ip, 80, "web-gitconfig", "Exposed .git/config — embedded credential looted",
           "high", cwes=["CWE-538"], source="web", qod=95, qod_type="active_vuln",
           confidence="confirmed",
           output=("GET /.git/config → 200. remote \"origin\" URL embeds a token:\n"
                   "  https://deploybot:ghp_****@github.com/contoso/webapp.git\n"
                   "CAPTURED 1 cleartext credential (deploybot) → credential store (sprayable)."),
           remediation="Block /.git in the web server; deploy from an artifact, not a working "
                       "tree; rotate the leaked token.",
           evidence=[{"kind": "live-probe", "detail": "GET /.git/config → 200, remote URL parsed", "positive": True}]),
        _v(ip, 80, "web-dotenv", "Exposed .env — DB credentials looted",
           "high", cwes=["CWE-538", "CWE-215"], source="web", qod=95, qod_type="active_vuln",
           confidence="confirmed",
           output=("GET /.env → 200.  leaked: DB_USER=webapp; DB_PASSWORD=Su…DB; "
                   "REDIS_PASSWORD=re…11\n"
                   "CAPTURED 2 cleartext credential(s) → credential store (sprayable)."),
           remediation="Move .env outside the web root; deny dotfiles; rotate the DB password.",
           evidence=[{"kind": "live-probe", "detail": "GET /.env → 200, secret pairs parsed", "positive": True}]),
        _v(ip, 8080, "http-default-creds", "Tomcat Manager default credentials",
           "high", cwes=["CWE-1392"], source="probe", qod=92, qod_type="active_enum",
           confidence="confirmed",
           output="POST /manager/html with tomcat:tomcat → 200. WAR deploy (RCE) available.",
           remediation="Remove/rename the Manager app or set a strong password; restrict by IP."),
    ]
    if log4shell:
        vulns.append(_v(ip, 8080, "http-log4shell",
            "Log4Shell — Log4j2 JNDI remote code execution", "critical",
            ids=["CVE-2021-44228"], cwes=["CWE-502", "CWE-917"], source="probe",
            kev=True, epss=0.976, qod=96, qod_type="active_vuln", confidence="confirmed",
            output=("Sent ${jndi:ldap://<listener>/a} in the User-Agent; the app made an\n"
                    "outbound LDAP callback to our listener — remote class loading confirmed."),
            remediation="Upgrade Log4j2 to 2.17.1+. As a stopgap set "
                        "log4j2.formatMsgNoLookups=true and remove JndiLookup.class.",
            evidence=[{"kind": "live-probe", "detail": "outbound LDAP callback received", "positive": True}]))
    if heartbleed:
        vulns.append(_v(ip, 443, "ssl-heartbleed",
            "Heartbleed — OpenSSL memory disclosure", "high",
            ids=["CVE-2014-0160"], cwes=["CWE-125"], source="nse", kev=True, epss=0.94,
            qod=95, qod_type="active_vuln", confidence="confirmed",
            output="Heartbeat response returned 16KB of process memory (server private data).",
            remediation="Upgrade OpenSSL to 1.0.1g+; revoke and reissue the certificate."))
    h = Host(ip=ip, up_reason="syn-ack", hostnames=[hostname],
             os_name="Ubuntu 22.04.3 LTS", os_family="Linux",
             ports=ports, vulns=vulns, enumerated=True,
             access_gained=log4shell, access_detail="Log4Shell RCE → www-data shell" if log4shell else "")
    return h


# --- linux database server ---------------------------------------------------

def _linux_db(ip, hostname, kind) -> Host:
    svc = {"redis": (6379, "redis", "Redis key-value store", "6.0.16"),
           "mongo": (27017, "mongodb", "MongoDB", "5.0.14"),
           "mysql": (3306, "mysql", "MySQL", "8.0.32"),
           "postgres": (5432, "postgresql", "PostgreSQL DB", "16.2")}[kind]
    ports = [_p(22, "ssh", "OpenSSH", version="8.9p1", banner="SSH-2.0-OpenSSH_8.9p1"),
             _p(svc[0], svc[1], svc[2], version=svc[3])]
    for p in ports:
        p.vuln_scanned = True
    vulns = []
    if kind == "redis":
        vulns.append(_v(ip, 6379, "redis-unauth", "Redis exposed without authentication",
            "high", cwes=["CWE-306"], source="probe", qod=95, qod_type="active_vuln",
            confidence="confirmed",
            output="INFO command answered without AUTH; CONFIG GET dir writable → RCE via module/cron.",
            remediation="Set requirepass, bind to localhost, enable protected-mode, firewall 6379."))
    elif kind == "mongo":
        vulns.append(_v(ip, 27017, "mongodb-unauth", "MongoDB exposed without authentication",
            "high", cwes=["CWE-306"], source="probe", qod=95, qod_type="active_vuln",
            confidence="confirmed",
            output="listDatabases returned 6 DBs (incl. 'prod') with no credentials.",
            remediation="Enable authorization (security.authorization: enabled); bind to private iface."))
    elif kind == "postgres":
        vulns.append(_v(ip, 5432, "postgres-trust-auth",
            "PostgreSQL trust authentication (no password) — pg_shadow looted", "high",
            cwes=["CWE-306", "CWE-287"], source="postgres", qod=95, qod_type="active_vuln",
            confidence="confirmed",
            output=("v3 startup for user 'postgres' returned AuthenticationOk with NO password "
                    "(trust in pg_hba.conf).\nLOOTED (read-only): 3 databases (postgres, "
                    "app_prod, billing); 2 password hash(es) captured (crackable) → postgres, app_svc."),
            remediation="Replace trust with scram-sha-256 in pg_hba.conf; bind to localhost; "
                        "require TLS for remote access.",
            evidence=[{"kind": "live-probe", "detail": "AuthenticationOk (code 0) with zero-length password", "positive": True}]))
    else:
        vulns.append(_v(ip, 3306, "mysql-empty-password",
            "MySQL root with empty password — mysql.user looted", "high",
            cwes=["CWE-521"], source="mysql", qod=90, qod_type="active_enum",
            confidence="confirmed",
            output=("mysql -uroot (no password) connected.\nLOOTED (read-only): mysql.user read "
                    "— 2 password hash(es) captured (root, app); crack with hashcat -m 300."),
            remediation="Set a strong root password; remove anonymous accounts; bind to localhost."))
    return Host(ip=ip, up_reason="syn-ack", hostnames=[hostname],
                os_name="Debian 12", os_family="Linux", ports=ports, vulns=vulns,
                enumerated=True)


# --- workstation / network gear ---------------------------------------------

def _workstation(ip, hostname) -> Host:
    ports = [_p(135, "msrpc", "Microsoft Windows RPC"),
             _p(139, "netbios-ssn"), _p(445, "microsoft-ds", "Windows 10 Pro", version="19045"),
             _p(3389, "ms-wbt-server", "Microsoft Terminal Services")]
    for p in ports:
        p.vuln_scanned = True
    vulns = [_v(ip, 445, "smb-os-discovery", "Windows 10 build 19045 (banner)",
                "info", source="version-db", qod=45, qod_type="version_only", confidence="potential",
                output="OS via SMB: Windows 10 Pro 19045.", remediation="Informational.")]
    return Host(ip=ip, up_reason="arp-response", hostnames=[hostname],
                os_name="Windows 10 Pro 19045", os_family="Windows",
                ports=ports, vulns=vulns, smb_signing="not required",
                enumerated=random.random() < 0.5, defenses=["Microsoft Defender AV"])


def _netgear(ip, hostname) -> Host:
    ports = [_p(23, "telnet", "Cisco IOS telnetd"),
             _p(161, "snmp", "net-snmp", version="5.7", protocol="udp"),
             _p(443, "ssl/http", "Cisco IOS http", tunnel="ssl")]
    for p in ports:
        p.vuln_scanned = True
    vulns = [
        _v(ip, 161, "snmp-public", "SNMP default community 'public'", "medium",
           cwes=["CWE-1392"], source="probe", qod=92, qod_type="active_enum",
           confidence="confirmed", protocol="udp",
           output="snmpget with community 'public' returned sysDescr (Cisco IOS 15.1).",
           remediation="Change/disable public community; use SNMPv3 with auth+priv."),
        _v(ip, 23, "telnet-open", "Telnet enabled (cleartext management)", "medium",
           cwes=["CWE-319"], source="probe", qod=90, qod_type="remote_banner",
           confidence="likely",
           output="Telnet banner: 'User Access Verification'. Credentials sent in cleartext.",
           remediation="Disable telnet; use SSH for management."),
    ]
    return Host(ip=ip, up_reason="syn-ack", hostnames=[hostname],
                os_name="Cisco IOS 15.1", os_family="IOS", ports=ports, vulns=vulns)


# --- non-AD file server (standalone SMB + NFS shares) ------------------------
# The user's environments aren't all AD — plenty are workgroup NAS/Linux boxes
# whose exposure is unauthenticated SMB/NFS shares. This archetype exercises the
# non-AD share-enum + spider + secret-file path.

def _fileserver(ip, hostname) -> Host:
    ports = [
        _p(111, "rpcbind", "rpcbind", version="2-4", extrainfo="RPC #100000"),
        _p(139, "netbios-ssn", "Samba smbd", version="4.15.13-Ubuntu"),
        _p(445, "microsoft-ds", "Samba smbd", version="4.15.13-Ubuntu", banner="SMB 3.1.1"),
        _p(2049, "nfs", "nfs", version="3-4", extrainfo="RPC #100003"),
    ]
    for p in ports:
        p.vuln_scanned = True
    vulns = [
        _v(ip, 445, "smb-null-session-shares", "SMB shares readable over a null/guest session",
           "high", cwes=["CWE-306"], source="smb", qod=95, qod_type="active_enum",
           confidence="confirmed",
           output=("Null session (-U '' -N) listed shares; guest mapped to 'Finance' and\n"
                   "'IT-Backup' with READ. No domain — standalone workgroup (WORKGROUP)."),
           remediation="Set 'restrict anonymous', disable the guest account, require "
                       "authenticated access; remove world-readable shares.",
           evidence=[{"kind": "on-target", "detail": "smbclient -N -L → Finance, IT-Backup (READ)", "positive": True}]),
        _v(ip, 445, "smb-secret-file", "Credential-bearing file found in an open share",
           "high", cwes=["CWE-538", "CWE-256"], source="smb", qod=92, qod_type="active_enum",
           confidence="confirmed",
           output=("Spidered //%s/IT-Backup → unattend.xml contains an AutoLogon local\n"
                   "administrator password (cleartext). Captured → credential store." % ip),
           remediation="Remove secrets from shares; scrub unattend/sysprep answer files; "
                       "rotate the exposed local admin password.",
           evidence=[{"kind": "on-target", "detail": "IT-Backup/unattend.xml → <Password> cleartext", "positive": True}]),
        _v(ip, 2049, "nfs-world-export", "NFS export world-readable with no_root_squash",
           "high", cwes=["CWE-306", "CWE-732"], source="probe", qod=93, qod_type="active_enum",
           confidence="confirmed",
           output=("showmount -e → /srv/nfs/backups *(rw,no_root_squash). Any host can mount\n"
                   "read-write AND write files owned by root → trivial privilege escalation."),
           remediation="Restrict exports to specific hosts; set root_squash; drop rw where not needed."),
    ]
    h = Host(ip=ip, up_reason="syn-ack", hostnames=[hostname],
             os_name="Ubuntu 22.04 (Samba)", os_family="Linux",
             ports=ports, vulns=vulns, roles=["File server"],
             smb_signing="not required", enumerated=True, access_gained=True,
             access_detail="unattend.xml local admin looted from IT-Backup share")
    h.accounts = [
        Account(ip=ip, source="smb-enum-shares", kind="share", name="Finance",
                detail="READ via guest — 4.2 GB of finance spreadsheets"),
        Account(ip=ip, source="smb-enum-shares", kind="share", name="IT-Backup",
                detail="READ via guest — contains unattend.xml (local admin password)"),
        Account(ip=ip, source="nfs-showmount", kind="share", name="/srv/nfs/backups",
                detail="NFS export *(rw,no_root_squash) — world-mountable"),
    ]
    return h


def build(eng_dir: str, hosts: int = 48, seed: int = 1337,
          engagement: str = "Contoso Corp — internal network assessment") -> dict:
    """Seed a realistic engagement into eng_dir. Returns summary counts."""
    random.seed(seed)
    from recce.cli import _open_paths
    from recce.store import Store
    from recce.targets import _subnet_of

    st = Store(_open_paths(eng_dir)["db"])
    try:
        st.set_meta("engagement", engagement)
        for sn in ("10.20.10.0/24", "10.20.20.0/24", "10.20.30.0/24"):
            st.set_scope(sn, 254)

        domain, realm = "contoso.local", "CONTOSO.LOCAL"
        made: list[Host] = []
        made.append(_dc("10.20.10.10", "dc01.contoso.local", domain, realm))
        made.append(_win_member("10.20.10.11", "sql01.contoso.local", domain))
        made.append(_win_member("10.20.10.23", "fs01.contoso.local", domain, old=True))
        made.append(_linux_web("10.20.20.15", "web01.contoso.local", log4shell=True))
        made.append(_linux_web("10.20.20.16", "web02.contoso.local", heartbleed=True))
        made.append(_linux_db("10.20.20.30", "redis01.contoso.local", "redis"))
        made.append(_linux_db("10.20.20.31", "mongo01.contoso.local", "mongo"))
        made.append(_linux_db("10.20.20.32", "db01.contoso.local", "mysql"))
        made.append(_linux_db("10.20.20.33", "pg01.contoso.local", "postgres"))
        made.append(_fileserver("10.20.20.40", "nas01"))       # non-AD workgroup NAS
        made.append(_netgear("10.20.30.1", "core-sw01.contoso.local"))

        # fill out the rest with workstations + the odd extra server, across subnets.
        # Start above the fixed-archetype host numbers (…40 nas01) to avoid IP collisions.
        i = 50
        while len(made) < hosts:
            sub = random.choice([10, 20, 30])
            ip = f"10.20.{sub}.{i}"
            i += 1
            r = random.random()
            if r < 0.14:
                made.append(_win_member(ip, f"srv-{i}.contoso.local", domain, old=random.random() < 0.3))
            elif r < 0.22:
                made.append(_linux_web(ip, f"app-{i}.contoso.local",
                                       log4shell=random.random() < 0.25))
            else:
                made.append(_workstation(ip, f"ws-{i:03d}.contoso.local"))

        nf = 0
        for h in made:
            h.subnet = _subnet_of(h.ip)     # a real scan/import always sets this
            st.upsert_host(h, merge=False)
            nf += len(h.vulns)

        # captured credentials — the full loot surface: kerberoast + GPP + default
        # logins (AD), web-loot (.git/.env cleartext), DB-loot (pg_shadow / mysql.user
        # hashes), and a share-looted local admin. These stack for the spray chain.
        creds = [
            Credential(username="svc_sql", secret="Summer2023!", kind="password", domain=domain,
                       source="kerberoast", origin_ip="10.20.10.10", notes="cracked TGS (RC4), 6h"),
            Credential(username="localadmin", secret="aad3b435b51404eeaad3b435b51404ee:31d6...",
                       kind="nthash", domain="", source="secretsdump", origin_ip="10.20.10.23"),
            Credential(username="backupsvc", secret="P@ssw0rd-Gpp", kind="password", domain=domain,
                       source="gpp", origin_ip="10.20.10.10", notes="GPP cpassword in SYSVOL Groups.xml"),
            Credential(username="tomcat", secret="tomcat", kind="password", domain="",
                       source="default", origin_ip="10.20.20.15"),
            # web-loot: cleartext, directly sprayable (from web01's exposed .git/.env)
            Credential(username="deploybot", secret="ghp_A1b2C3d4E5f6DEADBEEFcafe0011",
                       kind="password", domain="", source="web-loot", origin_ip="10.20.20.15",
                       notes="embedded in .git/config remote URL (sprayable)"),
            Credential(username="webapp", secret="Sup3rS3cr3t!DB", kind="password", domain="",
                       source="web-loot", origin_ip="10.20.20.15", notes="DB_PASSWORD from exposed .env"),
            # db-loot: password hashes (crackable, not directly sprayable)
            Credential(username="postgres", secret="SCRAM-SHA-256$4096:Hh8…$rk9…", kind="hash",
                       domain="", source="postgres-loot", origin_ip="10.20.20.33",
                       notes="pg_shadow hash from trust-auth PostgreSQL"),
            Credential(username="root", secret="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B",
                       kind="nthash", domain="", source="mysql-loot", origin_ip="10.20.20.32",
                       notes="mysql.user hash (empty-password root); hashcat -m 300"),
            # share-loot: cleartext local admin from an open SMB share (non-AD)
            Credential(username="Administrator", secret="Nas-Local-Adm!n2022", kind="password",
                       domain="", source="loot", origin_ip="10.20.20.40",
                       notes="unattend.xml AutoLogon password from //nas01/IT-Backup"),
        ]
        ncred = sum(1 for c in creds if st.add_credential(c))
        st.add_issue("10.20.10.23", "vulns", "warn",
                     "SMBv1 enabled on fs01 — EternalBlue exploitable; segment/patch urgently")
        return {"hosts": len(made), "findings": nf, "credentials": ncred,
                "subnets": 3, "domain": domain}
    finally:
        st.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed a high-fidelity mock recce engagement")
    ap.add_argument("eng_dir", help="engagement directory to create/populate")
    ap.add_argument("--hosts", type=int, default=48)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    stats = build(args.eng_dir, hosts=args.hosts, seed=args.seed)
    print(f"[+] seeded {stats['hosts']} hosts, {stats['findings']} findings, "
          f"{stats['credentials']} creds → {args.eng_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
