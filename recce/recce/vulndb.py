"""Offline vulnerability engine - the part that beats stock Kali airgapped.

Kali's `nmap --script vulners` maps service versions to CVEs, but it queries
vulners.com and returns NOTHING on an airgapped network. This module ships a
curated, no-internet knowledge base of high-value findings you actually hit on
internal engagements, and matches it against the product+version data `enum`
already collected - producing prioritized findings with a description, CVE
references, and *remediation*, none of which raw nmap output gives you.

The database is plain Python data (extensible - add a dict, no code). Matching is
pure standard library.
"""

from __future__ import annotations

import re

from .models import Host, Port, Vuln


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable numeric tuple.

    '2.4.41' -> (2,4,41); '8.2p1' -> (8,2,1); '1.0.2k' -> (1,0,2,11).
    Trailing letters become their alphabet index so 2.3.4 < 2.3.4a.
    """
    v = v.strip().lower()
    parts: list[int] = []
    for token in re.split(r"[.\-_]", v):
        # Match the OpenSSH-style pN patch BEFORE the generic trailing letter, so
        # the greedy [a-z]* can't swallow the 'p' (which collapsed 9.3p1 == 9.3p2).
        m = re.match(r"(\d+)(?:p(\d+))?([a-z]*)", token)
        if not m:
            continue
        parts.append(int(m.group(1)))
        if m.group(2):                     # OpenSSH-style pN (8.2p1 -> ...,1)
            parts.append(int(m.group(2)))
        elif m.group(3):                   # trailing letter (1.0.2k -> ...,11)
            parts.append(ord(m.group(3)[0]) - ord("a") + 1)
    return tuple(parts) or (0,)


def _clean_version(v: str) -> str:
    """Normalize a service version before comparison.

    MariaDB 10.x announces itself with a legacy MySQL-compat handshake prefix:
    "5.5.5-10.11.6-MariaDB-0+deb12u1" - the real version is 10.11.6. Without
    stripping the "5.5.5-" prefix, _ver_tuple reads the leading 5.5.5 and a
    patched MariaDB matches the MySQL "< 5.7 EOL" and "5.5.x / CVE-2012-2122"
    ranges, fabricating findings. A genuine MySQL 5.5.5 has no "-<version>" after
    it, so it is left untouched (and correctly flagged as EOL).
    """
    v = v.strip()
    m = re.match(r"5\.5\.5-(\d+\.\d+.*)", v, re.I)
    return m.group(1) if m else v


def _cmp(a: str, b: str) -> int:
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _same_base_no_p(v: str, bound: str) -> bool:
    """True when `v` is a bare X.Y release and `bound` is X.YpN of the SAME base -
    e.g. v='9.8', bound='9.8p1'. OpenSSH's portable pN is the same release as the
    OpenBSD base for vuln purposes, so a bare 9.8 must not read as < 9.8p1 (which
    flagged the patched 9.8 as vulnerable to regreSSHion)."""
    if "p" not in bound.lower():
        return False
    if re.search(r"\d+p\d+", v.lower()):        # v has its own pN -> normal compare
        return False
    base = re.sub(r"(?i)(\d+)p\d+", r"\1", bound)   # 9.8p1 -> 9.8
    return _ver_tuple(v) == _ver_tuple(base)


def _product_in(token: str, blob: str) -> bool:
    """Whole-token product match so 'bind' does not match 'rpcbind' and 'php' does
    not match 'phpmyadmin'. Boundaries are non-alphanumeric, so 'php-cgi', 'isc
    bind', 'ms-sql' still match; the token may contain spaces/dots itself."""
    return re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", blob) is not None


# Service version/extrainfo markers that mean the build is DISTRO-PACKAGED, so a
# fix is often backported with the upstream version string left unchanged - a bare
# version match then can't be trusted as "vulnerable" without checking the package.
_DISTRO_RE = re.compile(
    r"ubuntu|debian|\+deb|raspbian|\bel[5-9]\b|rhel|centos|red\s?hat|amzn|"
    r"\.fc\d|fedora|suse|\+dfsg|mageia|\bcp\d", re.I)


def _distro_packaged(port: "Port") -> bool:
    return bool(_DISTRO_RE.search(f"{port.version} {port.extrainfo}"))


def _in_range(version: str, lo: str | None, hi: str | None,
              lo_incl: bool, hi_incl: bool) -> bool:
    if lo is not None:
        c = _cmp(version, lo)
        if c < 0 or (c == 0 and not lo_incl):
            return False
    if hi is not None:
        c = _cmp(version, hi)
        # A bare X.Y is the same release as the X.YpN upper bound (see above): don't
        # let the missing pN component read as "below" the bound.
        if c < 0 and _same_base_no_p(version, hi):
            c = 0
        if c > 0 or (c == 0 and not hi_incl):
            return False
    return True


# --- the knowledge base ---------------------------------------------------------
# Each signature: product substring(s) to match against port.product/service,
# an optional version range, and the finding. Ranges use lt/le/ge/gt/eq/exact.
#
# Keep entries high-signal (things that actually matter on internal tests) and
# version-detectable from nmap -sV. Config-only findings live in parser.py.
#
# Fields:
#   product     list of lowercase substrings matched against "product service"
#   eq/lt/le/ge/gt   optional version bounds (omit all -> product-only advisory)
#   os / os_lt  optional OS gate (os_lt without version = OS-only match)
#   severity    critical/high/medium/low/info
#   title       one-line finding name (also the dedupe key)
#   cves        CVE references (may be empty)
#   cwe         CWE weakness references (e.g. ["CWE-78"])
#   remediation offline fix guidance
#   desc        what/why for the operator
#   advisory    True -> product-only informational lead (confidence "potential")

SIGNATURES: list[dict] = [
    # --- FTP -------------------------------------------------------------------
    {"product": ["vsftpd"], "eq": "2.3.4", "severity": "critical",
     "title": "vsftpd 2.3.4 backdoor (smiley-face) - remote root",
     "cves": ["CVE-2011-2523"], "cwe": ["CWE-78", "CWE-506"],
     "remediation": "Replace this build immediately; upgrade vsftpd.",
     "desc": "This exact build shipped with a backdoor that spawns a root shell "
             "on port 6200 when a ':)' username is sent."},
    {"product": ["proftpd"], "eq": "1.3.3c", "severity": "critical",
     "title": "ProFTPD 1.3.3c compromised source backdoor",
     "cves": ["CVE-2010-4221"], "cwe": ["CWE-78", "CWE-506"],
     "remediation": "Upgrade ProFTPD to a current release.",
     "desc": "The 1.3.3c distribution tarball was trojaned; allows remote code exec."},
    {"product": ["proftpd"], "ge": "1.3.5", "lt": "1.3.5b", "severity": "critical",
     "title": "ProFTPD 1.3.5 mod_copy unauth file copy / RCE",
     "cves": ["CVE-2015-3306"], "cwe": ["CWE-264"],
     "remediation": "Upgrade ProFTPD to 1.3.5b/1.3.6+ or disable mod_copy.",
     "desc": "SITE CPFR/CPTO lets an unauthenticated user copy files, often "
             "leading to webshell upload and remote code execution."},
    # --- SSH -------------------------------------------------------------------
    {"product": ["openssh"], "lt": "7.7", "severity": "medium",
     "title": "OpenSSH < 7.7 username enumeration",
     "cves": ["CVE-2018-15473"], "cwe": ["CWE-200", "CWE-203"],
     "remediation": "Upgrade OpenSSH to 7.7 or later.",
     "desc": "Timing/response differences let an unauthenticated attacker "
             "enumerate valid usernames - useful for password spraying."},
    {"product": ["openssh"], "lt": "9.3p2", "ge": "8.5", "severity": "high",
     "title": "OpenSSH 8.5-9.3 double-free (potential RCE)",
     "cves": ["CVE-2023-38408", "CVE-2023-25136"], "cwe": ["CWE-415"],
     "remediation": "Upgrade OpenSSH to 9.3p2+.",
     "desc": "Memory-safety issues in ssh-agent/forwarding paths that have been "
             "shown to be exploitable in some configurations."},
    {"product": ["openssh"], "ge": "8.5p1", "lt": "9.8p1", "severity": "critical",
     "title": "OpenSSH 'regreSSHion' pre-auth RCE",
     "cves": ["CVE-2024-6387"], "cwe": ["CWE-364"],
     "remediation": "Upgrade OpenSSH to 9.8p1+ or set LoginGraceTime 0.",
     "desc": "Signal-handler race in sshd allows unauthenticated remote code "
             "execution as root on glibc Linux (32-bit demonstrated)."},
    # --- Apache HTTPD ----------------------------------------------------------
    {"product": ["apache httpd", "apache"], "ge": "2.4.49", "le": "2.4.50",
     "severity": "critical",
     "title": "Apache 2.4.49/2.4.50 path traversal & RCE",
     "cves": ["CVE-2021-41773", "CVE-2021-42013"], "cwe": ["CWE-22"],
     "remediation": "Upgrade to Apache httpd 2.4.51 or later.",
     "desc": "Unauthenticated path traversal that can read files outside the "
             "docroot and, with mod_cgi enabled, achieve remote code execution."},
    {"product": ["apache httpd", "apache"], "lt": "2.4.53", "ge": "2.4",
     "severity": "high",
     "title": "Apache httpd < 2.4.53 multiple vulns (mod_lua/proxy)",
     "cves": ["CVE-2022-22720", "CVE-2022-23943"], "cwe": ["CWE-444", "CWE-787"],
     "remediation": "Upgrade to the latest Apache httpd 2.4.x.",
     "desc": "HTTP request smuggling and out-of-bounds writes in several modules."},
    {"product": ["apache httpd", "apache"], "ge": "2.4.17", "lt": "2.4.59",
     "severity": "high",
     "title": "Apache httpd < 2.4.59 mod_proxy SSRF / smuggling",
     "cves": ["CVE-2023-25690", "CVE-2024-27316"], "cwe": ["CWE-444"],
     "remediation": "Upgrade to Apache httpd 2.4.59 or later.",
     "desc": "Request-smuggling and HTTP/2 memory-exhaustion issues in the "
             "proxy/mod_http2 code paths."},
    # --- nginx -----------------------------------------------------------------
    {"product": ["nginx"], "lt": "1.21.0", "ge": "0.6.18", "severity": "high",
     "title": "nginx < 1.21.0 resolver off-by-one (CVE-2021-23017)",
     "cves": ["CVE-2021-23017"], "cwe": ["CWE-193", "CWE-787"],
     "remediation": "Upgrade nginx to 1.21.0+ or drop the resolver directive.",
     "desc": "Off-by-one in the DNS resolver, potentially exploitable for RCE."},
    # --- Microsoft IIS / Exchange / RDP / SMB ----------------------------------
    {"product": ["microsoft iis", "iis httpd"], "lt": "7.5", "severity": "medium",
     "title": "Legacy Microsoft IIS (<= 7.0) - unsupported",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Migrate off end-of-life IIS/Windows Server.",
     "desc": "Runs on an unsupported Windows Server; multiple public exploits."},
    {"product": ["microsoft terminal services", "ms-wbt-server", "terminal services"],
     "os": "windows", "os_lt": "6.2", "severity": "critical",
     "title": "RDP on Windows <= 7/2008 R2 - BlueKeep exposure",
     "cves": ["CVE-2019-0708"], "cwe": ["CWE-416"],
     "remediation": "Patch (MS mitigations for CVE-2019-0708) or disable RDP; "
                    "enable Network Level Authentication.",
     "desc": "Pre-auth wormable RDP RCE affecting Windows 7 / Server 2008 R2 and "
             "earlier. Confirm with a dedicated BlueKeep check before exploiting."},
    {"product": ["microsoft exchange", "outlook web", "owa"], "severity": "critical",
     "title": "Microsoft Exchange exposed - ProxyLogon/ProxyShell risk",
     "cves": ["CVE-2021-26855", "CVE-2021-34473", "CVE-2021-34523"],
     "cwe": ["CWE-918", "CWE-22"], "advisory": True,
     "remediation": "Apply current Exchange cumulative updates + security patches; "
                    "restrict OWA/ECP exposure.",
     "desc": "Internet/intranet-facing Exchange is a prime target (ProxyLogon "
             "SSRF pre-auth, ProxyShell path confusion). Confirm build number and "
             "patch level; unpatched = full mailbox/host compromise."},
    # --- Samba / SMB -----------------------------------------------------------
    {"product": ["samba"], "ge": "3.5.0", "lt": "4.6.4", "severity": "critical",
     "title": "Samba 'SambaCry' remote code execution",
     "cves": ["CVE-2017-7494"], "cwe": ["CWE-94"],
     "remediation": "Upgrade Samba to 4.6.4/4.5.10/4.4.14+ or set "
                    "'nt pipe support = no'.",
     "desc": "A malicious client can upload and cause the server to load a shared "
             "library, executing code as root."},
    {"product": ["samba"], "lt": "3.5.0", "ge": "3.0", "severity": "high",
     "title": "Legacy Samba 3.x - multiple RCE (incl. usermap_script)",
     "cves": ["CVE-2007-2447"], "cwe": ["CWE-78"],
     "remediation": "Upgrade Samba; this is end-of-life.",
     "desc": "Old Samba 3.x has command-injection and heap RCE bugs "
             "(usermap_script is a classic unauth root shell)."},
    # --- Databases -------------------------------------------------------------
    {"product": ["mysql"], "lt": "5.7.0", "ge": "5.0", "severity": "medium",
     "title": "End-of-life MySQL (< 5.7) exposed",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Upgrade to a supported MySQL/MariaDB and restrict network access.",
     "desc": "Unsupported MySQL with many public CVEs; should not be network-exposed."},
    {"product": ["mysql"], "ge": "5.5.0", "le": "5.5.63", "severity": "high",
     "title": "MySQL 5.5.x remote pre-auth issues",
     "cves": ["CVE-2012-2122"], "cwe": ["CWE-287"],
     "remediation": "Upgrade MySQL; enforce strong auth.",
     "desc": "Some 5.5/5.6 builds allow an authentication bypass on repeated tries."},
    {"product": ["postgresql"], "lt": "11.0", "ge": "9.0", "severity": "medium",
     "title": "End-of-life PostgreSQL exposed",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Upgrade to a supported PostgreSQL major version.",
     "desc": "Unsupported PostgreSQL exposed on the network."},
    {"product": ["mongodb"], "lt": "3.6.0", "severity": "high",
     "title": "Legacy MongoDB (< 3.6) - default no-auth exposure",
     "cves": [], "cwe": ["CWE-306"],
     "remediation": "Upgrade MongoDB; enable authentication and bind to localhost.",
     "desc": "Old MongoDB defaulted to no authentication and open binding - "
             "frequently exposes entire databases."},
    {"product": ["redis"], "lt": "6.0.0", "severity": "high",
     "title": "Redis < 6.0 - no ACLs, common unauth RCE",
     "cves": [], "cwe": ["CWE-306"],
     "remediation": "Upgrade Redis 6+, require a password, bind to localhost.",
     "desc": "Pre-6.0 Redis has no ACLs; unauthenticated access allows config "
             "rewrite to drop SSH keys or cron jobs (RCE)."},
    {"product": ["elasticsearch"], "lt": "6.0.0", "severity": "high",
     "title": "Legacy Elasticsearch (< 6.0) - unauth data / Groovy RCE",
     "cves": ["CVE-2015-1427", "CVE-2014-3120"], "cwe": ["CWE-95", "CWE-306"],
     "remediation": "Upgrade Elasticsearch; enable security; never expose 9200.",
     "desc": "Old Elasticsearch exposes all indices without auth and had "
             "Groovy/MVEL sandbox-escape RCE in the search API."},
    {"product": ["memcached"], "severity": "medium", "advisory": True,
     "title": "Memcached exposed - amplification / data exposure",
     "cves": ["CVE-2018-1000115"], "cwe": ["CWE-306"],
     "remediation": "Bind memcached to localhost, disable UDP, firewall 11211.",
     "desc": "Network-exposed memcached leaks cached data and is a massive UDP "
             "reflection/amplification vector."},
    # --- Web apps / middleware -------------------------------------------------
    {"product": ["jenkins"], "lt": "2.319", "severity": "high",
     "title": "Outdated Jenkins - multiple RCE / auth bypass",
     "cves": ["CVE-2019-1003000", "CVE-2018-1000861"], "cwe": ["CWE-94"],
     "remediation": "Upgrade Jenkins to the latest LTS; restrict access.",
     "desc": "Old Jenkins is a frequent full-compromise vector (script console, "
             "unauth RCE chains)."},
    {"product": ["jenkins"], "severity": "medium", "advisory": True,
     "title": "Jenkins exposed - check for weak/default auth & CVE-2024-23897",
     "cves": ["CVE-2024-23897"], "cwe": ["CWE-22", "CWE-1188"],
     "remediation": "Require authentication, disable anonymous read, patch CLI.",
     "desc": "Jenkins CI is high-value. Recent CLI arbitrary-file-read "
             "(CVE-2024-23897) can leak secrets leading to RCE; also check for "
             "anonymous access and default credentials."},
    {"product": ["apache tomcat", "tomcat"], "lt": "9.0.31", "ge": "6.0",
     "severity": "high",
     "title": "Apache Tomcat AJP 'Ghostcat' file read/inclusion",
     "cves": ["CVE-2020-1938"], "cwe": ["CWE-22"],
     "remediation": "Upgrade Tomcat; disable/secure the AJP connector (8009).",
     "desc": "The AJP connector allows reading web-app files and, with upload, RCE."},
    {"product": ["apache tomcat", "tomcat", "coyote"], "severity": "medium",
     "advisory": True,
     "title": "Tomcat exposed - check /manager for default credentials",
     "cves": [], "cwe": ["CWE-1392", "CWE-798"],
     "remediation": "Remove or firewall the Manager/Host-Manager apps; change "
                    "default tomcat/admin credentials.",
     "desc": "Tomcat Manager with default creds (tomcat/tomcat, admin/admin) gives "
             "WAR-upload RCE - one of the most common internal footholds."},
    {"product": ["php"], "lt": "7.4.0", "ge": "5.0", "severity": "medium",
     "title": "End-of-life PHP (< 7.4) in use",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Upgrade to a supported PHP release.",
     "desc": "Unsupported PHP with many known vulns backing the web app."},
    {"product": ["php-cgi", "php cgi"], "severity": "critical", "advisory": True,
     "title": "PHP-CGI argument injection (CVE-2024-4577) exposure",
     "cves": ["CVE-2024-4577", "CVE-2012-1823"], "cwe": ["CWE-88"],
     "remediation": "Patch PHP; avoid running PHP as CGI; apply mod_rewrite guards.",
     "desc": "PHP running as CGI (esp. on Windows/XAMPP) is exploitable for "
             "unauthenticated RCE via query-string argument injection."},
    {"product": ["drupal"], "lt": "7.58", "severity": "critical",
     "title": "Drupal 'Drupalgeddon2' pre-auth RCE",
     "cves": ["CVE-2018-7600"], "cwe": ["CWE-20"],
     "remediation": "Upgrade Drupal to 7.58 / 8.5.1+.",
     "desc": "Unauthenticated remote code execution via the Form API render "
             "arrays - trivially exploitable."},
    {"product": ["webmin"], "lt": "1.930", "severity": "critical",
     "title": "Webmin < 1.930 backdoor / RCE",
     "cves": ["CVE-2019-15107"], "cwe": ["CWE-78"],
     "remediation": "Upgrade Webmin to 1.930+.",
     "desc": "A malicious password_change.cgi path allows unauthenticated command "
             "injection as root."},
    {"product": ["confluence"], "severity": "critical", "advisory": True,
     "title": "Atlassian Confluence exposed - OGNL/auth-bypass RCE risk",
     "cves": ["CVE-2022-26134", "CVE-2023-22515"], "cwe": ["CWE-74", "CWE-288"],
     "remediation": "Apply current Confluence security patches; restrict exposure.",
     "desc": "Confluence has repeated pre-auth OGNL-injection and broken-access "
             "RCE bugs. Confirm exact version; unpatched = full host compromise."},
    {"product": ["phpmyadmin"], "severity": "medium", "advisory": True,
     "title": "phpMyAdmin exposed - default/weak DB creds & LFI history",
     "cves": ["CVE-2018-12613"], "cwe": ["CWE-98", "CWE-22"],
     "remediation": "Restrict phpMyAdmin by IP, require strong auth, keep updated.",
     "desc": "Exposed phpMyAdmin invites DB credential brute-force; older builds "
             "had file-inclusion RCE. Try root/(blank) and common passwords."},
    {"product": ["grafana"], "ge": "8.0.0", "lt": "8.3.1", "severity": "high",
     "title": "Grafana 8.x path traversal (arbitrary file read)",
     "cves": ["CVE-2021-43798"], "cwe": ["CWE-22"],
     "remediation": "Upgrade Grafana to 8.3.1+.",
     "desc": "Unauthenticated path traversal via plugin routes reads local files "
             "(grafana.db, /etc/passwd) - harvest secrets for lateral movement."},
    {"product": ["gitlab"], "severity": "high", "advisory": True,
     "title": "GitLab exposed - ExifTool RCE / account-takeover risk",
     "cves": ["CVE-2021-22205", "CVE-2023-7028"], "cwe": ["CWE-94", "CWE-640"],
     "remediation": "Keep GitLab patched to the latest point release.",
     "desc": "GitLab has had unauth ExifTool RCE and password-reset account "
             "takeover. Confirm version; self-managed instances are prime targets."},
    # --- VPN / edge appliances -------------------------------------------------
    {"product": ["fortinet", "fortios", "fortigate", "fortigate ssl vpn"],
     "severity": "critical", "advisory": True,
     "title": "Fortinet FortiOS SSL-VPN exposed - path traversal / auth bypass",
     "cves": ["CVE-2018-13379", "CVE-2022-40684"], "cwe": ["CWE-22", "CWE-287"],
     "remediation": "Patch FortiOS; rotate all VPN credentials after exposure.",
     "desc": "FortiOS SSL-VPN has pre-auth credential-file disclosure "
             "(CVE-2018-13379) and admin auth-bypass (CVE-2022-40684). Highly "
             "targeted; assume credential theft if unpatched."},
    {"product": ["pulse secure", "pulse connect", "pulse-secure"],
     "severity": "critical", "advisory": True,
     "title": "Pulse Connect Secure exposed - pre-auth file read (CVE-2019-11510)",
     "cves": ["CVE-2019-11510"], "cwe": ["CWE-22"],
     "remediation": "Patch Pulse Secure; rotate credentials and session secrets.",
     "desc": "Unauthenticated arbitrary file read leaks plaintext creds and "
             "session data - a mass-exploited ransomware entry point."},
    {"product": ["citrix", "netscaler"], "severity": "critical", "advisory": True,
     "title": "Citrix ADC/Gateway exposed - Shitrix / CitrixBleed risk",
     "cves": ["CVE-2019-19781", "CVE-2023-4966"], "cwe": ["CWE-22", "CWE-119"],
     "remediation": "Patch Citrix ADC/Gateway; invalidate all active sessions.",
     "desc": "Citrix ADC has pre-auth path-traversal RCE (Shitrix) and session "
             "token leak (CitrixBleed). Confirm build; heavily exploited."},
    {"product": ["palo alto", "globalprotect", "pan-os"], "severity": "critical",
     "advisory": True,
     "title": "Palo Alto GlobalProtect exposed - pre-auth RCE risk",
     "cves": ["CVE-2019-1579", "CVE-2024-3400"], "cwe": ["CWE-77", "CWE-134"],
     "remediation": "Patch PAN-OS to a fixed release; check for compromise.",
     "desc": "GlobalProtect portal has had format-string and command-injection "
             "pre-auth RCE. Confirm PAN-OS version; assume targeted."},
    # --- Legacy / cleartext / misc services ------------------------------------
    {"product": ["rsync"], "severity": "medium", "advisory": True,
     "title": "rsync daemon exposed - check for anonymous module access",
     "cves": [], "cwe": ["CWE-306"],
     "remediation": "Require auth on rsync modules; firewall 873; use SSH transport.",
     "desc": "Open rsync modules often allow anonymous read (and sometimes write) "
             "of sensitive paths - list modules with 'rsync host::'."},
    {"product": ["x11", "x window"], "severity": "high", "advisory": True,
     "title": "X11 server exposed - possible unauthenticated access",
     "cves": [], "cwe": ["CWE-284"],
     "remediation": "Disable TCP listening (-nolisten tcp); use xauth/SSH forwarding.",
     "desc": "An X11 server with access control disabled lets a remote attacker "
             "capture keystrokes and screenshots (xspy/xwd)."},
    {"product": ["rexec", "rlogin", "rshd", "rsh"], "severity": "high",
     "advisory": True,
     "title": "Berkeley r-services exposed (rsh/rlogin/rexec)",
     "cves": [], "cwe": ["CWE-306", "CWE-319"],
     "remediation": "Disable r-services; use SSH. Remove .rhosts/hosts.equiv trust.",
     "desc": "r-services use trust-based, cleartext auth and are trivially "
             "abused where host trust is configured."},
    {"product": ["telnet"], "severity": "medium", "advisory": True,
     "title": "Telnet service exposed (cleartext credentials)",
     "cves": [], "cwe": ["CWE-319"],
     "remediation": "Disable Telnet; use SSH.",
     "desc": "Telnet transmits credentials and sessions in cleartext - trivial to "
             "sniff on a shared segment."},
    {"product": ["vnc"], "severity": "medium", "advisory": True,
     "title": "VNC service exposed - check for weak/no authentication",
     "cves": [], "cwe": ["CWE-287"],
     "remediation": "Require strong VNC auth or tunnel over SSH; restrict access.",
     "desc": "VNC often uses weak 8-char-truncated passwords or none at all; "
             "confirm the auth type before assuming it's protected."},
    {"product": ["snmp"], "severity": "medium", "advisory": True,
     "title": "SNMP service exposed - check for default community strings",
     "cves": [], "cwe": ["CWE-1392"],
     "remediation": "Use SNMPv3 with auth+priv; remove public/private communities.",
     "desc": "SNMP with 'public'/'private' leaks system, interface, ARP and "
             "sometimes credential data - a rich enumeration source."},
    {"product": ["isc bind", "bind"], "lt": "9.11.0", "severity": "medium",
     "title": "Legacy ISC BIND (< 9.11) - multiple remote DoS/RCE",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Upgrade BIND to a supported branch.",
     "desc": "Old BIND has a long list of remote crash and cache-poisoning CVEs."},
    {"product": ["ntp", "ntpd"], "lt": "4.2.8", "severity": "medium",
     "title": "Legacy NTP (< 4.2.8) - amplification & remote bugs",
     "cves": ["CVE-2013-5211"], "cwe": ["CWE-406"],
     "remediation": "Upgrade ntpd to 4.2.8+; disable monlist/mode 6-7.",
     "desc": "Old ntpd supports monlist, a large DDoS-amplification and info-leak "
             "vector, plus several remote crashes."},
    {"product": ["dropbear"], "lt": "2016.72", "severity": "medium",
     "title": "Legacy Dropbear SSH (< 2016.72)",
     "cves": ["CVE-2016-7406", "CVE-2016-7407", "CVE-2016-7408"],
     "cwe": ["CWE-94"],
     "remediation": "Upgrade Dropbear (common on embedded/IoT devices).",
     "desc": "Old Dropbear has format-string and command-injection issues; "
             "usually indicates an unpatched embedded device."},
    {"product": ["iprint", "cups"], "lt": "2.0.0", "severity": "medium",
     "title": "Legacy CUPS printing service exposed",
     "cves": [], "cwe": ["CWE-1104"],
     "remediation": "Upgrade CUPS; restrict 631 to management networks.",
     "desc": "Old CUPS builds have remote bugs; recent cups-browsed issues "
             "(CVE-2024-47176 chain) make exposed printing services worth checking."},
    {"product": ["jetdirect", "hp jetdirect", "printer", "pjl"],
     "severity": "low", "advisory": True,
     "title": "Network printer exposed - PJL/PostScript filesystem access",
     "cves": [], "cwe": ["CWE-284"],
     "remediation": "Restrict printer mgmt ports (9100/631/23); set an admin PIN.",
     "desc": "Printers on 9100 often allow PJL/PostScript filesystem and NVRAM "
             "access (PRET) - credential and config disclosure."},
    {"product": ["ilo", "integrated lights-out", "idrac", "ipmi", "bmc"],
     "severity": "high", "advisory": True,
     "title": "Server management controller (iLO/iDRAC/IPMI) exposed",
     "cves": ["CVE-2017-12542"], "cwe": ["CWE-798", "CWE-306"],
     "remediation": "Isolate BMCs on a dedicated mgmt VLAN; change default creds.",
     "desc": "Lights-out controllers ship with default creds and have pre-auth "
             "bugs (iLO4 CVE-2017-12542, IPMI cipher-0/hash disclosure) that yield "
             "full out-of-band control of the host."},
    # --- Mail ------------------------------------------------------------------
    {"product": ["exim"], "lt": "4.92", "ge": "4.87", "severity": "critical",
     "title": "Exim 4.87-4.91 remote code execution",
     "cves": ["CVE-2019-10149"], "cwe": ["CWE-78"],
     "remediation": "Upgrade Exim to 4.92 or later.",
     "desc": "'Return of the WIZard' - unauthenticated RCE as root in default configs."},
    {"product": ["exim"], "lt": "4.94.2", "ge": "4.0", "severity": "high",
     "title": "Exim < 4.94.2 '21Nails' multiple vulns",
     "cves": ["CVE-2020-28017", "CVE-2020-28021"], "cwe": ["CWE-787", "CWE-190"],
     "remediation": "Upgrade Exim to 4.94.2 or later.",
     "desc": "The 21Nails cluster includes several locally- and remotely-"
             "exploitable memory-corruption bugs leading to root."},
    {"product": ["dovecot"], "lt": "2.3.15", "ge": "2.3", "severity": "medium",
     "title": "Legacy Dovecot (< 2.3.15)",
     "cves": ["CVE-2021-33515"], "cwe": ["CWE-74"],
     "remediation": "Upgrade Dovecot to 2.3.15+.",
     "desc": "STARTTLS command-injection and other issues in older Dovecot."},
    {"product": ["postfix"], "severity": "info", "advisory": True,
     "title": "SMTP server exposed - verify relay & user enumeration controls",
     "cves": [], "cwe": ["CWE-200"],
     "remediation": "Disable VRFY/EXPN; ensure no open relay; require auth to submit.",
     "desc": "Confirm the MTA does not allow open relay or VRFY/EXPN user "
             "enumeration; check for anonymous submission on 25/587."},

    # === Virtualization ========================================================
    {"product": ["vmware esxi", "vmware authentication daemon"], "severity": "critical",
     "advisory": True,
     "title": "VMware ESXi exposed - OpenSLP pre-auth RCE (ransomware target)",
     "cves": ["CVE-2021-21974", "CVE-2019-5544", "CVE-2020-3992"],
     "cwe": ["CWE-787", "CWE-416"],
     "remediation": "Patch ESXi; disable OpenSLP (427/tcp); isolate the management "
                    "network.",
     "desc": "ESXi's OpenSLP service has heap-overflow pre-auth RCE (CVE-2021-21974) - "
             "the ESXiArgs ransomware entry point. Confirm build and that 427/tcp is "
             "firewalled."},
    {"product": ["vmware vcenter", "vsphere"], "severity": "critical", "advisory": True,
     "title": "VMware vCenter exposed - unauthenticated RCE risk",
     "cves": ["CVE-2021-22005", "CVE-2021-21972", "CVE-2023-34048"],
     "cwe": ["CWE-434", "CWE-502"],
     "remediation": "Apply current vCenter patches; restrict management-plane access.",
     "desc": "vCenter has repeated pre-auth RCE (file-upload CVE-2021-22005, vSphere "
             "Client CVE-2021-21972, DCERPC CVE-2023-34048). Compromise = control of "
             "the entire virtual estate."},
    {"product": ["vmware horizon", "vmware view"], "severity": "critical",
     "advisory": True,
     "title": "VMware Horizon exposed - Log4Shell / RCE target",
     "cves": ["CVE-2021-44228"], "cwe": ["CWE-502", "CWE-917"],
     "remediation": "Patch Horizon/Log4j; hunt for prior compromise (webshells).",
     "desc": "Internet/intranet-facing Horizon was mass-exploited via Log4Shell "
             "(CVE-2021-44228). Verify Log4j remediation and scan for webshells."},

    # === Java / web middleware =================================================
    {"product": ["weblogic"], "severity": "critical", "advisory": True,
     "title": "Oracle WebLogic exposed - deserialization / unauth RCE",
     "cves": ["CVE-2020-14882", "CVE-2019-2725", "CVE-2023-21839"],
     "cwe": ["CWE-502"],
     "remediation": "Apply Oracle CPU patches; restrict the admin console and T3/IIOP.",
     "desc": "WebLogic has a long line of pre-auth RCE (console path traversal "
             "CVE-2020-14882, T3/IIOP deserialization) - a prime internal foothold."},
    {"product": ["jboss", "wildfly"], "severity": "high", "advisory": True,
     "title": "JBoss/WildFly exposed - deserialization / JMXInvoker RCE",
     "cves": ["CVE-2017-12149", "CVE-2015-7501"], "cwe": ["CWE-502"],
     "remediation": "Remove/secure JMXInvokerServlet & the admin console; patch.",
     "desc": "Legacy JBoss exposes JMXInvokerServlet/HTTPInvoker and Java "
             "deserialization gadgets leading to unauthenticated RCE."},
    {"product": ["activemq"], "severity": "critical", "advisory": True,
     "title": "Apache ActiveMQ exposed - OpenWire RCE (CVE-2023-46604)",
     "cves": ["CVE-2023-46604"], "cwe": ["CWE-502"],
     "remediation": "Upgrade ActiveMQ (5.15.16/5.16.7/5.17.6/5.18.3+); firewall 61616.",
     "desc": "The OpenWire protocol (61616) has an unauthenticated deserialization RCE "
             "mass-exploited for ransomware; also secure the 8161 web console."},
    {"product": ["coldfusion"], "severity": "critical", "advisory": True,
     "title": "Adobe ColdFusion exposed - unauthenticated RCE",
     "cves": ["CVE-2023-26360", "CVE-2023-29298", "CVE-2010-2861"],
     "cwe": ["CWE-284", "CWE-22"],
     "remediation": "Apply ColdFusion security updates; restrict the admin panel.",
     "desc": "ColdFusion has recurring pre-auth RCE and admin-panel path traversal. "
             "Confirm the exact update level."},
    {"product": ["solr"], "severity": "high", "advisory": True,
     "title": "Apache Solr exposed - Velocity template RCE",
     "cves": ["CVE-2019-17558", "CVE-2021-27905"], "cwe": ["CWE-94", "CWE-918"],
     "remediation": "Disable the Velocity response writer / params resource loading; "
                    "firewall 8983; upgrade Solr.",
     "desc": "Solr's VelocityResponseWriter allows template-injection RCE, plus SSRF in "
             "the replication handler; the admin API is usually unauthenticated."},
    {"product": ["zimbra"], "severity": "critical", "advisory": True,
     "title": "Zimbra Collaboration exposed - unauthenticated RCE",
     "cves": ["CVE-2022-27925", "CVE-2022-41352", "CVE-2019-9670"],
     "cwe": ["CWE-22", "CWE-611"],
     "remediation": "Patch Zimbra; replace vulnerable cpio/pax; hunt for webshells.",
     "desc": "Zimbra has multiple mass-exploited pre-auth RCE (mboximport traversal, "
             "cpio extraction) and XXE - a frequent full-mail-server compromise."},
    {"product": ["jetty"], "lt": "9.4.41", "ge": "9.0", "severity": "medium",
     "title": "Eclipse Jetty < 9.4.41 - path normalization info disclosure",
     "cves": ["CVE-2021-28164", "CVE-2021-28169", "CVE-2021-34429"],
     "cwe": ["CWE-22", "CWE-200"],
     "remediation": "Upgrade Jetty to 9.4.41+ (or 10.0.2+/11.0.2+).",
     "desc": "Encoded paths bypass access controls and expose WEB-INF/protected "
             "resources (config, credentials)."},

    # === Dev / CI / infrastructure exposure ====================================
    {"product": ["docker"], "severity": "critical", "advisory": True,
     "title": "Docker Engine API exposed - unauthenticated host RCE",
     "cves": [], "cwe": ["CWE-306", "CWE-284"],
     "remediation": "Never expose 2375/2376 unauthenticated; bind to localhost or "
                    "require mTLS; firewall it.",
     "desc": "An open Docker Engine API (2375/2376) lets anyone start a privileged "
             "container mounting the host filesystem - trivial root on the host."},
    {"product": ["kubernetes", "kubelet"], "severity": "high", "advisory": True,
     "title": "Kubernetes API / kubelet exposed - unauth container exec",
     "cves": [], "cwe": ["CWE-306"],
     "remediation": "Require authN/Z on the API server; disable anonymous kubelet "
                    "(10250) auth; firewall 6443/10250.",
     "desc": "An anonymous kube-apiserver (6443) or kubelet (10250) allows listing and "
             "exec-ing into pods - cluster-wide compromise."},
    {"product": ["etcd"], "severity": "high", "advisory": True,
     "title": "etcd exposed - unauthenticated cluster secrets",
     "cves": [], "cwe": ["CWE-306"],
     "remediation": "Require client-certificate auth on etcd (2379); firewall it.",
     "desc": "An open etcd store (2379) exposes all Kubernetes secrets and config - "
             "service-account tokens, credentials, the lot."},
    {"product": ["nexus"], "severity": "high", "advisory": True,
     "title": "Sonatype Nexus exposed - RCE / traversal / default creds",
     "cves": ["CVE-2024-4956", "CVE-2019-7238"], "cwe": ["CWE-22", "CWE-94", "CWE-798"],
     "remediation": "Patch Nexus; change the default admin/admin123 credentials.",
     "desc": "Nexus has unauth path traversal (CVE-2024-4956) and older unauth RCE, and "
             "ships with default admin/admin123 - repo write access is supply-chain."},
    {"product": ["teamcity"], "severity": "critical", "advisory": True,
     "title": "JetBrains TeamCity exposed - authentication-bypass RCE",
     "cves": ["CVE-2023-42793", "CVE-2024-27198"], "cwe": ["CWE-288"],
     "remediation": "Upgrade TeamCity to a fixed build; rotate tokens after exposure.",
     "desc": "TeamCity has authentication-bypass to admin/RCE - CI compromise exposes "
             "source code and deployment credentials."},
    {"product": ["sonarqube"], "severity": "medium", "advisory": True,
     "title": "SonarQube exposed - default credentials / anonymous access",
     "cves": ["CVE-2020-27986"], "cwe": ["CWE-1188", "CWE-798"],
     "remediation": "Change the default admin/admin; disable anonymous access.",
     "desc": "SonarQube ships with admin/admin and often allows anonymous project "
             "access, exposing source code and tokens."},
    {"product": ["gitea", "gogs"], "severity": "medium", "advisory": True,
     "title": "Gitea/Gogs exposed - check for RCE and weak auth",
     "cves": ["CVE-2022-30781"], "cwe": ["CWE-94", "CWE-1188"],
     "remediation": "Patch Gitea/Gogs; disable open registration; enforce strong auth.",
     "desc": "Self-hosted Git services have had template/hook RCE and often allow open "
             "registration - a route to source code and CI secrets."},

    # === Monitoring / management ===============================================
    {"product": ["zabbix"], "severity": "high", "advisory": True,
     "title": "Zabbix exposed - SAML auth bypass / default creds",
     "cves": ["CVE-2022-23131", "CVE-2022-23134"], "cwe": ["CWE-290", "CWE-287"],
     "remediation": "Patch Zabbix; change default Admin/zabbix; restrict the frontend.",
     "desc": "Zabbix has an unauth SAML session-forgery admin bypass and ships with "
             "Admin/zabbix; admin = command execution on monitored hosts."},
    {"product": ["cacti"], "severity": "critical", "advisory": True,
     "title": "Cacti exposed - unauthenticated command injection",
     "cves": ["CVE-2022-46169", "CVE-2023-39362"], "cwe": ["CWE-78", "CWE-94"],
     "remediation": "Upgrade Cacti (1.2.23+); restrict access; change default creds.",
     "desc": "Cacti has unauthenticated OS command injection (CVE-2022-46169) - direct "
             "RCE on the monitoring server."},
    {"product": ["prtg"], "severity": "high", "advisory": True,
     "title": "PRTG Network Monitor exposed - command injection / default creds",
     "cves": ["CVE-2018-9276"], "cwe": ["CWE-78", "CWE-798"],
     "remediation": "Patch PRTG; change default prtgadmin/prtgadmin; restrict access.",
     "desc": "PRTG has authenticated command injection and ships with prtgadmin/"
             "prtgadmin - notifications/sensors run commands on the host."},
    {"product": ["nagios"], "severity": "high", "advisory": True,
     "title": "Nagios exposed - multiple RCE / default creds",
     "cves": ["CVE-2018-15708", "CVE-2016-9566"], "cwe": ["CWE-78", "CWE-22"],
     "remediation": "Patch Nagios XI/Core; change default nagiosadmin; restrict access.",
     "desc": "Nagios XI/Core have a history of unauth RCE and privilege escalation, and "
             "default nagiosadmin credentials."},
    {"product": ["couchdb"], "severity": "critical", "advisory": True,
     "title": "Apache CouchDB exposed - admin bypass / Erlang cookie RCE",
     "cves": ["CVE-2022-24706", "CVE-2017-12635"], "cwe": ["CWE-306", "CWE-94"],
     "remediation": "Upgrade CouchDB (3.2.2+); set a strong Erlang cookie; require auth; "
                    "firewall 5984/4369.",
     "desc": "CouchDB had 'admin party' privilege escalation and an Erlang-distribution "
             "cookie RCE (CVE-2022-24706) reachable when the cluster port is exposed."},
    {"product": ["kibana"], "severity": "high", "advisory": True,
     "title": "Kibana exposed - Timelion prototype-pollution RCE",
     "cves": ["CVE-2019-7609"], "cwe": ["CWE-94", "CWE-306"],
     "remediation": "Upgrade Kibana; enable authentication; never expose 5601.",
     "desc": "Kibana's Timelion had a prototype-pollution RCE, and it is frequently "
             "exposed without authentication over the whole Elastic dataset."},
    {"product": ["splunk"], "severity": "medium", "advisory": True,
     "title": "Splunk exposed - check patch level and default credentials",
     "cves": ["CVE-2023-40598"], "cwe": ["CWE-78", "CWE-798"],
     "remediation": "Patch Splunk; change default admin credentials; restrict 8000/8089.",
     "desc": "Splunk Enterprise has had authenticated RCE and older default creds; the "
             "management port (8089) and web (8000) should not be broadly exposed."},

    # === Windows / AD (OS-gated advisories - verify build/patch level) ==========
    {"product": ["microsoft-ds", "netbios-ssn"], "os": "windows", "severity": "critical",
     "advisory": True,
     "title": "Windows SMB - verify SMBGhost (CVE-2020-0796)",
     "cves": ["CVE-2020-0796"], "cwe": ["CWE-787"],
     "remediation": "Patch (KB4551762); disable SMBv3.1.1 compression; block 445 "
                    "externally.",
     "desc": "SMBv3.1.1 compression pre-auth RCE affecting Windows 10 / Server "
             "1903-1909. Confirm the build/patch level - not fingerprintable from the "
             "banner alone."},
    {"product": ["microsoft-ds", "netbios-ssn"], "os": "windows", "severity": "critical",
     "advisory": True,
     "title": "Windows - verify PrintNightmare (CVE-2021-34527)",
     "cves": ["CVE-2021-34527", "CVE-2021-1675"], "cwe": ["CWE-269"],
     "remediation": "Patch; disable the Print Spooler where not needed; restrict "
                    "Point-and-Print.",
     "desc": "Print Spooler remote code execution / LPE - any unpatched Windows host "
             "with the spooler running is exploitable to SYSTEM."},
    {"product": ["microsoft-ds", "netbios-ssn"], "os": "windows", "severity": "critical",
     "advisory": True, "dc_only": True,
     "title": "Windows DC - verify ZeroLogon (CVE-2020-1472)",
     "cves": ["CVE-2020-1472"], "cwe": ["CWE-330"],
     "remediation": "Apply Aug-2020+ patches and enforce secure RPC on Netlogon.",
     "desc": "Netlogon cryptographic flaw lets an unauthenticated attacker reset a "
             "domain controller's machine password - instant domain takeover. Verify "
             "whether this host is a DC and its patch level."},
    {"product": ["wsman", "winrm"], "severity": "medium", "advisory": True,
     "title": "WinRM exposed - remote credentialed execution surface",
     "cves": [], "cwe": ["CWE-284"],
     "remediation": "Restrict WinRM (5985/5986) to management hosts; require HTTPS; "
                    "monitor for credential-based lateral movement.",
     "desc": "Exposed WinRM (5985/5986) is a primary lateral-movement channel "
             "(evil-winrm / PSRemoting) once any valid credentials are obtained."},
    {"product": ["microsoft sql server", "ms-sql"], "severity": "medium",
     "advisory": True,
     "title": "Microsoft SQL Server exposed - verify version, sa auth, xp_cmdshell",
     "cves": ["CVE-2020-0618"], "cwe": ["CWE-1104", "CWE-798"],
     "remediation": "Restrict SQL exposure; upgrade off EOL (<2016) builds; enforce "
                    "strong sa auth; disable xp_cmdshell.",
     "desc": "Network-exposed SQL Server is a prime lateral-movement/data target. "
             "Pre-2016 builds are EOL (SSRS RCE CVE-2020-0618); check for weak/blank sa "
             "credentials and enabled xp_cmdshell."},
    {"product": ["microsoft iis", "iis httpd"], "severity": "high", "advisory": True,
     "title": "IIS AppPool - SeImpersonate -> Potato LPE to SYSTEM",
     "cves": [], "cwe": ["CWE-269", "CWE-250"],
     "remediation": "Run AppPools under least-privilege identities; remove "
                    "SeImpersonatePrivilege where feasible; patch and monitor.",
     "desc": "IIS worker (AppPool) identities normally hold SeImpersonatePrivilege. "
             "Any code execution as the AppPool (webshell, upload, deserialization) "
             "escalates to SYSTEM with a current Potato - GodPotato, PrintSpoofer, "
             "SharpEfsPotato, JuicyPotatoNG - even on a fully-patched Windows 11 / "
             "Server 2016-2022. See the Priv-Esc sheet for the tools/commands."},
    {"product": ["microsoft sql server", "ms-sql"], "severity": "high", "advisory": True,
     "title": "MSSQL service account - SeImpersonate -> Potato LPE to SYSTEM",
     "cves": [], "cwe": ["CWE-269", "CWE-250"],
     "remediation": "Run SQL Server under a least-privilege (g)MSA; remove "
                    "SeImpersonate; disable xp_cmdshell.",
     "desc": "The MSSQL service account normally holds SeImpersonatePrivilege, so "
             "code execution through the database (xp_cmdshell, etc.) escalates to "
             "SYSTEM with a current Potato (GodPotato, PrintSpoofer, SharpEfsPotato) "
             "even on a fully-patched host."},

    # === Default-credential advisories =========================================
    {"product": ["grafana"], "severity": "medium", "advisory": True,
     "title": "Grafana exposed - check for default admin/admin credentials",
     "cves": [], "cwe": ["CWE-798", "CWE-1392"],
     "remediation": "Change the default admin password; disable anonymous/org signup.",
     "desc": "Grafana ships with admin/admin; dashboards and datasource credentials "
             "(often DB/cloud) are exposed if the default is unchanged."},
    {"product": ["rabbitmq"], "severity": "medium", "advisory": True,
     "title": "RabbitMQ exposed - check for default guest/guest credentials",
     "cves": [], "cwe": ["CWE-798", "CWE-1392"],
     "remediation": "Remove/disable the guest account; restrict the management UI "
                    "(15672).",
     "desc": "RabbitMQ's default guest/guest account (management UI on 15672) exposes "
             "queues and often the application credentials passing through them."},

    # === Edge / VPN / firewall appliances (heavily targeted, mass-exploited) ====
    {"product": ["ivanti", "connect secure", "pulse connect"], "severity": "critical",
     "advisory": True,
     "title": "Ivanti Connect Secure exposed - auth-bypass + command-injection chain",
     "cves": ["CVE-2023-46805", "CVE-2024-21887", "CVE-2024-21893"],
     "cwe": ["CWE-287", "CWE-77"],
     "remediation": "Patch Ivanti Connect Secure; run the Integrity Checker; rotate "
                    "all secrets and assume compromise if it was unpatched.",
     "desc": "Ivanti Connect Secure (formerly Pulse) had a mass-exploited pre-auth "
             "chain: authentication bypass (CVE-2023-46805) + command injection "
             "(CVE-2024-21887) = unauthenticated RCE, plus SSRF (CVE-2024-21893)."},
    {"product": ["sonicwall"], "severity": "critical", "advisory": True,
     "title": "SonicWall SSL-VPN / SMA exposed - access control / SQLi",
     "cves": ["CVE-2024-40766", "CVE-2021-20016", "CVE-2023-0656"],
     "cwe": ["CWE-284", "CWE-89"],
     "remediation": "Patch SonicOS/SMA; rotate VPN credentials; restrict management "
                    "exposure.",
     "desc": "SonicWall SSL-VPN has an improper-access-control flaw (CVE-2024-40766, "
             "exploited by Akira ransomware) and SMA100 pre-auth SQLi "
             "(CVE-2021-20016). Confirm firmware and assume credential theft."},
    {"product": ["big-ip", "bigip", "f5 big-ip"], "severity": "critical",
     "advisory": True,
     "title": "F5 BIG-IP exposed - TMUI / iControl REST auth-bypass RCE",
     "cves": ["CVE-2020-5902", "CVE-2022-1388", "CVE-2023-46747"],
     "cwe": ["CWE-22", "CWE-288"],
     "remediation": "Patch BIG-IP; never expose TMUI / the management interface; "
                    "restrict iControl REST.",
     "desc": "BIG-IP has pre-auth RCE via the TMUI config utility (CVE-2020-5902) and "
             "iControl REST authentication bypass (CVE-2022-1388, CVE-2023-46747) - "
             "full device compromise."},
    {"product": ["cisco asa", "cisco adaptive security", "cisco anyconnect"],
     "severity": "critical", "advisory": True,
     "title": "Cisco ASA/AnyConnect exposed - file disclosure / WebVPN RCE",
     "cves": ["CVE-2020-3452", "CVE-2018-0101", "CVE-2023-20269"],
     "cwe": ["CWE-22", "CWE-787"],
     "remediation": "Patch ASA/FTD; restrict WebVPN exposure; enforce MFA on remote "
                    "access.",
     "desc": "Cisco ASA WebVPN has unauth path-traversal file disclosure "
             "(CVE-2020-3452), historic pre-auth RCE (CVE-2018-0101), and a "
             "remote-access brute-force flaw (CVE-2023-20269)."},
    {"product": ["cisco smart install", "smart install"], "severity": "critical",
     "advisory": True,
     "title": "Cisco Smart Install exposed - unauth config theft / RCE",
     "cves": ["CVE-2018-0171"], "cwe": ["CWE-306", "CWE-863"],
     "remediation": "Disable Smart Install ('no vstack'); firewall 4786/tcp.",
     "desc": "Smart Install (4786/tcp) accepts unauthenticated commands - config "
             "download (credentials), config replacement, and RCE (CVE-2018-0171). "
             "Trivially abused with SIET."},
    {"product": ["mikrotik", "routeros", "winbox"], "severity": "high",
     "advisory": True,
     "title": "MikroTik RouterOS exposed - Winbox credential disclosure / privesc",
     "cves": ["CVE-2018-14847", "CVE-2023-30799"], "cwe": ["CWE-22", "CWE-798"],
     "remediation": "Upgrade RouterOS; restrict Winbox (8291) and the API; change "
                    "default admin credentials.",
     "desc": "Winbox (8291) path traversal (CVE-2018-14847) reads the credential DB "
             "unauthenticated; RouterOS also has admin-to-super-admin privesc "
             "(CVE-2023-30799). Router compromise enables traffic interception."},
    {"product": ["zyxel"], "severity": "critical", "advisory": True,
     "title": "Zyxel firewall/VPN exposed - unauth command injection / RCE",
     "cves": ["CVE-2022-30525", "CVE-2023-28771"], "cwe": ["CWE-77", "CWE-78"],
     "remediation": "Patch Zyxel firmware; restrict WAN management and IKE exposure.",
     "desc": "Zyxel ZyWALL/USG/ATP have unauthenticated OS command injection "
             "(CVE-2022-30525) and an unauth IKE RCE (CVE-2023-28771) - both "
             "mass-exploited into botnets."},
    {"product": ["draytek", "vigor"], "severity": "critical", "advisory": True,
     "title": "DrayTek Vigor exposed - unauthenticated RCE",
     "cves": ["CVE-2020-8515", "CVE-2024-41592"], "cwe": ["CWE-78", "CWE-120"],
     "remediation": "Patch Vigor firmware; disable remote management; restrict WAN "
                    "access.",
     "desc": "DrayTek Vigor routers have unauthenticated RCE via the web management "
             "interface (CVE-2020-8515) and buffer overflows (CVE-2024-41592)."},
    {"product": ["sophos"], "severity": "critical", "advisory": True,
     "title": "Sophos Firewall exposed - auth-bypass RCE / SQLi",
     "cves": ["CVE-2022-1040", "CVE-2020-12271"], "cwe": ["CWE-287", "CWE-89"],
     "remediation": "Patch Sophos Firewall; restrict the user/admin portal exposure.",
     "desc": "Sophos Firewall has an authentication-bypass RCE in the User Portal/"
             "Webadmin (CVE-2022-1040) and a pre-auth SQLi (CVE-2020-12271) used to "
             "steal credentials (Asnarok)."},
    {"product": ["barracuda"], "severity": "critical", "advisory": True,
     "title": "Barracuda Email Security Gateway exposed - RCE (CVE-2023-2868)",
     "cves": ["CVE-2023-2868"], "cwe": ["CWE-77"],
     "remediation": "Replace the appliance per vendor guidance (patching was deemed "
                    "insufficient); investigate for compromise.",
     "desc": "The Barracuda ESG had a remote command-injection (CVE-2023-2868) "
             "exploited for months by a state actor; the vendor advised full "
             "appliance replacement, not just patching."},
]


# nmap reports Windows as product names ("Windows 7", "Server 2008 R2") that carry
# no dotted NT kernel version, so a bare regex can't gate os_lt sigs (e.g. BlueKeep,
# os_lt 6.2). Map the common product names to their NT version as a fallback.
_WIN_NT = [
    ("2022", "10.0"), ("2019", "10.0"), ("2016", "10.0"), ("windows 11", "10.0"),
    ("windows 10", "10.0"), ("2012 r2", "6.3"), ("windows 8.1", "6.3"),
    ("2012", "6.2"), ("windows 8", "6.2"), ("2008 r2", "6.1"), ("windows 7", "6.1"),
    ("2008", "6.0"), ("vista", "6.0"), ("2003", "5.2"), ("windows xp", "5.1"),
    ("windows 2000", "5.0"),
]


def _os_version(host: Host) -> str:
    osn = (host.os_name or "")
    m = re.search(r"(\d+\.\d+)", osn)
    if m:
        return m.group(1)
    low = osn.lower()
    for name, nt in _WIN_NT:
        if name in low:
            return nt
    return ""


def _is_dc(host: Host) -> bool:
    """True if the host looks like a domain controller (role or DC-only ports)."""
    if any("domain controller" in r.lower() for r in (host.roles or [])):
        return True
    open_ids = {p.portid for p in host.open_ports}
    # Kerberos KDC (88) + LDAP (389 or Global Catalog 3268) is a DC fingerprint.
    return 88 in open_ids and bool(open_ids & {389, 3268})


def _matches(sig: dict, port: Port, host: Host) -> bool:
    blob = f"{port.product} {port.service}".lower()
    if not any(_product_in(p, blob) for p in sig["product"]):
        return False
    # OS gate (e.g. BlueKeep only on old Windows).
    if sig.get("os") and sig["os"] not in (host.os_family or host.os_name).lower():
        return False
    # DC-only gate (e.g. ZeroLogon attacks a domain controller's Netlogon).
    if sig.get("dc_only") and not _is_dc(host):
        return False
    if sig.get("os_lt"):
        osv = _os_version(host)
        if not osv or _cmp(osv, sig["os_lt"]) >= 0:
            return False
        return True   # OS-gated sig without a service version requirement
    version = _clean_version(port.version)
    if any(k in sig for k in ("eq", "lt", "le", "ge", "gt")):
        if not version:
            return False
        if "eq" in sig:
            return _cmp(version, sig["eq"]) == 0
        return _in_range(
            version,
            lo=sig.get("ge") or sig.get("gt"), hi=sig.get("le") or sig.get("lt"),
            lo_incl="ge" in sig, hi_incl="le" in sig,
        )
    # No version constraint: product-only advisory (matches any version).
    return True


def _confidence(sig: dict) -> str:
    """How sure we are the finding applies, given only version/product data."""
    if sig.get("advisory"):
        return "potential"   # product seen; version/patch not confirmed
    if sig.get("os_lt"):
        return "potential"   # OS-gated guess without a service version match
    return "likely"          # a concrete version range matched


def assess_host(host: Host) -> list[Vuln]:
    """Match every service on a host against the offline knowledge base."""
    findings: list[Vuln] = []
    # Dedup per (title, port): a product exposed on two ports is two distinct
    # exposures, so both are reported (keyed to their own port) instead of the
    # second being silently dropped and its port missing from the write-up.
    seen = {(v.title, v.port) for v in host.vulns}
    for port in host.open_ports:
        for sig in SIGNATURES:
            if not _matches(sig, port, host):
                continue
            if (sig["title"], port.portid) in seen:
                continue
            seen.add((sig["title"], port.portid))
            banner = f"{port.product} {port.version}".strip() or port.service
            conf = _confidence(sig)
            remediation = sig.get("remediation", "")
            note = ""
            # A concrete version match on a distro-packaged build is unreliable: the
            # distro often backports the fix without bumping the upstream version, so
            # the number alone can't confirm the flaw (a patched Debian vsftpd 2.3.4
            # is not the backdoored upstream tarball). Downgrade to a lead + say so.
            if conf == "likely" and _distro_packaged(port):
                conf = "potential"
                note = ("  NOTE: distro-packaged build - the fix may be backported with "
                        "the version unchanged; verify the package before relying on "
                        "this version match.")
            findings.append(Vuln(
                ip=host.ip, port=port.portid, protocol=port.protocol,
                script_id="version-db", state="version match",
                title=sig["title"],
                output=f"{banner} on {port.portid}/{port.protocol} - {sig['desc']}{note}",
                severity=sig["severity"], ids=list(sig.get("cves", [])),
                cwes=list(sig.get("cwe", [])),
                source="version-db", remediation=remediation,
                confidence=conf,
            ))
    return findings


def assess_host_inplace(host: Host) -> int:
    new = assess_host(host)
    host.vulns.extend(new)
    return len(new)


def signature_count() -> int:
    return len(SIGNATURES)
