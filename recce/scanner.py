"""Scan orchestration.

Wraps nmap (and optionally masscan) via subprocess. The workflow is:

  1. discovery   - find live hosts across all subnets (skippable with -Pn mindset)
  2. full ports  - full TCP port sweep per live host (nmap -p- or masscan)
  3. deep enum   - -sV -sC (-O) plus vuln / AD NSE scripts on discovered open ports

Each phase writes nmap XML to the run's raw/ directory; the parser consumes it.
No scanning happens on import - callers drive the phases explicitly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class ScanProfile:
    """Tunable knobs for a scan run."""

    name: str = "standard"
    all_ports: bool = True            # full 65535 TCP sweep vs --top-ports
    top_ports: int = 1000
    min_rate: int = 1500              # packets/sec hint for nmap
    timing: int = 4                   # nmap -T
    os_detect: bool = True
    ad_enrich: bool = True            # SMB / LDAP NSE scripts (enum phase)
    deep_enum: bool = True            # service-aware deep enum scripts (enum phase)
    udp_top: int = 0                  # >0 -> also scan N top UDP ports (vulns phase)
    udp_basic: bool = True            # enum phase: sweep a curated set of high-value
                                      # UDP ports (DNS/SNMP/NTP/IKE/TFTP/NetBIOS/...) so
                                      # UDP services aren't missed by the TCP-only sweep
                                      # (needs root; skipped with a warning otherwise)
    ping_discovery: bool = True       # discovery; False => treat all as up (-Pn)
    assume_up: bool = False           # -Pn / discovery fell back: scanning dead IPs
                                      # too, so fail faster on non-responders
    offline: bool = False             # drop internet-dependent scripts (vulners)
    extra_nse: list[str] = field(default_factory=list)
    scanner: str = "nmap"             # nmap | masscan (masscan for the port sweep)
    host_timeout: int = 20            # minutes; per-host ceiling (nmap --host-timeout)
    version_intensity: int = 8        # -sV probe intensity 0-9 (higher = better ID)
    version_all: bool = False         # --version-all: try every probe (thorough)
    reliable: bool = False            # rate-limited/lossy net: no --min-rate floor,
                                      # more retries, let nmap's congestion control
                                      # adapt (auto-enabled when probe drops seen)
    max_retries: int = 3              # nmap --max-retries on the port sweep. 3 (not
                                      # nmap's 1-2 fast default) so a single dropped
                                      # SYN doesn't silently lose an open port
    verify: bool = True               # re-scan a host that came back with 0 ports to
                                      # confirm it's really empty vs a missed sweep
    verify_all: bool = False          # also verify 0-port hosts under -Pn (not just
                                      # discovered-live ones) - slower on dead-IP scopes
    udp_fallback: bool = True         # for a -Pn host still silent after the TCP
                                      # sweep+verify, send a UDP ping to common
                                      # services: a reply / ICMP-unreach proves it's
                                      # up, so a firewalled host isn't ruled dead
    reconfirm: bool = True            # after a PARTIAL ping sweep, re-probe the hosts
                                      # that DIDN'T answer with a fast -Pn top-ports
                                      # scan: any open port proves the host is up, so a
                                      # firewalled-but-alive box isn't written off down
    reconfirm_cap: int = 1024         # skip that re-probe when more than this many
                                      # hosts missed discovery (huge scope -> use -Pn)


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", all_ports=False, top_ports=200,
                         os_detect=False, min_rate=2000, host_timeout=10,
                         version_intensity=6, deep_enum=False),
    "standard": ScanProfile(name="standard"),
    "thorough": ScanProfile(name="thorough", min_rate=800, udp_top=100,
                            extra_nse=["banner"], host_timeout=40,
                            version_all=True),
}


@dataclass
class ScanIssue:
    """A scan that errored or didn't fully complete - surfaced to the operator."""

    level: str        # "error" (nothing usable) | "warning" (partial results)
    message: str
    kind: str = ""    # classifier, e.g. "host-timeout" (scan truncated -> port
                      # list is partial); "" = unclassified


@dataclass
class RunOutcome:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False    # subprocess hard timeout (nmap itself hung)
    missing: bool = False      # the tool wasn't on PATH

# AD / Windows enrichment scripts (safe, non-intrusive category).
_AD_SCRIPTS = [
    "smb-os-discovery", "smb-security-mode", "smb2-security-mode",
    "smb-enum-shares", "smb-enum-users", "smb-enum-domains",
    "smb-enum-groups", "smb-enum-sessions", "smb-protocols", "smb2-time",
    "ldap-rootdse", "ldap-search", "rdp-ntlm-info", "krb5-enum-users",
    "nbstat", "msrpc-enum",
]

# --- service-aware NSE scripts ------------------------------------------------
# nmap only runs scripts whose portrule matches the detected service, so listing
# many is cheap (non-matching ones are skipped). Every name is a standard,
# long-shipping nmap script - an unknown name would abort the scan, so the lists
# are curated. Two lists, both applied automatically (no flags to remember):
#
#   _ENUM_SCRIPTS   deep, non-intrusive service enumeration
#   _VULN_DETECT    high-value vuln DETECTION that nmap does NOT tag "safe"
#                   (ms17-010, heartbleed, shellshock, vsftpd backdoor...) - the
#                   bare "vuln and safe" category MISSES these, so recce always
#                   layers them in. `--aggressive` still adds the full intrusive
#                   `vuln` category (XSS/SQLi/DoS probes) on top.

_ENUM_SCRIPTS = [
    # HTTP / web
    "http-title", "http-headers", "http-server-header", "http-methods",
    "http-enum", "http-robots.txt", "http-webdav-scan", "http-auth",
    "http-cors", "http-git", "http-open-proxy", "http-generator",
    "http-php-version", "http-favicon", "http-ntlm-info", "http-cookie-flags",
    "http-apache-server-status", "http-userdir-enum", "http-vhosts",
    "http-devframework", "http-wordpress-enum", "http-config-backup",
    "http-internal-ip-disclosure", "http-comments-displayer",
    # TLS / SSL
    "ssl-cert", "ssl-enum-ciphers", "tls-nextprotoneg", "ssl-known-key",
    "ssl-date", "tls-alpn",
    # SSH
    "ssh2-enum-algos", "ssh-auth-methods", "ssh-hostkey",
    # FTP / mail
    "ftp-anon", "ftp-syst", "ftp-bounce", "smtp-commands", "smtp-open-relay",
    "smtp-ntlm-info", "smtp-enum-users", "pop3-capabilities", "pop3-ntlm-info",
    "imap-capabilities", "imap-ntlm-info",
    # DNS
    "dns-nsid", "dns-recursion", "dns-zone-transfer", "dns-service-discovery",
    # Databases
    "mysql-info", "mysql-databases", "mysql-users", "mysql-variables",
    "mysql-empty-password", "ms-sql-info", "ms-sql-ntlm-info", "ms-sql-config",
    "ms-sql-empty-password", "oracle-tns-version", "mongodb-info",
    "mongodb-databases", "redis-info", "cassandra-info", "couchdb-stats",
    "memcached-info",
    # SNMP
    "snmp-info", "snmp-interfaces", "snmp-sysdescr", "snmp-netstat",
    "snmp-processes", "snmp-win32-services", "snmp-win32-software",
    "snmp-win32-users",
    # Remote access
    "rdp-enum-encryption", "rdp-ntlm-info", "vnc-info", "vnc-title",
    "telnet-encryption", "telnet-ntlm-info", "x11-access",
    # SMB extras (beyond the AD set)
    "smb-mbenum", "smb-enum-services", "smb2-capabilities", "smb-system-info",
    # Files / infra / misc
    "nfs-showmount", "nfs-ls", "nfs-statfs", "rpcinfo", "finger", "ntp-info",
    "ike-version", "ipmi-version", "upnp-info", "rsync-list-modules",
    "afp-serverinfo", "afp-showmount", "sip-methods", "amqp-info", "epmd-info",
]

_VULN_DETECT = [
    # SMB / Windows (detection only - does not exploit)
    "smb-vuln-ms17-010", "smb-double-pulsar-backdoor", "smb-vuln-cve-2017-7494",
    # TLS / crypto
    "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection", "ssl-dh-params",
    "sslv2-drown",
    # HTTP CVE checks (read-only)
    "http-shellshock", "http-vuln-cve2011-3192", "http-vuln-cve2010-2861",
    "http-vuln-cve2013-0156", "http-vuln-cve2014-3704", "http-vuln-cve2015-1635",
    "http-vuln-cve2017-5638", "http-vuln-cve2017-1001000",
    "http-vuln-misfortune-cookie",
    # Services
    "ftp-vsftpd-backdoor", "ftp-proftpd-backdoor", "ftp-vuln-cve2010-4221",
    "distcc-cve2004-2687", "rmi-vuln-classloader", "clamav-exec",
    "mysql-vuln-cve2012-2122", "smtp-vuln-cve2010-4344", "smtp-vuln-cve2011-1720",
    "smtp-vuln-cve2011-1764",
]


class ScannerError(RuntimeError):
    pass


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _proxied() -> bool:
    from . import proxy
    return proxy.is_active()


def _scan_type() -> str:
    """SYN scan when we can, EXCEPT through a proxy: a SYN scan uses raw packets that
    bypass proxychains and would fire from the operator's real IP. A TCP connect scan
    (-sT) goes through libc connect(), so the proxy tunnels it. This is the OPSEC
    linchpin of proxy mode - force -sT whenever proxied, regardless of root."""
    if _proxied():
        return "-sT"
    return "-sS" if _is_root() else "-sT"


def harden_for_proxy(profile: ScanProfile) -> ScanProfile:
    """Mutate a profile in place for proxy-safe scanning. proxychains only tunnels TCP
    connect(); masscan's raw engine and every UDP/ICMP path bypass it (leaking the real
    IP and/or missing findings). So through a proxy: force the nmap connect scanner, drop
    all UDP, and skip ICMP host-discovery (-Pn is already used). The dropped UDP services
    (SNMP etc.) are surfaced honestly by their own modules - never a silent zero."""
    if not _proxied():
        return profile
    profile.scanner = "nmap"          # masscan is raw-packet -> can't be proxied at all
    profile.udp_basic = False         # UDP can't traverse a TCP proxy...
    profile.udp_top = 0
    profile.udp_fallback = False
    profile.ping_discovery = False    # ICMP/UDP pings bypass the proxy -> -Pn instead
    profile.assume_up = True          # under -Pn, treat targets as up (fail fast on dead)
    if profile.host_timeout:          # a connect scan through a pivot is much slower -
        profile.host_timeout *= 2     # give each host longer before nmap abandons it
    return profile


def check_environment(profile: ScanProfile) -> list[str]:
    """Return a list of human-readable warnings about the runtime environment."""
    warnings: list[str] = []
    if not _have("nmap"):
        raise ScannerError("nmap is required but was not found on PATH. Install nmap.")
    if not _is_root():
        warnings.append(
            "Not running as root: falling back to TCP connect scan (-sT); "
            "OS detection and SYN scan need root/CAP_NET_RAW."
        )
    if profile.scanner == "masscan" and not _have("masscan"):
        warnings.append("masscan requested but not found; using nmap for port sweep.")
        profile.scanner = "nmap"
    return warnings


def _run(cmd: list[str], timeout: int | None = None) -> RunOutcome:
    """Run a command, capturing output. Never raises - returns a RunOutcome the
    caller inspects, so one bad host can't stall or crash a run. `errors=replace`
    keeps a non-UTF-8 service banner from raising UnicodeDecodeError mid-scan."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return RunOutcome(p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired as e:
        so = e.stdout or ""
        se = e.stderr or ""
        return RunOutcome(returncode=124,
                          stdout=so.decode("utf-8", "replace") if isinstance(so, bytes) else so,
                          stderr=se.decode("utf-8", "replace") if isinstance(se, bytes) else se,
                          timed_out=True)
    except FileNotFoundError:
        return RunOutcome(returncode=127, missing=True)
    except (OSError, ValueError) as e:
        # PermissionError, E2BIG (arg list too long), decode error, etc. - treat
        # as a failed run rather than crashing the whole phase.
        return RunOutcome(returncode=126, stderr=str(e))


def _timeout_args(profile: ScanProfile, minutes: int | None = None):
    """Return (nmap --host-timeout args, subprocess-kill-timeout seconds).

    The nmap host-timeout fires first and lets nmap skip the slow host and still
    write its XML; the subprocess timeout is a hard backstop for a truly hung
    nmap. 0/None disables both."""
    m = profile.host_timeout if minutes is None else minutes
    if not m or m <= 0:
        return [], None
    return ["--host-timeout", f"{m}m"], m * 60 + 120


def _version_args(profile: ScanProfile) -> list[str]:
    """Service-detection flags. --version-all (intensity 9, every probe) when the
    profile asks for it, else an explicit intensity."""
    if profile.version_all:
        return ["-sV", "--version-all"]
    return ["-sV", "--version-intensity", str(profile.version_intensity)]


def _issue_from(outcome: RunOutcome, out_xml: str, phase: str,
                minutes: int | None) -> ScanIssue | None:
    """Classify a run's outcome into an operator-facing issue, or None if fine."""
    if outcome.missing:
        return ScanIssue("error", f"{phase}: nmap not found on PATH")
    if outcome.timed_out:
        return ScanIssue("error",
                         f"{phase}: hard-timed-out (nmap unresponsive); results "
                         f"may be missing", kind="host-timeout")
    blob = f"{outcome.stdout}\n{outcome.stderr}".lower()
    if "host timeout" in blob or "due to host timeout" in blob:
        span = f" after {minutes}m" if minutes else ""
        return ScanIssue("warning",
                         f"{phase}: host timed out{span} - partial results kept "
                         "(port list is INCOMPLETE; raise --host-timeout or narrow "
                         "scope with --top-ports)", kind="host-timeout")
    if outcome.returncode not in (0, None) and (
            not os.path.exists(out_xml) or os.path.getsize(out_xml) < 80):
        err = (outcome.stderr or outcome.stdout or "").strip().splitlines()
        detail = err[-1] if err else f"exit {outcome.returncode}"
        return ScanIssue("error", f"{phase}: nmap failed ({detail})")
    return None


# --- phase 1: discovery ----------------------------------------------------------

def discover_hosts(targets_file: str, out_xml: str) -> tuple[str, ScanIssue | None]:
    """Ping-sweep the targets; return (xml path, issue|None) listing live hosts."""
    cmd = [
        "nmap", "-sn", "-PE", "-PP",
        # SYN-ping a broad port set - incl. the ports firewalled Windows/AD hosts most
        # often still answer (88 Kerberos, 389 LDAP, 5985 WinRM) so they aren't ruled
        # down. --max-retries 2 (not 1) so a single dropped probe doesn't lose a host.
        "-PS21,22,23,25,53,80,88,110,135,139,143,389,443,445,993,995,1433,3306,3389,5985,8080",
        "-PA80,443,3389", "-n", "--max-retries", "2", "--host-timeout", "3m",
        "-iL", targets_file, "-oX", out_xml,
    ]
    # nmap's --host-timeout bounds each host, but add a wall-clock backstop scaled
    # by scope size so a wedged sweep can't hang the first phase forever.
    try:
        with open(targets_file) as fh:
            ntargets = sum(1 for ln in fh if ln.strip())
    except OSError:
        ntargets = 256
    kill = int(min(7200, max(600, ntargets * 0.5 + 300)))
    outcome = _run(cmd, timeout=kill)
    if outcome.missing:
        return out_xml, ScanIssue("error", "discovery: nmap not found on PATH")
    if outcome.returncode not in (0, None) and not os.path.exists(out_xml):
        detail = (outcome.stderr or "").strip().splitlines()
        return out_xml, ScanIssue(
            "error", f"discovery: nmap failed ({detail[-1] if detail else 'error'})")
    return out_xml, _issue_from(outcome, out_xml, "discovery", None)


# --- phase 2: full port sweep ----------------------------------------------------

# nmap runtime warnings that mean it's dropping probes / backing off - i.e. the
# network is rate-limiting or lossy, so a fast pass under-reports open ports.
_DROP_MARKERS = ("increasing send delay", "dropped probes", "giving up on port",
                 "packet drop", "successful_tryno")


def _congested(outcome: RunOutcome) -> bool:
    blob = f"{outcome.stdout}\n{outcome.stderr}".lower()
    return any(m in blob for m in _DROP_MARKERS)


def port_scope_label(profile: ScanProfile) -> tuple[str, bool]:
    """(human label, is_full) for the TCP port scope this profile scans. `is_full`
    is False for a top-N scan, so callers can loudly flag a PARTIAL sweep."""
    if profile.all_ports:
        return "all 65535 TCP ports", True
    return f"top {profile.top_ports} TCP ports", False


def _portscan_cmd(ip: str, out_xml: str, profile: ScanProfile,
                  reliable: bool) -> tuple[list, int | None]:
    scan_type = _scan_type()
    port_spec = ["-p-"] if profile.all_ports else ["--top-ports", str(profile.top_ports)]
    if reliable:
        # Mirror what a manual nmap does on a rate-limiting / lossy network: let
        # congestion control adapt - NO --min-rate floor (it would pin the send
        # rate above what the network tolerates and guarantee dropped SYNs to
        # open ports), normal -T3 timing, and retry dropped probes generously.
        # Crucially this stays bounded by the SAME --host-timeout as any host:
        # nmap abandons the host when it fires and writes what it found, so an
        # adaptive scan can never run for hours/days - it just returns partial
        # (still far better than the fast pass's zero). Raise --host-timeout for
        # more completeness, or set a gentler --min-rate floor to bound it more.
        to_args, kill = _timeout_args(profile)
        cmd = ["nmap", scan_type, "-Pn", "-n", "-T3", "--max-retries", "6", "--open",
               *to_args, *port_spec, ip, "-oX", out_xml]
    else:
        to_args, kill = _timeout_args(profile)
        # A dropped SYN with too few retries silently loses an open port, so retry
        # enough to survive minor loss (default 3, not nmap's fast 1-2). Dead -Pn
        # IPs are still bounded by --host-timeout, and a 0-port host gets a
        # verification re-scan, so completeness no longer hinges on this alone.
        cmd = ["nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
               "--min-rate", str(profile.min_rate),
               "--max-retries", str(profile.max_retries), "--open",
               *to_args, *port_spec, ip, "-oX", out_xml]
    return cmd, kill


def full_port_scan(ip: str, out_xml: str,
                   profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Full/top TCP port sweep for one host; returns (xml path, issue|None).

    If the fast pass trips nmap's congestion control (it starts dropping probes
    on a rate-limiting network), the port list is unreliable - so we re-scan the
    host letting nmap adapt (no --min-rate, more retries), which is what actually
    finds the ports. `--reliable` forces that mode from the first pass.
    """
    if profile.scanner == "masscan" and _have("masscan") and not _proxied():
        return _masscan_ports(ip, out_xml, profile)

    reliable = profile.reliable
    cmd, kill = _portscan_cmd(ip, out_xml, profile, reliable)
    outcome = _run(cmd, timeout=kill)
    if not reliable and _congested(outcome):
        cmd, kill = _portscan_cmd(ip, out_xml, profile, reliable=True)
        outcome = _run(cmd, timeout=kill)
        return out_xml, _issue_from(outcome, out_xml, "port-sweep", profile.host_timeout) \
            or ScanIssue("warning", "port-sweep: network rate-limiting detected "
                         "(dropped probes); re-scanned this host with congestion-"
                         "adaptive timing (no --min-rate, more retries). If ports "
                         "still look low, raise --host-timeout or pass --reliable.")
    return out_xml, _issue_from(outcome, out_xml, "port-sweep", profile.host_timeout)


def verify_port_scan(ip: str, out_xml: str,
                     profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Independent confirmation sweep for a host the fast pass found 0 ports on -
    always congestion-adaptive (no --min-rate floor, more retries), so it catches
    ports a fast/lossy first pass dropped. Bounded by the same --host-timeout."""
    cmd, kill = _portscan_cmd(ip, out_xml, profile, reliable=True)
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "verify", profile.host_timeout)


# Common UDP services that answer even when TCP and ICMP are firewalled off. A ping
# to any of them elicits a service reply OR an ICMP port-unreachable - either one
# proves the host is up. Kept small so the probe stays fast against dead IPs.
_UDP_PING_PORTS = "53,67,123,137,138,161,500,514,520,623,1900,4500,5353"


def udp_liveness_probe(ip: str, out_xml: str,
                       profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Last-resort liveness check for a host that answered NOTHING on TCP under -Pn.

    Under -Pn a silent host is genuinely ambiguous: it could be dead, or a live host
    behind a default-drop firewall that only silences TCP+ICMP. A UDP ping to common
    services (DNS/DHCP/NTP/NetBIOS/SNMP/IKE/Syslog/RIP/IPMI/SSDP/mDNS) catches the
    firewalled-but-alive case - a service reply or an ICMP port-unreachable both come
    back with a real nmap status reason (never the -Pn "user-set"), so the host flips
    from UNKNOWN to confirmed-up instead of being written off as down.

    Uses `-sn` (no -Pn) so nmap's up/down verdict is meaningful again: it reports the
    host up ONLY on an actual reply. Needs root (raw UDP); returns a skip issue if not.
    """
    if _proxied():
        return _empty_xml(out_xml), ScanIssue(
            "warning", "udp-liveness: skipped - UDP can't traverse the proxy (a UDP ping "
            "would leak from the real IP). Firewalled hosts may read as down under -Pn.")
    if not _is_root():
        return _empty_xml(out_xml), ScanIssue(
            "warning", "udp-liveness: skipped (needs root/CAP_NET_RAW for UDP ping)")
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", "-sn", "-n", "-PU" + _UDP_PING_PORTS,
                    f"-T{profile.timing}", "--max-retries", "2", *to_args,
                    ip, "-oX", out_xml], timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "udp-liveness", profile.host_timeout)


def reconfirm_hosts(targets_file: str, out_xml: str,
                    profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Re-probe hosts that MISSED the ping sweep with a fast -Pn top-ports scan.

    A ping sweep (even the broad one above) can miss a live host behind a default-drop
    firewall that silences ICMP *and* every ping port. An actual TCP port scan is a
    stronger liveness test: a host that answers on ANY port is definitively up. This
    catches the firewalled-but-alive box before it's written off as down - without
    full-scanning every dead IP (top 100 ports, --open, fail-fast, one bounded sweep
    over all the missed IPs). Callers cap the input size (profile.reconfirm_cap)."""
    scan_type = _scan_type()
    cmd = ["nmap", scan_type, "-Pn", "-n", "--open", "--top-ports", "100",
           f"-T{profile.timing}", "--max-retries", "2", "--host-timeout", "2m",
           "-iL", targets_file, "-oX", out_xml]
    try:
        with open(targets_file) as fh:
            ntargets = sum(1 for ln in fh if ln.strip())
    except OSError:
        ntargets = 256
    kill = int(min(5400, max(300, ntargets * 1.5 + 180)))
    outcome = _run(cmd, timeout=kill)
    if outcome.missing:
        return out_xml, ScanIssue("error", "reconfirm: nmap not found on PATH")
    return out_xml, _issue_from(outcome, out_xml, "reconfirm", None)


def _masscan_ports(ip: str, out_xml: str,
                   profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    port_range = "0-65535" if profile.all_ports else f"0-{profile.top_ports}"
    tmp = out_xml + ".masscan.xml"
    _run(["masscan", ip, "-p", port_range, "--rate", str(profile.min_rate * 10),
          "-oX", tmp], timeout=(profile.host_timeout * 60 + 120) or None)
    # Re-emit as an nmap-shaped XML by re-scanning just the open ports with nmap.
    ports = _extract_masscan_ports(tmp)
    try:                                      # clean up the intermediate masscan XML
        os.unlink(tmp)
    except OSError:
        pass
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = _scan_type()
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", scan_type, "-Pn", "-n", "--open", *to_args,
                    "-p", ",".join(str(p) for p in ports), ip, "-oX", out_xml],
                   timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "port-sweep", profile.host_timeout)


def masscan_sweep(ips: list[str], out_xml: str, profile: ScanProfile) -> dict[str, list[int]]:
    """Fast network-wide port sweep of many hosts in a single masscan run.

    Returns {ip: [open_ports]}. This collapses per-host full scans into one
    high-rate sweep - the biggest single speedup for large scopes. Falls back to
    an empty map (caller then uses nmap) if masscan is unavailable.
    """
    if not _have("masscan"):
        return {}
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(ips))
        list_file = tf.name
    port_range = "0-65535" if profile.all_ports else f"0-{profile.top_ports}"
    # masscan rate is packets/sec across the whole sweep; scale up from min_rate.
    rate = max(profile.min_rate * 10, 5000)
    # Hard backstop so a wedged masscan (bad rate, no raw-socket perms, odd iface)
    # can't hang the whole run: estimate the work and give it 2x + slack, capped 1h.
    nports = 65536 if profile.all_ports else (profile.top_ports + 1)
    est = nports * max(1, len(ips)) / max(rate, 1)
    kill = int(min(3600, max(600, est * 2 + 120)))
    outcome = _run(["masscan", "-iL", list_file, "-p", port_range,
                    "--rate", str(rate), "-oX", out_xml], timeout=kill)
    try:
        os.unlink(list_file)
    except OSError:
        pass
    # A timed-out / errored sweep leaves a PARTIAL XML - hosts it never reached would
    # silently vanish. Warn loudly so the operator re-runs (per-host nmap, or -Pn).
    if outcome.timed_out or (outcome.returncode not in (0, None) and not outcome.missing):
        print("[!] masscan sweep did not finish cleanly (timeout/error) - results may be "
              "PARTIAL; hosts it didn't reach are missing. Re-run without --fast, or with "
              "-Pn, to be sure.")
    return parse_masscan_sweep_xml(out_xml)


def parse_masscan_sweep_xml(out_xml: str) -> dict[str, list[int]]:
    """Parse a masscan XML file into {ip: [sorted open ports]}."""
    result: dict[str, list[int]] = {}
    if not os.path.exists(out_xml):
        return result
    try:
        tree = ET.parse(out_xml)
    except ET.ParseError:
        return result
    for host in tree.getroot().findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None
        if not ip:
            continue
        for port in host.iter("port"):
            try:
                result.setdefault(ip, []).append(int(port.get("portid")))
            except (TypeError, ValueError):
                continue
    for ip in result:
        result[ip] = sorted(set(result[ip]))
    return result


def _extract_masscan_ports(path: str) -> list[int]:
    if not os.path.exists(path):
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    ports = []
    for port in tree.getroot().iter("port"):
        try:
            ports.append(int(port.get("portid")))
        except (TypeError, ValueError):
            continue
    return sorted(set(ports))


# --- phase 3a: light service enumeration (feeds the sheet fast) ------------------

def _empty_xml(out_xml: str) -> str:
    with open(out_xml, "w") as fh:
        fh.write('<?xml version="1.0"?><nmaprun start="0"></nmaprun>')
    return out_xml


def _creds_args(creds: dict | None) -> list[str]:
    if not (creds and creds.get("username")):
        return []
    args = [f"smbusername={creds['username']}", f"smbpassword={creds.get('password', '')}"]
    if creds.get("domain"):
        args.append(f"smbdomain={creds['domain']}")
    args += [f"ldap.username={creds['username']}", f"ldap.password={creds.get('password', '')}"]
    return ["--script-args", ",".join(args)]


def enum_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
              creds: dict | None = None) -> tuple[str, ScanIssue | None]:
    """Light pass: version/OS detection + safe default scripts + AD facts.

    Deliberately cheap so the spreadsheet populates fast. This is where accurate
    service detection happens (it feeds the offline vuln DB), so version probing
    is turned up here. No vuln scanning here - that is the separate vuln_scan().
    """
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = _scan_type()
    scripts = ["default"]                 # safe, gives http-title, ssl-cert, etc.
    if profile.ad_enrich:
        scripts += _AD_SCRIPTS            # smb-os-discovery, signing, ldap-rootdse
    if profile.deep_enum:
        scripts += _ENUM_SCRIPTS          # deep service-aware enumeration
    scripts += profile.extra_nse
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        *_version_args(profile),          # thorough service ID (feeds vuln DB)
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", ",".join(dict.fromkeys(scripts)),
        "--script-timeout", "120s", *to_args,
    ]
    cmd += _creds_args(creds)
    if profile.os_detect and _is_root():
        cmd.append("-O")
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "enum", profile.host_timeout)


# --- phase 3b: vulnerability scan (targeted, safe-by-default) --------------------

_ENUM_SCRIPTS_SET = frozenset(_ENUM_SCRIPTS)


def enum_scripts_present(host) -> bool:
    """True if the deep service-enum NSE scripts already ran on this host (their output is
    stored on its ports) - so the vuln pass can skip re-running the ~90-script set with NO
    coverage loss (the same scripts would re-match the same ports and find nothing new).
    Fail-safe: if none are present, they run, so coverage can never be lost."""
    for p in getattr(host, "ports", []) or []:
        for s in (p.scripts or []):
            if s.id in _ENUM_SCRIPTS_SET:
                return True
    return False


def vuln_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
              creds: dict | None = None, aggressive: bool = False,
              fast: bool = False, skip_enum_scripts: bool = False) -> tuple[str, ScanIssue | None]:
    """Per-open-port vulnerability pass.

    Safe by default, but deeper than the raw `vuln and safe` category: many
    high-value detection scripts (ms17-010, heartbleed, shellshock, vsftpd
    backdoor...) are tagged `vuln` but NOT `safe`, so the bare safe category
    misses them. recce always layers in the curated `_VULN_DETECT` set of
    non-destructive checks plus the deep service-enum scripts, with no flags to
    remember. `aggressive=True` adds the full intrusive `vuln` category
    (XSS/SQLi/DoS probes) and, if online, the `vulners` CVE lookup.

    `fast=True` is the opposite end: run ONLY the curated `_VULN_DETECT`
    top-signal checks - no broad `(vuln and safe)` category, no deep service
    enum - so a whole /24 finishes quickly when you just want the high-value
    hits. (`fast` and `aggressive` are mutually exclusive; aggressive wins.)
    """
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = _scan_type()

    # nmap --script grammar: a comma-separated list where each item is a boolean
    # category expression OR a script name (each name portrule-filtered by nmap).
    # The deep service-enum scripts run in the ENUM phase; when they already ran on this
    # host (skip_enum_scripts), the vuln pass drops the ~90-script set - it would only
    # re-match the same ports and find nothing new - keeping just the vuln DETECTORS. This
    # roughly halves the vuln pass's NSE work with zero coverage loss.
    _enum = [] if skip_enum_scripts else _ENUM_SCRIPTS
    if aggressive:
        selection = "(vuln or vulners)" if not profile.offline else "(vuln)"
        named = _enum + _VULN_DETECT
    elif fast:
        selection = None                 # skip the broad category net entirely
        named = _VULN_DETECT             # top-signal detection scripts only
    else:
        selection = "(vuln and safe)"    # broad safe net...
        named = _enum + _VULN_DETECT     # ...always plus the misses it leaves
    parts = ([selection] if selection else []) + list(dict.fromkeys(named))
    script_expr = ",".join(parts)

    # enum already did the heavy -sV; here we only need service names for NSE
    # portrules, so a light version probe (not a full re-scan) is enough.
    to_args, kill = _timeout_args(profile, profile.host_timeout * 2 if aggressive
                                  else None)
    script_to = "90s" if fast else "180s"
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "-sV", "--version-light",
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", script_expr,
        "--script-timeout", script_to, *to_args,
    ]
    cmd += _creds_args(creds)
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "vuln-scan", profile.host_timeout)


def nse_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
             scripts: list[str], creds: dict | None = None) -> tuple[str, ScanIssue | None]:
    """Generic targeted NSE run on specific ports (used by db / privesc phases)."""
    if not ports or not scripts:
        return _empty_xml(out_xml), None
    scan_type = _scan_type()
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "-sV", "--version-light",
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", ",".join(dict.fromkeys(scripts)),
        "--script-timeout", "180s", *to_args,
    ]
    cmd += _creds_args(creds)
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "nse", profile.host_timeout)


def reprobe_services(ip: str, ports: list[int], out_xml: str,
                     profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Second-opinion service ID on a few still-unknown ports: max-effort `-sV
    --version-all` (intensity 9, every probe) aimed at just those ports. Focused,
    so it's cheap even though --version-all is exhaustive - the first enum pass
    ran under a whole-host budget, this one spends it on the handful nmap couldn't
    name. Returns the XML path + any scan issue."""
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = _scan_type()
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "-sV", "--version-all",
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        *to_args, ip, "-oX", out_xml,
    ]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "reprobe", profile.host_timeout)


# High-value UDP services a TCP-only sweep misses. Kept small so the enum-phase sweep
# stays fast: DNS, DHCP, TFTP, NTP, NetBIOS, SNMP(+trap), IKE/VPN, syslog, RIP, IPMI,
# MSSQL browser, SIP, SSDP/UPnP, IPsec NAT-T, mDNS.
_UDP_BASIC_PORTS = "53,67,69,123,137,138,161,162,500,514,520,623,1434,1900,4500,5060,5353"


def udp_basic_scan(ip: str, out_xml: str, profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Enum-phase sweep of a curated set of high-value UDP ports with service detection
    and the cheap SNMP/DNS/NTP/NetBIOS/IKE scripts, so UDP services show up in the main
    enumeration instead of only under `thorough`. Needs root (raw UDP)."""
    if not _is_root():
        return _empty_xml(out_xml), ScanIssue(
            "warning", "udp-basic: skipped (needs root/CAP_NET_RAW for raw UDP); "
            "run with sudo, or use --udp-top in the vulns phase")
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", "-sU", "-sV", "-Pn", "-n", "-p", _UDP_BASIC_PORTS, "--open",
                    f"-T{profile.timing}",
                    "--script", "snmp-info,dns-nsid,ntp-info,nbstat,ike-version",
                    "--script-timeout", "60s", *to_args, ip, "-oX", out_xml],
                   timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "udp-basic", profile.host_timeout)


def udp_scan(ip: str, out_xml: str, profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Optional top-N UDP scan with service detection + SNMP/DNS/NTP enumeration."""
    if not _is_root():
        return _empty_xml(out_xml), ScanIssue(
            "warning", "udp: skipped (needs root/CAP_NET_RAW for raw sockets)")
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", "-sU", "-sV", "-Pn", "-n", "--top-ports",
                    str(profile.udp_top), "--open", f"-T{profile.timing}",
                    "--script", "snmp-info,snmp-interfaces,snmp-sysdescr,dns-nsid,"
                                "ntp-info,nbstat,ike-version",
                    "--script-timeout", "90s", *to_args, ip, "-oX", out_xml],
                   timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "udp", profile.host_timeout)
