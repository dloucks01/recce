"""Argparse setup + subcommand tree for recce.

Extracted from cli/__init__.py to keep the command dispatcher small and to
make the parser layout the first thing a reader sees when they want to
understand which subcommands recce exposes.

Handler resolution — every subcommand's `set_defaults(func=…)` used to
reference a `cmd_<name>` function defined next to it in cli.py. Now those
handlers live in `cli/cmd_*.py` sibling modules; the parser resolves them
by name at parse time via ``_h`` so we can build the parser without
importing every command module first (and without cycles).
"""
from __future__ import annotations

import argparse
import os
import sys

from ..core import scanner


def _h(name: str):
    """Look up cmd_<name> on the cli package. Every command handler is
    exposed as an attribute of `recce.cli` (either defined in
    cli/__init__.py itself, or re-exported by it from cmd_*.py), so this
    lookup works whether the split has completed or is still in progress."""
    return getattr(sys.modules[__package__], f"cmd_{name}")


def _deprecated_alias(fn, old: str, new: str):
    """Wrap a command so a pre-rename spelling keeps working, with a nudge to the new one."""
    def _run(args: argparse.Namespace) -> int:
        print(f"[!] `recce {old}` is deprecated - use `recce {new}`.", file=sys.stderr)
        return fn(args)
    return _run



def _add_budget(parser) -> None:
    """A wall-clock cap for a deep module's sequential probe loop."""
    parser.add_argument("--budget", type=float, metavar="SECONDS",
                        help="stop probing after this many seconds and keep partial "
                             "results (default: no cap)")


def _add_common(pp) -> None:
    # The two flags almost every run actually uses stay in the default section so
    # they're the first thing `-h` shows; the tuning knobs fold into a labelled
    # group below so the help reads as "here's the one flag you need, advanced
    # stuff is over there" instead of a flat wall.
    pp.add_argument("-o", "--output-dir", default="engagement",
                    help="output directory (default: ./engagement)")
    pp.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown in reports")
    g = pp.add_argument_group("output & performance (optional)")
    g.add_argument("--profile", choices=list(scanner.PROFILES), default="standard",
                   help="scan depth preset (default: standard)")
    g.add_argument("--workers", type=int, default=6,
                   help="concurrent hosts to scan at once (default: 6)")
    g.add_argument("--refresh-every", type=int, default=10, metavar="N",
                   help="regenerate reports every N hosts (0 to disable; default 10)")
    g.add_argument("--host-timeout", type=int, metavar="MIN",
                   help="per-host time ceiling in minutes; nmap gives up on a "
                        "host after this and moves on (0 = no limit)")
    g.add_argument("--proxy", metavar="URL",
                   help="pivot: route the whole run through a proxy, e.g. "
                        "socks5h://127.0.0.1:1080 (also socks4a:// or http://). recce "
                        "re-execs under proxychains4 and switches to a proxy-safe "
                        "connect scan (no SYN/masscan/UDP - they'd bypass the proxy)")


def _add_io(pp, title: bool = True) -> None:
    """The output-dir (+ optional engagement title) flags the lighter commands share.
    The scan-style commands use _add_common (these two PLUS the perf group); the
    report/status/next/verify/... commands just want these, so this is the one place
    their default/help lives instead of ~35 hand-copied add_argument lines."""
    pp.add_argument("-o", "--output-dir", default="engagement",
                    help="output directory (default: ./engagement)")
    if title:
        pp.add_argument("--title", default="Recce Engagement",
                        help="engagement title shown in reports")


def _add_creds(pp) -> None:
    # The three you reach for (user / pass / domain) are grouped together; the
    # privileged-account and LDAP-tuning flags fold into a second group so the
    # simple credentialed run (`-u USER -p PASS -d DOMAIN`) isn't buried.
    g = pp.add_argument_group("credentials")
    g.add_argument("-u", "--username",
                   help="user account for authenticated SMB/LDAP/WinRM. Domain-"
                        "qualified forms work too: 'CORP\\user', 'corp.local/user', "
                        "or 'user@corp.local' (splits out the domain, so -d is "
                        "optional then)")
    g.add_argument("-p", "--password", help="password for the user account")
    g.add_argument("-d", "--domain",
                   help="AD domain (e.g. corp.local) for authentication; overrides "
                        "any domain embedded in -u")
    a = pp.add_argument_group("privileged & LDAP (optional)")
    a.add_argument("--admin-user", dest="admin_username",
                   help="privileged/superuser account: runs the admin-only checks "
                        "(confirm local-admin reach, secretsdump hash dump)")
    a.add_argument("--admin-pass", dest="admin_password",
                   help="password for the privileged account")
    a.add_argument("--admin-domain", dest="admin_domain",
                   help="domain for the privileged account (defaults to -d)")
    a.add_argument("--ldap-enum", action="store_true",
                   help="credentialed LDAP enumeration of discovered DCs")
    a.add_argument("--ldap-anon", action="store_true", help="attempt anonymous LDAP bind")
    a.add_argument("--ldap-ssl", action="store_true", help="use LDAPS (636)")
    a.add_argument("--dc-ip", help="target this DC IP for LDAP instead of auto-detect")


def _add_discovery(pp) -> None:
    # `targets` plus the one or two flags a normal sweep uses (-Pn, --fast) sit up
    # top; the rest are scan internals you only reach for on a difficult network,
    # folded into a labelled group so `enum -h` opens with what you actually type.
    pp.add_argument("targets", nargs="+", help="CIDRs / ranges / IPs / hostnames, or @file")
    pp.add_argument("-Pn", "--no-discovery", action="store_true", dest="no_discovery",
                    help="skip the ping sweep and scan every target as if up (like "
                         "nmap -Pn). Use this when hosts block ping - common on "
                         "firewalled / Windows / AD networks.")
    pp.add_argument("--targets-up", action="store_true", dest="targets_up",
                    help="treat the target list as AUTHORITATIVE: implies -Pn, and "
                         "PRE-SEEDS every target (with its @file hostname) into the "
                         "report up front - so a slow / timed-out / failed scan can "
                         "never make a real host vanish ('no hosts'). Use with a "
                         "complete IP[,hostname] @file you trust.")
    pp.add_argument("--fast", action="store_true",
                    help="go fast: masscan network-wide sweep instead of per-host "
                         "nmap (and, in `scan`, top-signal vuln scripts only)")
    g = pp.add_argument_group("scan tuning (optional)")
    g.add_argument("--exclude", nargs="*", metavar="IP|CIDR|RANGE|@file",
                   help="hosts to keep OUT of scope: IPs / ranges / CIDRs, or @file "
                        "(one per line). Persisted to the engagement - once excluded, an "
                        "IP stays out of scope on every later phase/re-run.")
    g.add_argument("--masscan", action="store_true", help="use masscan for port sweep")
    g.add_argument("--all-ports", action="store_true",
                   help="force the full 65535-port TCP sweep, overriding the profile "
                        "and any --top-ports (the `standard`/`thorough` profiles already "
                        "do this; use it to force a full scan under `quick`/`--fast`)")
    g.add_argument("--top-ports", type=int,
                   help="scan only the top-N TCP ports (PARTIAL - faster but can miss a "
                        "service on an unusual port; recce prints a warning)")
    g.add_argument("--min-rate", type=int, help="nmap --min-rate override")
    g.add_argument("--max-retries", type=int, metavar="N",
                   help="nmap --max-retries on the port sweep. Floored at nmap's own -T "
                        "default (6 at -T4, 10 at -T3) so a lower value can't silently "
                        "drop open ports; raise it for very lossy links.")
    g.add_argument("--no-verify", action="store_true",
                   help="skip the confirmation re-scan of hosts that come back with "
                        "0 open ports (faster; may trust a missed sweep)")
    g.add_argument("--verify-all", action="store_true",
                   help="also re-verify 0-port hosts under -Pn (not just discovered-"
                        "live ones) - catches every missed sweep, slower on dead-IP "
                        "scopes")
    g.add_argument("--no-udp-fallback", action="store_true",
                   help="skip the UDP liveness ping sent to a -Pn host that stays "
                        "silent on TCP (the ping tells a firewalled-but-alive host "
                        "apart from a dead one; needs root for raw UDP)")
    g.add_argument("--no-reconfirm", action="store_true",
                   help="after a partial ping sweep, DON'T re-probe the non-responders "
                        "with a fast -Pn top-ports scan (that re-probe recovers "
                        "firewalled hosts that block ping but answer a port scan)")
    g.add_argument("--reliable", action="store_true",
                   help="rate-limited / lossy network: drop the --min-rate floor, "
                        "retry dropped probes more, let nmap's congestion control "
                        "adapt (recce also switches to this automatically when it "
                        "sees nmap dropping probes)")
    g.add_argument("--no-ad", action="store_true", help="skip SMB/LDAP AD scripts")
    g.add_argument("--no-os", action="store_true", help="skip OS detection")
    g.add_argument("--version-all", action="store_true",
                   help="max-effort service detection (--version-all: every probe)")
    g.add_argument("--version-intensity", type=int, metavar="0-9",
                   help="nmap -sV probe intensity for service detection (default 8)")
    g.add_argument("--resume", action="store_true", help="skip hosts already in datastore")


def _add_vuln_opts(pp) -> None:
    g = pp.add_argument_group("vuln-scan tuning (optional)")
    g.add_argument("--rules", metavar="FILE",
                   help="load extra detection rules from a JSON file (data-driven "
                        "detection: add/override version->CVE signatures without code; "
                        "see docs/reference/detection-rules.md)")
    g.add_argument("--aggressive", action="store_true",
                   help="run the full intrusive NSE 'vuln' category (can crash "
                        "fragile services); default is deep safe detection")
    g.add_argument("--offline", action="store_true",
                   help="airgapped: disable internet-dependent NSE (vulners)")
    g.add_argument("--no-searchsploit", action="store_true",
                   help="skip offline exploit mapping via searchsploit")
    g.add_argument("--no-probes", action="store_true",
                   help="skip the active stdlib probes (HTTP-header / TLS "
                        "enrichment + the service-detection banner grabs); the free "
                        "passive naming (servicefp mining + curated port map) stays on")
    g.add_argument("--udp-top", type=int,
                   help="scan top-N UDP ports in the vulns phase (default 30 on the "
                        "standard profile, 100 on thorough; 0 disables)")
    g.add_argument("--no-udp", action="store_true",
                   help="skip ALL UDP scanning - both the enum-phase curated sweep "
                        "(DNS/SNMP/NTP/IKE/TFTP/NetBIOS/CLDAP/RADIUS/NFS/...) and the "
                        "vulns-phase top-N. UDP needs root; it auto-skips otherwise.")


def build_arg_parser() -> argparse.ArgumentParser:
    from .. import __version__
    p = argparse.ArgumentParser(
        prog="recce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Phased enumeration & reporting for pentest engagements. "
                    "Scans fill an Excel workbook you check off as you go.",
        epilog=(
            "quick start - one command does the whole engagement:\n"
            "  recce run 10.0.0.0/24 -o eng             # discover->enum->vulns->deep->report\n"
            "  recce run 10.0.0.0/24 -u U -p P -o eng   # + authenticated SMB/AD/mssql modules\n\n"
            "core loop, any time:\n"
            "  recce next   -o eng     # the best next step, from what's been found\n"
            "  recce verify --run -o eng   # confirm/refute version leads (safe re-check)\n"
            "  recce status -o eng     # coverage + what's left\n"
            "  recce report -o eng     # regenerate the workbook / write-ups\n\n"
            "everything else is a surgical subcommand (per-service enum, ingest, deploy, ...).\n"
            "targets: single IP, several IPs, range (10.0.0.10-40), CIDR, or @file.\n"
            "interrupted? re-run (add --resume) or 'recce next' - nothing dead-ends.\n"
            "run 'recce <command> -h' for a command's options."
        ),
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"recce {__version__}")
    sub = p.add_subparsers(dest="command", required=False, metavar="<command>")

    # Phase 1: fast enumeration -> sheet.
    e = sub.add_parser("enum", help="discover hosts, scan ports, ID services -> sheet")
    _add_discovery(e)
    _add_common(e)
    _add_creds(e)
    e.set_defaults(func=_h("enum"))

    # Phase 2: targeted vuln scanning of open ports already in the datastore.
    v = sub.add_parser("vulns", help="vuln-scan open ports found by `enum`")
    v.add_argument("targets", nargs="*",
                   help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(v)
    _add_vuln_opts(v)
    _add_creds(v)
    v.add_argument("--fast", action="store_true",
                   help="top-signal detection scripts only (skip the broad "
                        "'vuln and safe' net + deep enum) - much quicker on a /24, "
                        "shows live per-host progress + ETA")
    v.add_argument("--only", nargs="*", metavar="SVC",
                   help="only ports matching these service names / port numbers "
                        "(e.g. http smb 445)")
    v.add_argument("--unscanned", action="store_true",
                   help="only ports not already vuln-scanned")
    v.set_defaults(func=_h("vulns"))

    # Phase 2 (databases): DB-specific enumeration + vuln scan.
    dbp = sub.add_parser("db", help="database enumeration + vuln scan")
    dbp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(dbp)
    dbp.add_argument("--aggressive", action="store_true",
                     help="intrusive DB checks (brute / xp_cmdshell / hash dump)")
    dbp.add_argument("--no-searchsploit", action="store_true")
    _add_creds(dbp)
    dbp.set_defaults(func=_h("db"))

    # Phase 3 (priv-esc): playbook + optional remote checks.
    pep = sub.add_parser("privesc", help="priv-esc playbook (Windows/Linux) + checks")
    pep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(pep)
    pep.add_argument("--scan", action="store_true",
                     help="also run remote privesc NSE checks (smb-vuln-* etc.)")
    pep.add_argument("--aggressive", action="store_true",
                     help="include intrusive privesc NSE (may crash services)")
    _add_creds(pep)
    pep.set_defaults(func=_h("privesc"))

    # Phase 3 (credentialed): authenticated enum via netexec / impacket / ssh.
    cep = sub.add_parser("credenum",
                         help="credentialed enum (netexec/impacket/ssh) - needs creds")
    cep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(cep)
    _add_creds(cep)
    cep.add_argument("--ssh-user", help="username for SSH local checks on Linux hosts")
    cep.add_argument("--ssh-pass", help="SSH password (needs sshpass on PATH)")
    cep.add_argument("--ssh-key", help="SSH private-key path for local checks")
    cep.add_argument("--aggressive", action="store_true",
                     help="also dump hashes with secretsdump (needs admin/DA)")
    cep.add_argument("--all-creds", action="store_true",
                     help="spray every stacked/looted credential (lockout-safe) to find "
                          "the working cred per host, then enum each host with ITS cred")
    cep.add_argument("--user-list", metavar="FILE", help="usernames to spray (one per line)")
    cep.add_argument("--pass-list", metavar="FILE", help="passwords to spray (one per line)")
    cep.add_argument("--spray", action="store_true",
                     help="full user x password when discovering creds (drops "
                          "--no-bruteforce). REAL lockout risk - opt-in.")
    cep.set_defaults(func=_h("credenum"))

    # deploy: push + run the read-only local-enum / priv-esc scripts across every
    # host we have creds for (SSH / WinRM / SMB), then fold the results in.
    dp = sub.add_parser("deploy",
                        help="mass local-enum + priv-esc: run recce-enum.sh/.ps1 on "
                             "every host you have creds for (SSH/WinRM/SMB)")
    dp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(dp)
    _add_creds(dp)
    dg = dp.add_argument_group("deploy options (optional)")
    dg.add_argument("--ssh-user", help="username for SSH (Linux hosts)")
    dg.add_argument("--ssh-pass", help="SSH password (needs sshpass on PATH)")
    dg.add_argument("--ssh-key", help="SSH private-key path")
    dg.add_argument("--hash", help="NTLM hash for pass-the-hash (SMB/WinRM), with -u")
    dg.add_argument("--stager", action="store_true",
                    help="Windows hosts fetch + run the script IN MEMORY from a "
                         "short-lived local HTTP server (no temp file, any size); "
                         "auto-falls-back to the push path if a host can't reach you")
    dg.add_argument("--lhost", help="your IP that targets route back to (for "
                                    "--stager; autodetected if omitted)")
    dg.add_argument("--no-validate", action="store_true",
                    help="skip the nxc credential precheck (select transport from "
                         "open ports only)")
    dg.add_argument("--timeout", type=int, metavar="SEC",
                    help="per-host remote-exec ceiling (default 300s)")
    dg.add_argument("--dry-run", action="store_true",
                    help="show the per-host transport plan and exit; run nothing")
    dp.set_defaults(func=_h("deploy"))

    # Reporting: per-finding Word write-ups from the template.
    wu = sub.add_parser("writeups",
                        help="generate one Word (.docx) write-up per finding")
    wu.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(wu, title=False)
    wu.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown on the combined report")
    wu.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="only findings at or above this severity (default: low - "
                         "excludes informational items; use 'info' to include them)")
    wu.add_argument("--include-potential", action="store_true",
                    help="also write up low-confidence, version-inferred 'potential' "
                         "findings (default: real findings only - those confirmed by "
                         "an actual check/observation)")
    wu.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    wu.add_argument("--no-combined", action="store_true",
                    help="skip the single combined findings_report.docx")
    wu.add_argument("--overwrite", action="store_true",
                    help="regenerate even where a write-up exists (loses tester edits)")
    wu.set_defaults(func=_h("writeups"))

    # Single-finding write-up, pre-filled with what's already looted/obtained.
    w1 = sub.add_parser("writeup",
                        help="write up ONE finding (pre-filled with looted/obtained "
                             "evidence); run with no selector to list findings")
    w1.add_argument("selector", nargs="?",
                    help="which finding: an F-id (F-007 / 7), a CVE, an IP or IP:port, "
                         "or a word from its title. Omit to list all findings.")
    _add_io(w1, title=False)
    w1.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    w1.add_argument("--overwrite", action="store_true",
                    help="regenerate even if this write-up already exists")
    w1.set_defaults(func=_h("writeup"))

    # Bridge: per-open-port enumeration commands from recce/scripts/.
    sv = sub.add_parser("services",
                        help="print the per-service enum command to run for every "
                             "open port recce found (bridges to recce/scripts/)")
    sv.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(sv, title=False)
    sv.add_argument("-a", "--aggressive", action="store_true",
                    help="append -a to each command (enable the intrusive checks)")
    sv.set_defaults(func=_h("services"))

    # Deep web enumeration: fingerprint + non-intrusive checks on every HTTP(S) port.
    # External-tool bridges: recce doesn't reimplement these scanners — it
    # drives them and folds their native output back into the engagement.
    nu = sub.add_parser("nuclei",
                        help="run nuclei against web endpoints and fold findings "
                             "back into the engagement (recce doesn't ship nuclei — install it)")
    nu.add_argument("targets", nargs="*",
                    help="URLs or host[:port] tokens; default = every web endpoint in the store")
    _add_io(nu)
    nu.set_defaults(func=_h("nuclei"))

    ct = sub.add_parser("certipy",
                        help="run certipy find against an AD-CS enrollment endpoint "
                             "and fold ESC findings via the `ad` importer "
                             "(recce doesn't ship certipy — pipx install certipy-ad)")
    _add_io(ct)
    ct.add_argument("-u", "--username", required=True, help="domain user")
    ct.add_argument("-p", "--password", required=True, help="domain user password")
    ct.add_argument("-d", "--domain", required=True, help="domain FQDN (CORP.LOCAL)")
    ct.add_argument("--dc-ip", dest="dc_ip", required=True, help="DC IP")
    # Placeholders so cmd_certipy can hand the whole ns to cmd_ad without KeyError.
    ct.add_argument("--admin-username", default="", help=argparse.SUPPRESS)
    ct.add_argument("--admin-password", default="", help=argparse.SUPPRESS)
    ct.add_argument("--admin-domain", default="", help=argparse.SUPPRESS)
    ct.add_argument("--replace-ad", action="store_true", default=False, help=argparse.SUPPRESS)
    ct.add_argument("--roast", action="store_true", default=False, help=argparse.SUPPRESS)
    ct.add_argument("--asrep", action="store_true", default=False, help=argparse.SUPPRESS)
    ct.add_argument("--dcsync", action="store_true", default=False, help=argparse.SUPPRESS)
    ct.add_argument("--owned", default="", help=argparse.SUPPRESS)
    ct.add_argument("--screenshots", action="store_true", default=False, help=argparse.SUPPRESS)
    ct.add_argument("--creds", default="", help=argparse.SUPPRESS)
    ct.set_defaults(func=_h("certipy"))

    wb = sub.add_parser("web",
                        help="deep-enumerate web endpoints (tech fingerprint + "
                             "exposed .git/.env, actuator, methods, headers/TLS)")
    wb.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(wb)
    wb.add_argument("--workers", type=int, default=6,
                    help="concurrent hosts to scan at once (default: 6)")
    wb.add_argument("--no-active", action="store_true",
                    help="passive only: headers/TLS fingerprint, skip the path/method "
                         "probes (no requests beyond the root)")
    wb.add_argument("--cookie", help="Cookie header to scan as an authenticated user "
                                     "(e.g. 'session=abc123')")
    wb.add_argument("--header", action="append", metavar="K: V",
                    help="extra request header, repeatable (e.g. --header "
                         "'Authorization: Bearer <token>')")
    wb.add_argument("--screenshots", action="store_true",
                    help="also capture a headless-browser screenshot per endpoint "
                         "-> engagement/screenshots/ (needs chromium/firefox)")
    wb.add_argument("--creds", action="store_true",
                    help="also try a tiny documented default-credential list against "
                         "HTTP Basic-auth endpoints (lockout-aware, <=5 tries/endpoint)")
    wb.add_argument("--crawl", action="store_true",
                    help="same-origin crawl each site (authenticated with --cookie/"
                         "--header): discover pages/params/forms, then test discovered "
                         "GET params AND form fields for reflection/SSTI + SQL injection "
                         "(error/boolean), and flag cleartext-login / no-CSRF forms")
    wb.add_argument("--sqli-time", action="store_true",
                    help="with --crawl, also run the slower TIME-based blind SQLi probe "
                         "(sends deliberate DB sleeps; confirms by scaling the delay)")
    wb.add_argument("--autologin", action="store_true",
                    help="ACTIVE: try to log into each site's form with the engagement's "
                         "harvested credentials (looted from .git/.env/DBs/specs), then "
                         "scan the AUTHENTICATED surface. One login POST per credential "
                         "(lockout-aware). Ignored if --cookie/--header is set.")
    wb.add_argument("--fuzz-risky-forms", action="store_true",
                    help="with --crawl, ALSO submit forms whose action/fields signal a "
                         "side effect (delete / pay / send / post / ...). Off by default "
                         "- those forms are recorded, not submitted. File uploads are "
                         "never submitted. Use only on a throwaway/dev target.")
    wb.add_argument("--upload-shell", action="store_true",
                    help="ACTIVE PROOF: when a multipart upload form is found, upload a "
                         "BENIGN server-computed-marker payload (echoes tag + 7*7) across "
                         "common script extensions and fetch it back - a computed marker in "
                         "the response CONFIRMS code execution (RCE). Writes a file to the "
                         "target; the finding names the path to delete. Use only in ROE.")
    wb.add_argument("--smuggle", action="store_true",
                    help="ACTIVE PROOF: CL.TE/TE.CL HTTP request-smuggling timing probe "
                         "(sends a request with both Content-Length and Transfer-Encoding; "
                         "an incomplete body only, never a smuggled second request). Can "
                         "disturb fragile proxies and may affect SHARED front-ends - use "
                         "only against dedicated infra in ROE.")
    wb.add_argument("--wordlist", metavar="FILE",
                    help="path to a wordlist of extra HTTP paths to probe (one per "
                         "line; # comments; leading / auto-added). AUGMENTS the "
                         "bundled 110-path list — nothing removed. Use a dirbuster/"
                         "SecLists file to widen coverage on custom apps.")
    _add_budget(wb)
    wb.set_defaults(func=_h("web"))

    # Per-finding exploitation plan: runnable artifacts driving existing tools.
    ep = sub.add_parser("exploitplan",
                        help="generate ready-to-run exploitation artifacts (msf .rc + "
                             "tool commands) for confirmed findings, params pre-filled")
    ep.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(ep, title=False)
    ep.add_argument("--lhost", default="<LHOST>",
                    help="your callback IP for reverse payloads (fills LHOST in the "
                         ".rc files)")
    ep.add_argument("--lport", type=int, default=4444, help="callback port (default 4444)")
    ep.add_argument("--run", action="store_true",
                    help="arm the Metasploit launch lines (default: check-only, safe). "
                         "Use ONLY within your rules of engagement.")
    ep.set_defaults(func=_h("exploitplan"))

    pc = sub.add_parser("poc",
                        help="assemble a per-CVE PoC dossier + Python harness skeleton "
                             "from offline intel (vulndb/KEV/EPSS/Exploit-DB/msf); "
                             "authorized testing only")
    pc.add_argument("cves", nargs="*",
                    help="CVE ids to build (e.g. CVE-2021-44228); default: the CVEs from "
                         "the engagement's findings")
    _add_io(pc, title=False)
    pc.add_argument("--confirmed", action="store_true",
                    help="only CVEs from CONFIRMED findings (default: all findings' CVEs)")
    pc.add_argument("--with-exploits", action="store_true",
                    help="also copy the matching Exploit-DB PoC files into each CVE dir "
                         "(needs searchsploit/exploitdb)")
    pc.set_defaults(func=_h("poc"))

    # Proof / verification: is a flagged finding real or a false positive?
    pv = sub.add_parser("prove",
                        help="prove out findings - verdict (real / false-positive / "
                             "needs-PoC) + the exact safe check, per finding")
    pv.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(pv)
    pv.add_argument("--profile", choices=list(scanner.PROFILES), default="standard")
    pv.add_argument("--run", action="store_true",
                    help="also re-run the NON-INTRUSIVE detection NSE (SMB "
                         "security-mode / ms17-010) to move verdicts from LIKELY to "
                         "CONFIRMED / FALSE POSITIVE on real evidence")
    pv.set_defaults(func=_h("prove"))

    # Attack-path synthesis: chain confirmed findings into a staged path.
    ap = sub.add_parser("attackpath",
                        help="chain confirmed findings into a prioritised attack path "
                             "(foothold -> priv-esc -> creds -> lateral -> domain)")
    ap.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(ap, title=False)
    ap.set_defaults(func=_h("attackpath"))

    # Credential stacking + spray planning.
    cd = sub.add_parser("creds",
                        help="stack captured credentials and build a netexec/impacket "
                             "spray plan across the discovered surface")
    cd.add_argument("targets", nargs="*",
                    help="restrict spray targets to these IPs / ranges / CIDRs / @file")
    _add_io(cd, title=False)
    cd.add_argument("--add", action="append", metavar="USER:SECRET",
                    help="add a captured credential: 'user:secret', "
                         "'DOMAIN\\user:secret' (a 32-hex secret => NT hash). Repeatable.")
    # --username/--password (not --user/--pass) so -u/-p read the same across every
    # subcommand's --help, even though creds' -u/-p stage a credential rather than
    # authenticate with one; dest= pinned so cmd_creds's args.user is unaffected.
    cd.add_argument("-u", "--username", dest="user", help="add a credential: username")
    cd.add_argument("-p", "--password", dest="password", help="add a credential: password")
    cd.add_argument("-H", "--hash", help="add a credential: NT hash (for pass-the-hash)")
    cd.add_argument("-d", "--domain", help="add a credential: AD domain (blank = local)")
    # Closes the crack loop: recce formats hashes for hashcat in a dozen places
    # (NT -m 1000, kerberoast -m 13100, AS-REP -m 18200, mssql -m 1731, ...) but
    # had no path back, so cracked passwords had to be re-keyed by hand before
    # they could be sprayed.
    cd.add_argument("--potfile", metavar="FILE",
                    help="fold cracked plaintexts back in from a hashcat/john potfile "
                         "(hash:plaintext). Matches against the NT hashes recce holds "
                         "and the roasted Kerberos hashes in loot/, adds each as a "
                         "password credential, then spray with --plan/--run")
    cd.add_argument("--plan", action="store_true",
                    help="build the spray plan (write users/passwords/hashes files "
                         "+ print the netexec/impacket commands)")
    cd.add_argument("--run", action="store_true",
                    help="EXECUTE the spray with netexec (lockout-safe: paired user<->pass, "
                         "one pass) across the target scope, and fold the validated logins "
                         "back. Needs netexec/nxc on PATH.")
    cd.add_argument("--user-list", metavar="FILE",
                    help="a file of usernames to spray (one per line), in addition to the "
                         "stacked/looted creds")
    cd.add_argument("--pass-list", metavar="FILE",
                    help="a file of passwords to spray (one per line)")
    cd.add_argument("--all-creds", action="store_true",
                    help="spray every stacked/looted credential (the default set for --run)")
    cd.add_argument("--spray", action="store_true",
                    help="full user x password (drops --no-bruteforce). REAL lockout risk on "
                         "a domain lockout policy - opt-in; default is lockout-safe paired.")
    cd.set_defaults(func=_h("creds"))

    # Convenience: enum + vulns in one shot.
    # THE front door: one adaptive, resumable command (scan --deep + authenticated modules
    # when creds are given). Mirrors scan's options; the surgical subcommands remain.
    rn = sub.add_parser("run", help="THE one command: discover -> enum -> vulns -> every "
                                    "applicable deep module -> report (adaptive, resumable; "
                                    "pass -u/-p to also run the authenticated modules)")
    _add_discovery(rn)
    _add_common(rn)
    _add_vuln_opts(rn)
    _add_creds(rn)
    rn.add_argument("--skip", nargs="*", metavar="MOD",
                    help="deep modules to skip (e.g. --skip mssql docker)")
    rn.add_argument("--only-modules", nargs="*", metavar="MOD",
                    help="run only these deep modules")
    rn.add_argument("--act", action="store_true",
                    help="after the pipeline, run the Act phase: auto-loot the read-only "
                         "links, refresh the spray plan, and print the ranked action plan")
    rn.set_defaults(func=_h("run"))

    s = sub.add_parser("scan", help="run enum then vulns in one shot "
                                     "(add --deep for the full credential-free sweep)")
    _add_discovery(s)
    _add_common(s)
    _add_vuln_opts(s)
    _add_creds(s)
    s.add_argument("--deep", action="store_true",
                   help="one kickoff, whole credential-free mass surface across ALL "
                        "targets: discovery -> ports -> service/version -> vulns -> "
                        "every applicable deep module (web/smb/ftp/snmp/db/nfs/...). "
                        "Runs `sweep` right after enum+vulns.")
    s.add_argument("--skip", nargs="*", metavar="MOD",
                   help="with --deep: deep modules to skip (e.g. --skip mssql docker)")
    s.add_argument("--only-modules", nargs="*", metavar="MOD",
                   help="with --deep: run only these deep modules")
    s.set_defaults(func=_h("scan"))

    # One command instead of ~9: run every applicable credential-free deep module.
    sw = sub.add_parser("sweep",
                        help="run ALL applicable deep modules after enum in one shot "
                             "(web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/"
                             "nfs/kerberos/docker/k8s/mssql)")
    sw.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(sw)
    _add_creds(sw)
    _add_vuln_opts(sw)
    sw.add_argument("--vulns", action="store_true",
                    help="also run the nmap NSE vuln scan (heavier; off by default)")
    sw.add_argument("--skip", nargs="*", metavar="MOD",
                    help="deep modules to skip (e.g. --skip mssql docker)")
    sw.add_argument("--only-modules", nargs="*", metavar="MOD",
                    help="run only these deep modules (e.g. --only-modules web smb)")
    sw.add_argument("--no-probe", action="store_true",
                    help="passive: fold what enum already found, don't send probes")
    sw.set_defaults(func=_h("sweep"))

    # The authenticated counterpart of `sweep`: needs creds, runs the credentialed
    # modules (credenum + authenticated ldap/smb/mssql/ftp) in one shot.
    csw = sub.add_parser("credsweep",
                         help="authenticated deep pass (needs -u/-p): run ALL "
                              "credentialed modules in one shot (credenum + "
                              "authenticated ldap/smb/mssql/ftp)")
    csw.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(csw)
    _add_creds(csw)
    csw.add_argument("--prove-write", action="store_true",
                     help="include the reversible writable-share / writable-dir proofs "
                          "(smb/ftp)")
    csw.add_argument("--skip", nargs="*", metavar="MOD",
                     help="credentialed modules to skip (e.g. --skip mssql)")
    csw.add_argument("--only-modules", nargs="*", metavar="MOD",
                     help="run only these modules (e.g. --only-modules credenum ldap)")
    csw.add_argument("--no-probe", action="store_true",
                     help="passive: fold what enum already found, don't send probes")
    csw.set_defaults(func=_h("credsweep"))

    # Fold on-target recce-enum.sh/.ps1 output into the Priv-Esc sheet.
    ing = sub.add_parser("ingest",
                         help="fold on-target recce-enum.sh/.ps1 output into Priv-Esc")
    ing.add_argument("loot", help="path to saved recce-enum output (-o / -OutFile file)")
    ing.add_argument("--host", help="attach findings to this IP (default: auto-resolve "
                                    "from the enum's own NET-IFACE interface IPs, then "
                                    "its hostname, else a 'local:<host>' entry)")
    _add_io(ing)
    ing.set_defaults(func=_h("ingest"))

    # Import an existing nmap scan (XML / grepable) -> workbook, no scanning.
    imp = sub.add_parser("import", aliases=["import-nmap"],
                         help="import a manual/external nmap scan (-oX / -oG / -oN) into "
                              "the engagement - the fallback when recce's own sweep "
                              "missed ports",
                         description="Ingest an nmap scan you ran by hand (or any external "
                         "nmap) and merge it into the engagement - no re-scanning. Hosts, "
                         "ports, and findings are merged by key, so it is safe to run "
                         "repeatedly and safe to overlap recce's own results: nothing is "
                         "duplicated. It reports exactly which open ports the scan ADDED "
                         "over what recce already had. Best output is `nmap -p- -sV -oX "
                         "scan.xml <target>`; grepable (-oG) and normal (-oN .nmap) work "
                         "too. After importing, run `vulns` / the service deep-scans to "
                         "enumerate the newly-added ports.")
    imp.add_argument("files", nargs="+",
                     help="nmap .xml / .gnmap / .nmap file(s), a directory, or a glob")
    _add_io(imp, title=False)
    imp.add_argument("--title", default="Recce Engagement",
                     help="engagement title (only used when starting a fresh datastore)")
    imp.add_argument("--enum-only", action="store_true",
                     help="mark hosts enumerated only; don't auto-mark ports vuln-scanned "
                          "even if the imported scan ran NSE scripts")
    imp.add_argument("--searchsploit", action="store_true",
                     help="also map exploits via searchsploit (needs the tool)")
    imp.set_defaults(func=_h("import"))

    # Import SharpHound and/or Certipy (ADCS) output -> AD findings + paths to DA.
    bhp = sub.add_parser("ad", aliases=["bloodhound"],
                         help="import SharpHound + Certipy (ADCS) data -> AD vulns, "
                              "ESC findings + paths to Domain Admin")
    bhp.add_argument("paths", nargs="+",
                     help="SharpHound output (.zip / dir / .json) and/or a Certipy "
                          "find -json file - pass any mix; each is auto-detected")
    bhp.add_argument("-u", "--username",
                     help="your account - attack paths start from it, and every "
                          "command is pre-filled with it. Domain-qualified forms "
                          "('CORP\\alice', 'alice@corp.local') work too")
    bhp.add_argument("-p", "--password", help="password for your account")
    bhp.add_argument("-d", "--domain", help="AD domain (e.g. corp.local)")
    bhp.add_argument("--dc-ip", help="DC IP to fill into the staged commands")
    bhp.add_argument("--owned", action="append", metavar="USER[,USER...]",
                     help="override the path start set with these principal(s) "
                          "(repeatable / comma-separated)")
    bhp.add_argument("--creds", metavar="DOMAIN/user:secret",
                     help="alternative to -u/-p/-d; an NT hash if it's 32 hex chars")
    bhp.add_argument("--replace-ad", action="store_true",
                     help="clear previously-imported AD/ESC findings on the DC host "
                          "before folding this import, so remediated items disappear "
                          "(default: accumulate across imports)")
    bhp.add_argument("--roast", action="store_true",
                     help="LIVE: run impacket-GetUserSPNs -request to capture real "
                          "TGS-REP (Kerberoast) hashes (needs creds + --dc-ip)")
    bhp.add_argument("--asrep", action="store_true",
                     help="LIVE: run impacket-GetNPUsers -request to capture real "
                          "AS-REP hashes for pre-auth-disabled accounts")
    bhp.add_argument("--dcsync", action="store_true",
                     help="LIVE: run impacket-secretsdump -just-dc to replicate the "
                          "domain NTLM hashes (incl. krbtgt) - only if the account "
                          "holds replication rights")
    bhp.add_argument("--screenshots", action="store_true",
                     help="save terminal-output proof screenshots of the live "
                          "captures into engagement/screenshots/")
    _add_io(bhp)
    bhp.set_defaults(func=_h("bloodhound"))

    # MSSQL offensive enumeration + attack chain.
    ms = sub.add_parser("mssql",
                        help="MSSQL: pre-auth probes + (with creds) nxc access/priv "
                             "matrix + MSSQLPwner-style runbook & attack chain")
    ms.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "MSSQL hosts in the datastore)")
    ms.add_argument("-u", "--username",
                    help="your account - runs the nxc access/priv check and pre-fills "
                         "every command ('CORP\\alice' / 'alice@corp.local' work too)")
    ms.add_argument("-p", "--password", help="password for your account")
    ms.add_argument("-d", "--domain", help="AD domain (omit + --local-auth for a SQL login)")
    ms.add_argument("--local-auth", action="store_true",
                    help="SQL Server authentication (not Windows/domain)")
    ms.add_argument("--dc-ip", help="DC IP to fill into the generated commands")
    ms.add_argument("--lhost", help="your capture/relay IP for the UNC/relay commands")
    ms.add_argument("--relay", action="store_true",
                    help="actually trigger the SQL service account to authenticate to "
                         "--lhost (xp_dirtree) so your ntlmrelayx catches it")
    ms.add_argument("--data", action="store_true",
                    help="mine the databases: enumerate every table (+ row counts) and "
                         "find columns/tables with sensitive names across all databases")
    ms.add_argument("--perms", action="store_true",
                    help="per-database object-permission mining: guest-enabled databases "
                         "and objects public/guest can access")
    ms.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of executed actions "
                         "(RCE output, write-proof, data mining) for the walkthrough")
    ms.add_argument("--prove-write", action="store_true",
                    help="prove write + permission-modify impact REVERSIBLY (create a "
                         "table, modify a field, toggle a role; everything is reverted)")
    ms.add_argument("--exec", dest="exec_cmd", metavar="CMD",
                    help="execute an OS command on each reachable instance for effect "
                         "and capture the output (needs sysadmin)")
    ms.add_argument("--method", choices=["xp", "ole", "agent", "clr"], default="xp",
                    help="execution primitive for --exec: xp_cmdshell (default), OLE "
                         "Automation, SQL Agent job, or CLR (hands off to mssqlpwner)")
    ms.add_argument("--no-run", action="store_true",
                    help="don't execute nxc/impacket; just write the commands (airgapped-safe)")
    ms.add_argument("--no-probe", action="store_true",
                    help="skip the live SQL Browser / TDS pre-login probes")
    ms.add_argument("--no-links", action="store_true",
                    help="don't recursively walk the linked-server graph")
    ms.add_argument("--link-depth", type=int, default=4, metavar="N",
                    help="max linked-server chain depth to walk (default 4)")
    ms.add_argument("--wordlist", metavar="FILE",
                    help="path to a credential wordlist (each line 'user:password' "
                         "or bare password paired with sa). AUGMENTS the bundled "
                         "weak-sa sweep — only runs when no engagement creds set.")
    _add_io(ms)
    _add_budget(ms)
    ms.set_defaults(func=_h("mssql"))

    # SMB offensive enumeration + attack surface.
    sm = sub.add_parser("smb",
                        help="SMB: stdlib pre-auth posture (dialect/signing/SMBv1) + "
                             "anonymous/credentialed share enum + writable-share proof")
    sm.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "SMB hosts in the datastore)")
    sm.add_argument("-u", "--username",
                    help="your account - runs the authenticated enum and pre-fills every "
                         "command ('CORP\\alice' / 'alice@corp.local' work too)")
    sm.add_argument("-p", "--password", help="password for your account")
    sm.add_argument("-d", "--domain", help="AD domain (e.g. corp.local)")
    sm.add_argument("--dc-ip", help="DC IP to fill into the generated commands")
    sm.add_argument("--prove-write", action="store_true",
                    help="prove a writable share REVERSIBLY (drop a marker file, list "
                         "it, delete it) - nothing is left behind")
    sm.add_argument("--spider", action="store_true",
                    help="spider READABLE shares for secret-looking files (answer files, "
                         "web.config, KeePass/SSH keys, GPP, password lists, backups)")
    sm.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of executed actions "
                         "(share enum, write-proof) for the walkthrough")
    sm.add_argument("--no-run", action="store_true",
                    help="don't execute nxc/smbclient; just write the commands (airgapped-safe)")
    sm.add_argument("--no-probe", action="store_true",
                    help="skip the live SMB2/SMBv1 negotiate probes")
    _add_io(sm)
    _add_budget(sm)
    sm.set_defaults(func=_h("smb"))

    # FTP offensive enumeration.
    fp = sub.add_parser("ftp",
                        help="FTP: stdlib banner/anonymous/AUTH-TLS probe + known-"
                             "backdoor match + reversible writable-directory proof")
    fp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "FTP hosts in the datastore)")
    fp.add_argument("-u", "--username", help="FTP username (omit to probe anonymous)")
    fp.add_argument("-p", "--password", help="FTP password")
    fp.add_argument("--prove-write", action="store_true",
                    help="prove a writable directory REVERSIBLY (STOR a marker file, "
                         "then DELE it - nothing left behind)")
    fp.add_argument("--screenshots", action="store_true",
                    help="capture terminal-style PROOF screenshots of the write proof")
    fp.add_argument("--no-run", action="store_true",
                    help="don't run the write proof; just write the commands")
    fp.add_argument("--no-probe", action="store_true",
                    help="skip the live banner/anonymous/FEAT probe")
    _add_io(fp)
    _add_budget(fp)
    fp.set_defaults(func=_h("ftp"))

    # Docker Engine API enumeration.
    dk = sub.add_parser("docker",
                        help="Docker: read the Engine API (2375/2376) unauthenticated "
                             "-> CONFIRMED exposed daemon = remote root RCE on the host")
    dk.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Docker hosts in the datastore)")
    dk.add_argument("--screenshots", action="store_true",
                    help="save a terminal-style `docker info` proof screenshot for "
                         "each exposed daemon")
    dk.add_argument("--no-probe", action="store_true",
                    help="skip the live API read; just write the commands")
    _add_io(dk)
    dk.set_defaults(func=_h("docker"))

    # Kubernetes attack-surface enumeration.
    kp = sub.add_parser("kubernetes", aliases=["k8s"],
                        help="Kubernetes: unauthenticated reads of the kubelet "
                             "(10250/10255), kube-apiserver (6443/8443) and etcd (2379)")
    kp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Kubernetes hosts in the datastore)")
    kp.add_argument("--no-probe", action="store_true",
                    help="skip the live unauthenticated reads; just write the commands")
    _add_io(kp)
    _add_budget(kp)
    kp.set_defaults(func=_h("kubernetes"))

    # LDAP / AD directory enumeration.
    lp = sub.add_parser("ldap",
                        help="LDAP: anonymously bind + read the RootDSE (domain/forest/"
                             "DC/functional level) and test for anonymous directory read")
    lp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "LDAP hosts in the datastore)")
    lp.add_argument("--screenshots", action="store_true",
                    help="save a terminal-style RootDSE proof screenshot per DC")
    lp.add_argument("--no-probe", action="store_true",
                    help="skip the live bind/read; just write the commands")
    _add_creds(lp)
    lp.add_argument("--hash", metavar="NThash",
                    help="NTLM hash for pass-the-hash (with -u/-d): an NTLM SASL bind "
                         "authenticates the enumeration without the plaintext password; "
                         "on plaintext 389 it is sign+sealed so a signing-required DC "
                         "accepts it (LDAPS 636 needs no sealing)")
    _add_io(lp)
    _add_budget(lp)
    lp.set_defaults(func=_h("ldap"))

    # SNMP enumeration (UDP 161).
    ap = sub.add_parser("api",
                        help="API enum: OpenAPI/Swagger specs, interactive docs, and "
                             "GraphQL introspection on the web services enum found")
    ap.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "web hosts in the datastore)")
    _add_io(ap)
    ap.add_argument("--no-probe", action="store_true",
                    help="don't send API probes (list web targets only)")
    _add_budget(ap)
    ap.set_defaults(func=_h("api"))

    sp = sub.add_parser("snmp",
                        help="SNMP: brute common community strings (UDP 161) and walk "
                             "the system group + Windows users / processes / software")
    sp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "hosts in the datastore - recce probes UDP 161 directly)")
    sp.add_argument("--no-probe", action="store_true",
                    help="skip the live community brute/walk; just write the commands")
    _add_io(sp)
    _add_budget(sp)
    sp.set_defaults(func=_h("snmp"))

    # MongoDB enumeration.
    mp = sub.add_parser("mongodb", aliases=["mongo"],
                        help="MongoDB: unauthenticated wire-protocol probe (27017-19) -> "
                             "CONFIRM listDatabases without auth = critical data exposure")
    mp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "MongoDB hosts in the datastore)")
    mp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    mp.add_argument("-u", "--username", help="credential to try on auth-required "
                    "instances (also sprays looted creds from the datastore)")
    mp.add_argument("-p", "--password", help="password for -u")
    mp.add_argument("--wordlist", metavar="FILE",
                    help="path to a credential wordlist (each line 'user:password' "
                         "or bare password paired with admin). AUGMENTS the "
                         "bundled 6-cred weak-SCRAM sweep.")
    _add_io(mp)
    _add_budget(mp)
    mp.set_defaults(func=_h("mongodb"))

    # Redis enumeration.
    rp = sub.add_parser("redis",
                        help="Redis: unauthenticated RESP probe (6379/6380) -> CONFIRM "
                             "INFO without auth = critical exposure (read/write + RCE)")
    rp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Redis hosts in the datastore)")
    rp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    _add_io(rp)
    _add_budget(rp)
    rp.set_defaults(func=_h("redis"))

    # MySQL / MariaDB enumeration.
    myp = sub.add_parser("mysql", aliases=["mariadb"],
                         help="MySQL/MariaDB: read the handshake (3306) -> CONFIRM an "
                              "empty-password root/anonymous login = data exposure")
    myp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "MySQL hosts in the datastore)")
    myp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    myp.add_argument("-u", "--username", help="credential to try on auth-required "
                     "instances (also sprays looted creds from the datastore)")
    myp.add_argument("-p", "--password", help="password for -u")
    _add_io(myp)
    _add_budget(myp)
    myp.set_defaults(func=_h("mysql"))

    # PostgreSQL enumeration.
    pgp = sub.add_parser("postgres", aliases=["postgresql", "psql"],
                         help="PostgreSQL: v3 startup probe (5432) -> CONFIRM `trust` "
                              "auth (no password) = data exposure")
    pgp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "PostgreSQL hosts in the datastore)")
    pgp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    pgp.add_argument("-u", "--username", help="credential to try on auth-required "
                     "instances (also sprays looted creds from the datastore)")
    pgp.add_argument("-p", "--password", help="password for -u")
    pgp.add_argument("--prove", dest="prove_rce", action="store_true",
                     help="ACTIVE: on a superuser/COPY-capable instance, run a benign "
                          "`id` via COPY FROM PROGRAM to CONFIRM RCE (opt-in; ROE only)")
    pgp.add_argument("--wordlist", metavar="FILE",
                     help="path to a credential wordlist (each line 'user:password' "
                          "or bare password paired with postgres). AUGMENTS the "
                          "bundled default-cred sweep — runs only when supplied "
                          "creds fail.")
    _add_io(pgp)
    _add_budget(pgp)
    pgp.set_defaults(func=_h("postgres"))

    # SMTP enumeration.
    smp = sub.add_parser("smtp", aliases=["mail"],
                         help="SMTP: EHLO + envelope-only open-relay test (no DATA sent) "
                              "+ VRFY user-enum + STARTTLS posture (25/465/587)")
    smp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "SMTP hosts in the datastore)")
    smp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    smp.add_argument("--wordlist", metavar="FILE",
                     help="path to a username wordlist, one per line. AUGMENTS "
                          "the bundled 15-user VRFY/EXPN enumeration list.")
    _add_io(smp)
    _add_budget(smp)
    smp.set_defaults(func=_h("smtp"))

    # DNS enumeration.
    dnp = sub.add_parser("dns",
                         help="DNS: attempt zone transfer (AXFR) for each discovered "
                              "domain + version.bind (53) - AXFR leaks the whole zone")
    dnp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "DNS hosts in the datastore)")
    dnp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(dnp)
    _add_budget(dnp)
    dnp.set_defaults(func=_h("dns"))

    # Elasticsearch enumeration.
    ep = sub.add_parser("elasticsearch", aliases=["es", "elastic"],
                        help="Elasticsearch: unauthenticated HTTP probe (9200/9201) -> "
                             "CONFIRM /_cat/indices without auth = critical data exposure")
    ep.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                         "Elasticsearch hosts in the datastore)")
    ep.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    _add_io(ep)
    _add_budget(ep)
    ep.set_defaults(func=_h("elasticsearch"))

    # memcached enumeration.
    mcp = sub.add_parser("memcached", aliases=["memcache"],
                         help="memcached: text-protocol probe (11211) -> CONFIRM `stats` "
                              "without auth = unauthenticated data exposure + amplification")
    mcp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "memcached hosts in the datastore)")
    mcp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(mcp)
    _add_budget(mcp)
    mcp.set_defaults(func=_h("memcached"))

    # CouchDB enumeration.
    cdp = sub.add_parser("couchdb", aliases=["couch"],
                         help="CouchDB: HTTP probe (5984/6984) -> CONFIRM /_all_dbs + "
                              "admin-party config without auth = critical exposure (RCE)")
    cdp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "CouchDB hosts in the datastore)")
    cdp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(cdp)
    _add_budget(cdp)
    cdp.set_defaults(func=_h("couchdb"))

    # InfluxDB enumeration.
    idp = sub.add_parser("influxdb", aliases=["influx"],
                         help="InfluxDB: /ping version + SHOW DATABASES (8086) -> CONFIRM "
                              "unauth query API (default) + <1.7.6 JWT bypass")
    idp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "InfluxDB hosts in the datastore)")
    idp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(idp)
    _add_budget(idp)
    idp.set_defaults(func=_h("influxdb"))

    # Cassandra enumeration.
    cap = sub.add_parser("cassandra", aliases=["cql", "scylla"],
                         help="Cassandra: CQL native-protocol probe (9042) -> CONFIRM "
                              "STARTUP READY without auth = no-auth exposure (UDF RCE)")
    cap.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "Cassandra hosts in the datastore)")
    cap.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(cap)
    _add_budget(cap)
    cap.set_defaults(func=_h("cassandra"))

    # Oracle TNS enumeration.
    orp = sub.add_parser("oracle", aliases=["tns"],
                         help="Oracle: TNS-listener probe (1521/1522) -> CONFIRM the "
                              "listener + leak version (SID brute / TNS Poison surface)")
    orp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "Oracle hosts in the datastore)")
    orp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(orp)
    _add_budget(orp)
    orp.set_defaults(func=_h("oracle"))

    # IBM Db2 (DRDA) enumeration.
    dbp = sub.add_parser("db2", aliases=["drda"],
                         help="Db2: DRDA/DDM EXCSAT probe (50000) -> CONFIRM the endpoint "
                              "+ read class name / release level (version disclosure)")
    dbp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all "
                          "Db2 hosts in the datastore)")
    dbp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(dbp)
    _add_budget(dbp)
    dbp.set_defaults(func=_h("db2"))

    # rsync-daemon enumeration.
    syp = sub.add_parser("rsync",
                         help="rsync daemon: list modules (873) + prove anonymous "
                              "access = CONFIRMED unauthenticated file exposure")
    syp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: "
                          "all rsync hosts in the datastore)")
    syp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(syp)
    _add_budget(syp)
    syp.set_defaults(func=_h("rsync"))

    # NFS / mountd enumeration.
    nfp = sub.add_parser("nfs", aliases=["showmount"],
                         help="NFS: ONC RPC portmapper + mountd export list (showmount "
                              "-e) -> world-mountable export = CONFIRMED exposure")
    nfp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: "
                          "all NFS hosts in the datastore)")
    nfp.add_argument("--no-probe", action="store_true",
                     help="skip the live probe; just write the commands")
    _add_io(nfp)
    _add_budget(nfp)
    nfp.set_defaults(func=_h("nfs"))

    # Credential-less Kerberos AS-REP roasting + user enumeration.
    kp = sub.add_parser("kerberos", aliases=["asrep", "asreproast"],
                        help="credential-less AD roasting: AS-REP roast pre-auth-disabled "
                             "accounts + validate usernames via the KDC (no creds, port 88)")
    kp.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file")
    kp.add_argument("--dc-ip", dest="dc_ip", default="",
                    help="domain controller IP (default: a host with port 88 open)")
    kp.add_argument("-d", "--domain", default="",
                    help="Kerberos realm / AD domain (e.g. CORP.LOCAL)")
    kp.add_argument("--userlist",
                    help="file of candidate usernames, one per line (default: the "
                         "user accounts recce already enumerated)")
    kp.add_argument("--user", action="append",
                    help="test a single username (repeatable)")
    kp.add_argument("--no-probe", action="store_true",
                    help="skip the live probe; just write the commands")
    _add_io(kp)
    _add_budget(kp)
    kp.set_defaults(func=_h("kerberos"))

    # ── T4 scanner-expansion services ────────────────────────────────────
    # Every entry follows the same pattern: targets nargs='*' + --no-probe +
    # standard IO + budget. Each maps to its cmd_<name> handler in
    # cli/_services.py which delegates to _run_service_scan.
    def _add_t4(name, help_txt, *aliases):
        p = sub.add_parser(name, aliases=list(aliases), help=help_txt)
        p.add_argument("targets", nargs="*",
                       help="restrict to these IPs / ranges / CIDRs / @file "
                            "(default: all matching hosts in the datastore)")
        p.add_argument("--no-probe", action="store_true",
                       help="skip the live probe; just write the commands")
        _add_io(p); _add_budget(p)
        p.set_defaults(func=_h(name.replace("-", "_")))
        return p
    _add_t4("zookeeper",       "Zookeeper 4LW probe: ruok/stat + dumping (dump/conf/cons) + admin (wchc/wchp) — leaks_data flag = HIGH")
    _add_t4("kafka",           "Kafka native MetadataRequest v1 probe: broker + topic enum without auth")
    _add_t4("etcd",            "etcd v2 + v3 unauthenticated read probe (TLS auto-fallback)")
    _add_t4("consul",          "Consul HTTP API probe: services + KV + nodes, ACL-disabled = CRITICAL")
    _add_t4("nomad",           "Nomad HTTP API probe: jobs + allocations + nodes, ACL detection")
    _add_t4("prometheus",      "Prometheus API probe: config leak + query open + admin-writable /-/reload")
    _add_t4("docker-registry", "Docker Registry v2 anonymous /v2/_catalog probe (5000/tcp)", "dregistry")
    _add_t4("vnc",             "VNC RFB 3.x handshake: security-type list; no-auth (type 1) = CRITICAL")
    _add_t4("modbus",          "Modbus/TCP Function 0x03 Read Holding Registers + Function 0x2B Read Device ID")
    _add_t4("rdp",             "RDP X.224 Connection Request: NLA (Network Level Authentication) detection")
    _ipmi_p = _add_t4("ipmi", "IPMI 623/udp Get Channel Auth Capabilities: cipher-zero (CVE-2013-4786) + null-user + weak MD2/MD5, plus RMCP+ RAKP hash capture for hashcat -m 7300/-m 7302")
    # `--rakp-users` overrides the sweep list. Without it recce unions 8
    # vendor BMC defaults with users learned from AD enum / BloodHound / SNMP
    # / SMB SAMR (creds.known_users), capped so a big BloodHound import
    # doesn't translate to thousands of round-trips per BMC. Accepts
    # `user1,user2` or `@file.txt` (one per line).
    _ipmi_p.add_argument("--rakp-users", metavar="LIST",
                         help="RAKP username sweep list: `user1,user2` or "
                              "`@file.txt`. Overrides the auto-union of BMC "
                              "defaults + engagement-known users.")
    _add_t4("ntp",             "NTP 123/udp: monlist amplification + client disclosure (CVE-2013-5211), mode-6 readvar OS/version leak, peer list, Kerberos-breaking clock skew")
    _add_t4("msrpc",           "MSRPC 135/tcp: endpoint mapper dump + IOXIDResolver interface leak, PetitPotam/PrinterBug/DFSCoerce coercion targets")
    _add_t4("winrm",           "WinRM 5985/5986: unauth WSMan Identify (version + product), auth mechanisms advertised, TLS posture on 5986")
    _add_t4("netbios",         "NetBIOS Name Service 137/udp: node-status — hostname, workgroup/domain, DC role, interface MAC — unauth")
    _add_t4("tftp",            "TFTP 69/udp: unauth read of canonical vendor filenames (running-config, IOS images, phone provisioning)")
    _add_t4("ipp",             "IPP / CUPS 631/tcp: unauth CUPS-Get-Printers + CVE-2024-47176 (foomatic RCE chain) reachability")
    _add_t4("x11",             "X11 6000-6009/tcp: initial handshake — accepted = full screenshot/keylog/input access to the desktop")
    _add_t4("sip",             "SIP 5060: OPTIONS fingerprint — Server/User-Agent + realm disclosure, methods, PBX identification")
    _add_t4("rservices",       "Legacy Berkeley r-services 512/513/514: cleartext IP-trust auth — flagged categorically when present")

    sk = sub.add_parser("fieldkit-export",
                        help="export the engagement as a seed for the fieldkit "
                             "exploitation kit (gnmap + bridge JSON + attack plan)")
    sk.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_io(sk)
    sk.set_defaults(func=_h("fieldkit_export"))

    ski = sub.add_parser("fieldkit-import",
                         help="fold a fieldkit findings.json (proven exploitation) back "
                              "into the workbook + report")
    ski.add_argument("findings", help="path to a fieldkit findings.json or recce_findings.json")
    _add_io(ski)
    ski.set_defaults(func=_h("fieldkit_import"))

    # Pre-rename spellings (the kit was called Sköll) - hidden from --help, still functional.
    # (no `help=` at all: argparse only lists a subcommand when the kwarg is present,
    #  and it prints `help=SUPPRESS` literally rather than honouring it.)
    sk_old = sub.add_parser("skoll-export")
    sk_old.add_argument("targets", nargs="*")
    _add_io(sk_old)
    sk_old.set_defaults(func=_deprecated_alias(_h("fieldkit_export"),
                                               "skoll-export", "fieldkit-export"))

    ski_old = sub.add_parser("skoll-import")
    ski_old.add_argument("findings")
    _add_io(ski_old)
    ski_old.set_defaults(func=_deprecated_alias(_h("fieldkit_import"),
                                                "skoll-import", "fieldkit-import"))

    r = sub.add_parser("report", help="regenerate reports (preserves tracking)")
    _add_io(r)
    r.add_argument("--min-qod", type=int, default=None, metavar="N",
                   help="hide findings below this Quality-of-Detection score (0-100; "
                        "70 hides banner/version leads, 95 shows only verified). "
                        "Persists; --min-qod 0 shows all again.")
    r.add_argument("--show-refuted", dest="show_refuted", action="store_true", default=None,
                   help="include findings an NSE check reported NOT VULNERABLE (patched); "
                        "hidden by default. Persists until --no-show-refuted.")
    r.add_argument("--no-show-refuted", dest="show_refuted", action="store_false",
                   help="hide refuted findings again (the default).")
    r.set_defaults(func=_h("report"))

    rt = sub.add_parser("retest", help="compare the current engagement against a "
                                       "prior one and emit a per-finding verdict "
                                       "report (fixed / still-open / new)")
    _add_io(rt, title=False)
    rt.add_argument("--against", "--prev", dest="prev", required=True,
                    help="path to the previous engagement's directory (or its recce.db)")
    rt.add_argument("--out-name", default="retest_report.docx",
                    help="basename for the retest .docx (written into -o)")
    rt.set_defaults(func=_h("retest"))

    st = sub.add_parser("status", help="print live review coverage")
    _add_io(st, title=False)
    st.set_defaults(func=_h("status"))

    sv = sub.add_parser("serve", help="serve the web workbench (local, multi-tester) "
                                      "for this engagement")
    _add_io(sv, title=False)
    sv.add_argument("--host", default="0.0.0.0",
                    help="bind address (default 0.0.0.0 = reachable across the LAN)")
    sv.add_argument("--port", type=int, default=8008, help="port (default 8008)")
    # The workbench's own Pivot panel tells the operator to run
    # `recce serve --proxy socks5h://host:port` (webui/routes/manage.py), and the
    # proxy config is process-global - but `serve` does not take _add_common, so
    # this flag did not exist and that instruction exited 2 on "unrecognized
    # arguments". _setup_proxy() reads args.proxy via getattr, so defining it here
    # is all that was missing: serve re-execs under proxychains like any other run.
    sv.add_argument("--proxy", metavar="URL",
                    help="pivot: run the workbench (and every scan it launches) "
                         "through a proxy, e.g. socks5h://127.0.0.1:1080")
    sv.set_defaults(func=_h("serve"))

    nx = sub.add_parser("next", help="the ranked next-best-actions for an engagement")
    _add_io(nx, title=False)
    nx.set_defaults(func=_h("next"))

    act_p = sub.add_parser("act", help="the Act phase: found things -> ranked, guided "
                           "action plan (loot / crack / spray / exploit / escalate / pivot)",
                           description="Turn findings into a ranked action plan. Every "
                           "finding is classified into an action archetype and scored by "
                           "tier (what you can do now) then impact × confidence × leverage. "
                           "Read-only/reversible items are flagged as ones recce can run "
                           "for you; intrusive ones are guided (exact command), never "
                           "auto-fired.")
    _add_io(act_p, title=False)
    act_p.add_argument("--host", action="append", metavar="IP",
                       help="limit the plan to these host(s) (repeatable)")
    act_p.add_argument("--only", metavar="ARCHETYPE",
                       choices=["loot", "crack", "spray", "exploit", "escalate", "pivot",
                                "ad-path", "default-cred"],
                       help="show only this archetype")
    act_p.add_argument("--top", type=int, default=0, metavar="N",
                       help="cap the plan to the top N cards per tier")
    act_p.add_argument("--run", action="store_true",
                       help="auto-execute the read-only/reversible links (loot the "
                            "flagged unauth services, regenerate the spray plan) and feed "
                            "the yields back; intrusive actions are never auto-run")
    act_p.set_defaults(func=_h("act"))

    atk = sub.add_parser("attack", help="MITRE ATT&CK coverage: findings mapped to "
                         "techniques, grouped by tactic")
    _add_io(atk, title=False)
    atk.add_argument("--host", action="append", metavar="IP",
                     help="limit to these host(s) (repeatable)")
    atk.set_defaults(func=_h("attack"))

    vf = sub.add_parser("verify", help="confirm/refute version leads by re-running their "
                                       "safe NSE check (dry-run; --run to execute)")
    _add_io(vf, title=False)
    vf.add_argument("--run", action="store_true",
                    help="actually run the safe (Tier-A/B) re-checks (sends traffic); "
                         "default is a dry-run plan that sends nothing")
    vf.add_argument("--title", default="Recce Engagement")
    vf.set_defaults(func=_h("verify"))

    ax = sub.add_parser("access",
                        help="record / review initial access (footholds) per host - "
                             "auto-derived from credentialed enum, or record your own")
    ax.add_argument("targets", nargs="*",
                    help="restrict the listing to these IPs / ranges / CIDRs / @file")
    _add_io(ax)
    ax.add_argument("--host", nargs="*",
                    help="record a foothold on this IP (or --undo to clear it)")
    ax.add_argument("--note", help="how access was gained (shown in the report)")
    ax.add_argument("--undo", action="store_true",
                    help="with --host, clear the recorded foothold")
    ax.set_defaults(func=_h("access"))

    rv = sub.add_parser("review", help="mark items reviewed / not reviewed")
    _add_io(rv)
    rv.add_argument("--host", nargs="*", help="host IP(s) to mark")
    rv.add_argument("--service", nargs="*", metavar="IP:PORT", help="service(s) to mark")
    rv.add_argument("--key", nargs="*", help="raw tracking key(s) to mark")
    rv.add_argument("--cascade", action="store_true",
                    help="with --host, also mark that host's services")
    rv.add_argument("--note", help="attach a note to the marked items")
    rv.add_argument("--undo", action="store_true", help="un-review instead of review")
    rv.set_defaults(func=_h("review"))

    d = sub.add_parser("demo", help="build reports from bundled sample scan (offline)")
    d.add_argument("-o", "--output-dir", default="demo_engagement")
    d.set_defaults(func=_h("demo"))

    doc = sub.add_parser("doctor", help="check this box can run the tool (env + tools + self-scan)")
    doc.add_argument("--no-self-scan", action="store_true",
                     help="skip the real localhost self-scan")
    doc.set_defaults(func=_h("doctor"))

    ed = sub.add_parser("encdec", aliases=["cyber"],
        help="encode/decode toolbox — base64 / url / hex / hash / JWT / gzip / XOR / …")
    ed.add_argument("op", nargs="?",
        help="Operation name (base64-decode, hex-encode, jwt-decode, sha256, …). "
             "Use --list to see the full catalogue.")
    ed.add_argument("input", nargs="?",
        help="Input text. Reads from stdin if omitted.")
    ed.add_argument("-k", "--key", default="",
        help="Key argument for keyed ops (HMAC, XOR, rot-n).")
    ed.add_argument("--list", action="store_true",
        help="Print the full op catalogue and exit.")
    ed.add_argument("--chain", nargs="+", metavar="OP",
        help="Pipe input through a sequence of ops (each stage's output feeds "
             "the next). Keyed ops in a chain use --key for all steps that "
             "need one — use the API for per-step keys.")
    ed.set_defaults(func=_h("encdec"))

    ls = sub.add_parser("loot-scan", aliases=["scan-evidence"],
        help="Scan <engagement>/evidence/** for Kerberos tickets, credential "
             "files, .git dumps, and configs with embedded secrets — folds "
             "findings into the engagement.")
    ls.add_argument("--dry-run", action="store_true",
        help="Print what WOULD be added, but don't persist to the store.")
    _add_io(ls)
    ls.set_defaults(func=_h("loot_scan"))

    sq = sub.add_parser("sqli",
        help="Active SQL injection tester (C5 — GATED attack tier). "
             "Runs error-based + boolean-blind + time-based checks against "
             "URL parameters. Refuses to run without --active-attacks.")
    sq.add_argument("targets", nargs="*",
        help="URL(s) to test — parameters get auto-injected. Example: "
             "'http://target/vulnerable.php?id=1'")
    sq.add_argument("--active-attacks", action="store_true",
        help="REQUIRED — acknowledge that recce will send injection "
             "payloads to the target(s). No-op safety gate.")
    sq.add_argument("--sqlmap", action="store_true",
        help="Hand off to sqlmap for deeper testing (needs sqlmap installed).")
    _add_io(sq)
    sq.set_defaults(func=_h("sqli"))

    return p


_QUICKSTART = r"""
recce - phased enumeration & reporting. New to this? Open QUICKSTART.md for the
plain-English walkthrough. In ONE command:

  recce run <targets> -o eng     discover -> enum -> vulns -> every applicable deep
                                 module -> report. Add -u USER -p PASS -d DOMAIN to
                                 also run the authenticated SMB/AD/mssql modules.

Then, any time (the core loop):

  recce next   -o eng            the single best next step, from what's been found
  recce verify --run -o eng      confirm/refute version leads with a safe re-check
  recce status -o eng            coverage + what's left   (open eng/enumeration.xlsx)
  recce report -o eng            regenerate the workbook / write-ups

Prefer a browser, or working as a team?

  recce serve  -o eng            the web workbench at http://<this-box>:8008 - run
                                 scans, triage findings, spray looted creds, export
                                 the report; the whole team shares one live view
                                 over the LAN. (--host/--port to change the bind.)

Interrupted? Re-run the command (add --resume to skip finished hosts) or `recce next`
- nothing dead-ends.

Surgical (focus one thing): recce web|smb|ftp|ldap|snmp|mongodb|redis|elasticsearch|
rsync|nfs|kerberos|docker|k8s|mssql -o eng  (add -u/-p/-d for authenticated depth),
plus enum|vulns|sweep|credsweep|ingest|deploy|import. Run `recce <command> -h`.

Already have an nmap scan?   recce import scan.xml -o eng   (no scanning)
First time on this box?      recce doctor
SharpHound / Certipy data?   recce ad loot.zip certipy.json -u USER -p PASS -d DOMAIN
                             (AD vulns + ESC findings + paths to Domain Admin)
Have a complete IP/hostname list?  recce enum @scope.txt --targets-up
                             (lines: 'IP hostname'; pre-seeds every host so a
                             timeout never drops a real target from the report)

Targets: a single IP, several IPs, a range (10.0.0.10-40), a CIDR, or @file.
Hosts blocking ping (firewalled / Windows / AD)?  add  -Pn  to enum/scan.
Run scans with sudo for SYN + OS detection.  `recce <command> -h` for options.
"""


def _print_quickstart() -> int:
    from .helpers import BANNER
    print(BANNER)
    print(_QUICKSTART)
    return 0


def _setup_proxy(args) -> int | None:
    """Handle --proxy / auto-detect. Returns an exit code to stop, or None to continue.

    Explicit --proxy: verify proxychains + the tunnel, then re-exec recce under
    proxychains so its whole process tree is proxied (unless already wrapped). A run that
    is already under proxychains (our re-exec, or the operator's own wrap) just switches
    on safe/honest mode. See docs/design/PROXY-PIVOT.md."""
    from ..core import proxy
    url = getattr(args, "proxy", None)
    if not url and not proxy.already_proxied():
        return None                              # the common, direct path: nothing to do
    if not url:                                  # wrapped in proxychains but no --proxy
        proxy.configure_detected()               # auto-enable safe/honest mode
        print(proxy.banner_line())
        return None
    try:
        cfg = proxy.configure(url)
    except proxy.ProxyError as e:
        print(f"[x] --proxy: {e}")
        return 2
    if proxy.already_proxied():                  # we ARE the re-exec'd child (or wrapped)
        print(proxy.banner_line())
        return None
    if not proxy.proxychains_bin():
        print("[x] --proxy needs proxychains4 (not on PATH). Install it, or use a "
              "transparent tunnel (ligolo/sshuttle) and run recce without --proxy.")
        return 2
    if not proxy.reachable(cfg):
        print(f"[x] --proxy: can't reach {proxy.describe()} - is the pivot/tunnel up?")
        return 2
    out = getattr(args, "output_dir", None) or "."
    try:
        os.makedirs(out, exist_ok=True)
        conf = proxy.write_proxychains_conf(cfg, os.path.join(out, ".proxychains.conf"))
    except OSError as e:
        print(f"[x] --proxy: could not write proxychains conf: {e}")
        return 2
    print(proxy.banner_line())
    print(f"    re-executing under proxychains4 so all traffic tunnels via "
          f"{proxy.describe()} ...")
    proxy.reexec_under_proxychains(conf)         # replaces this process on success
    print("[x] --proxy: failed to re-exec under proxychains4")
    return 2


