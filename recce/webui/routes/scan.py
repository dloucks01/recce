"""Scan jobs + live progress + the command catalog."""
from __future__ import annotations

import asyncio
import json

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from ..jobs import recce_argv
from .._common import _COMMANDS
from .chain_rules import CHAIN_RULE_CALLABLES
# Re-exported so tests that reach in as ``scan_mod._CHAIN_RULES`` still find
# the catalog after the extraction into ``chain_rules.py``.
from .chain_rules import _CHAIN_RULES as _CHAIN_RULES  # noqa: F401 (re-export)


# ---------------------------------------------------------------------------
# "recce suggests…" rules.  Each rule reads one shared-surface module and
# turns its facts into zero-or-more suggestion dicts of shape:
#   {"key": stable_id, "command": <catalog cmd or "">, "field": <field or "">,
#    "suggested_value": str, "reason": str, "confidence": "high|medium|low",
#    "source": <reader module name>, "external_cmd": <optional shell hint>}
# Rules are import-tolerant: a missing reader module is skipped, not fatal.
# ---------------------------------------------------------------------------

# Commands that carry a `--domain` field wired to the `domain` form input.
# The set is closed to catalog entries with `creds=True` so the frontend's
# Prefill can safely dispatch onto the existing form-state.
_DOMAIN_TARGETS = ("credenum", "certipy", "smb", "ldap", "ftp", "db",
                   "credsweep", "postgres", "mysql", "mssql", "mongodb")

# Commands that carry a `--user`/`username` field wired to the `username`
# form input.  Same closed-set rule as _DOMAIN_TARGETS.
_USER_TARGETS = ("credenum", "certipy", "smb", "ldap", "ftp",
                 "credsweep", "postgres", "mysql", "mssql", "mongodb")

# (protocol slug, matching OT vendor keyword hint).  Rule 6 emits one
# suggestion per OT protocol against every host that carries that asset
# family so the operator can rerun s7/opcua/bacnet/... against known-good
# targets in one click.
_OT_SWEEP_MAP = {
    "s7":     ("siemens",),
    "opcua":  ("opc", "kepware", "opc-ua"),
    "bacnet": ("bacnet", "delta", "honeywell", "johnson"),
    "dnp3":   ("dnp3",),
    "iec104": ("iec-104", "iec104"),
    "enip":   ("rockwell", "allen-bradley", "ethernetip"),
}


# Backlog fix: the /api/scan/context lookup used to walk `dir(mod)` for
# any public `*_targets` name as a fallback when the canonical
# `<cmd>_targets` wasn't present. That fallback was fragile — a
# class-nested helper named `SomeSpec._targets` inside a module could
# silently shadow the module's real targets fn, and the qualname
# dot-check was the only guard. Every service module now either
# defines the canonical `<cmd>_targets` directly or aliases its
# short-form name to the canonical (see e.g. `zookeeper_targets =
# zk_targets` in zookeeper.py). The fallback + its `_module_scoped_check`
# helper are gone.


def _rule_domain(hosts, creds, loot_dir):          # noqa: ARG001
    """known_domains → --domain prefill for credentialed commands."""
    try:
        from ...core.known_domains import known_domains
    except ImportError:
        return []
    kd = known_domains(hosts, creds)
    primary = (kd.get("primary_dns") or "").strip()
    if not primary:
        return []
    realm = primary.upper()
    # One suggestion, not one-per-command: prefill the realm into `credsweep`
    # (runs every credentialed module). Emitting a near-identical row for each of
    # the 11 credentialed commands just floods the panel with dupes.
    reason = (f"Learned AD realm `{primary}` from NTLM/LDAP enumeration across "
              f"{kd.get('total_known', 0)} host(s) — run the credentialed sweep "
              f"with --domain {realm}.")
    return [{"key": f"domain-credsweep-{realm}", "command": "credsweep",
             "field": "domain", "suggested_value": realm, "reason": reason,
             "confidence": "high", "source": "known_domains"}]


def _rule_admin_user(hosts, creds, loot_dir):      # noqa: ARG001
    """known_users → --user prefill for the first admincount=1 principal."""
    try:
        from ...creds.known_users import collect_user_accounts
    except ImportError:
        return []
    admins = [a for a in collect_user_accounts(hosts)
              if (a.get("attrs") or {}).get("admincount")
              or a["priority"] == 0]           # _priority(0) == admin bucket
    if not admins:
        return []
    name = admins[0]["name"]
    # Single row (prefill the credentialed sweep), not one per credentialed cmd.
    reason = (f"`{name}` is flagged adminCount=1 (or well-known-admin) — prefer it "
              f"for authenticated checks; prefilled into the credentialed sweep.")
    return [{"key": f"user-credsweep-{name.lower()}", "command": "credsweep",
             "field": "username", "suggested_value": name, "reason": reason,
             "confidence": "high", "source": "known_users"}]


# Hash category (as known_hashes reports it) -> hashcat -m mode, so the crack
# command comes prefilled with the right mode instead of a <mode> placeholder.
_HASHCAT_MODE = {
    "nthash": "1000", "ntlm": "1000", "ntlmv1": "5500", "netntlmv1": "5500",
    "ntlmv2": "5600", "netntlmv2": "5600", "net-ntlmv2": "5600",
    "krb5tgs": "13100", "kerberoast": "13100", "krb5asrep": "18200", "asrep": "18200",
    "md5": "0", "sha1": "100", "sha256": "1400", "sha512": "1700",
    "bcrypt": "3200", "sha512crypt": "1800", "md5crypt": "500",
    "mscache2": "2100", "dcc2": "2100", "lm": "3000",
}


def _rule_hashes_potfile(hosts, creds, loot_dir):  # noqa: ARG001
    """known_hashes > 0 → surface the hashcat + `recce creds --potfile` handoff."""
    try:
        from ...creds.known_hashes import known_hashes
    except ImportError:
        return []
    r = known_hashes(creds, loot_dir=loot_dir)
    if not r.get("total"):
        return []
    categories = r.get("categories") or {}
    cats = ", ".join(sorted(categories)) or "nthash"
    total = r["total"]
    # Fill -m from the (single) hash category; leave <mode> only when it's mixed
    # so the operator picks. loot dir is a known path — fill it instead of <eng>.
    modes = {_HASHCAT_MODE[c.lower()] for c in categories if c.lower() in _HASHCAT_MODE}
    mode = modes.pop() if len(modes) == 1 else "<mode>"
    loot = (loot_dir or "loot").rstrip("/")
    reason = (f"{total} crackable hash(es) captured ({cats}). Crack with "
              f"hashcat against `{loot}/*.hash`, then feed the potfile "
              f"back with `recce creds --potfile <pot>`.")
    return [{"key": f"hashes-potfile-{total}", "command": "",
             "field": "", "suggested_value": "",
             "external_cmd": f"hashcat -m {mode} {loot}/*.hash <wordlist>",
             "reason": reason, "confidence": "medium", "source": "known_hashes"}]


def _rule_relay_targets(hosts, creds, loot_dir):   # noqa: ARG001
    """relay_targets → ntlmrelayx handoff (external tool)."""
    try:
        from ...core.relay_targets import relay_target_lines
    except ImportError:
        return []
    lines = relay_target_lines(hosts)
    if not lines:
        return []
    reason = (f"{len(lines)} SMB host(s) accept unsigned sessions — a coerced "
              f"NTLM auth would relay. Write the list to a file and run "
              f"`ntlmrelayx -tf targets.txt -smb2support`.")
    return [{"key": f"relay-ntlmrelayx-{len(lines)}", "command": "",
             "field": "", "suggested_value": "",
             "external_cmd": f"ntlmrelayx.py -tf targets.txt -smb2support   # {len(lines)} target(s)",
             "reason": reason, "confidence": "high", "source": "relay_targets"}]


def _rule_ot_sweep(hosts, creds, loot_dir):        # noqa: ARG001
    """known_ot_assets → per-protocol sweep against learned OT IPs."""
    try:
        from ...core.known_ot_assets import known_ot_assets
    except ImportError:
        return []
    kot = known_ot_assets(hosts)
    if not kot.get("assets"):
        return []
    out: list[dict] = []
    # Group learned assets by (vendor keyword → protocol slug).  A single
    # asset can qualify for more than one protocol (e.g. Rockwell → enip)
    # but the resulting suggestion is keyed on (protocol, ip) so duplicates
    # collapse via the caller's dedup.
    by_ip: dict[str, list[str]] = {}
    for a in kot["assets"]:
        vendor = (a.get("vendor") or "").lower()
        ip = a.get("ip", "")
        if not ip:
            continue
        for slug, hints in _OT_SWEEP_MAP.items():
            if any(h in vendor for h in hints):
                by_ip.setdefault(slug, []).append(ip)
    for slug, ips in by_ip.items():
        ips = sorted(set(ips))
        out.append({"key": f"ot-{slug}-{','.join(ips[:4])}",
                    "command": slug, "field": "targets",
                    "suggested_value": ", ".join(ips),
                    "reason": (f"Learned {len(ips)} {slug.upper()} asset(s) via OT "
                               f"fingerprint — run the deep {slug} probe against them."),
                    "confidence": "high", "source": "known_ot_assets"})
    return out


def _rule_devices_vulns(hosts, creds, loot_dir):   # noqa: ARG001
    """known_devices w/ cve_candidates → suggest a targeted vulns rescan."""
    try:
        from ...core.known_devices import known_devices
    except ImportError:
        return []
    kd = known_devices(hosts)
    cves = kd.get("cve_candidates") or []
    if not cves:
        return []
    ips = sorted({(c.get("device") or {}).get("ip", "") for c in cves})
    ips = [ip for ip in ips if ip]
    if not ips:
        return []
    vendors = sorted({(c.get("device") or {}).get("vendor", "")
                      for c in cves if (c.get("device") or {}).get("vendor")})
    reason = (f"{len(cves)} CVE candidate(s) inferred from device fingerprints "
              f"({', '.join(vendors[:3]) or 'vendor'}) — rerun vulns against "
              f"the affected {len(ips)} host(s).")
    return [{"key": f"vulns-devices-{','.join(ips[:4])}", "command": "vulns",
             "field": "targets", "suggested_value": ", ".join(ips),
             "reason": reason, "confidence": "medium",
             "source": "known_devices"}]


def _rule_mail_cross_transport(hosts, creds, loot_dir):  # noqa: ARG001
    """known_mail_accounts → cross-transport spray on smtp/imap/pop3."""
    try:
        from ...creds.known_mail_accounts import known_mail_accounts
    except ImportError:
        return []
    km = known_mail_accounts(hosts)
    accounts = km.get("accounts") or []
    if not accounts:
        return []
    ips = sorted({ip for a in accounts for ip in (a.get("hosts") or [])})
    if not ips:
        return []
    users_n = len(km.get("by_user") or {})
    out = []
    for cmd in ("smtp", "imap", "pop3"):
        out.append({"key": f"mail-{cmd}-{','.join(ips[:3])}",
                    "command": cmd, "field": "targets",
                    "suggested_value": ", ".join(ips),
                    "reason": (f"{users_n} mail identit(y|ies) learned across "
                               f"{len(ips)} host(s) — spray the same names "
                               f"through {cmd.upper()} for cross-transport reuse."),
                    "confidence": "medium",
                    "source": "known_mail_accounts"})
    return out


def _rule_hostkey_reuse(hosts, creds, loot_dir):   # noqa: ARG001
    """known_hostkeys reuse → info-only cluster hint (appliance / golden image)."""
    try:
        from ...core.known_hostkeys import known_hostkeys
    except ImportError:
        return []
    reused = (known_hostkeys(hosts) or {}).get("reused") or []
    if not reused:
        return []
    first = reused[0]
    ips = first.get("ips") or []
    reason = (f"SSH host-key reused across {len(ips)} distinct host(s) "
              f"({', '.join(ips[:4])}{'…' if len(ips) > 4 else ''}) — "
              f"appliance family or golden-image clone; a shared credential "
              f"or SSH key almost certainly rides along.")
    return [{"key": f"hostkey-reuse-{first.get('fingerprint', '')[:16]}",
             "command": "", "field": "", "suggested_value": "",
             "reason": reason, "confidence": "medium",
             "source": "known_hostkeys"}]


def _rule_hostname_vhosts(hosts, creds, loot_dir):  # noqa: ARG001
    """known_hostnames (FQDN) + web endpoints → suggest scanning by FQDN."""
    try:
        from ...core.known_hostnames import known_hostnames
    except ImportError:
        return []
    web_hosts = {h.ip for h in hosts
                 for p in (h.open_ports or [])
                 if (p.service or "").lower().startswith("http")
                 or p.portid in (80, 443, 8080, 8443)}
    if not web_hosts:
        return []
    names = known_hostnames(hosts, only_fqdn=True)
    by_host = names.get("by_host") or {}
    picks = [(ip, n[0]) for ip, n in by_host.items() if ip in web_hosts and n]
    if not picks:
        return []
    fqdns = sorted({n for _ip, n in picks})[:4]
    reason = (f"{len(fqdns)} FQDN(s) learned for HTTP host(s) — re-run web "
              f"enumeration by name to hit vhost-scoped content that IP-only "
              f"scans miss.")
    return [{"key": f"web-vhost-{','.join(fqdns)}", "command": "web",
             "field": "targets", "suggested_value": ", ".join(fqdns),
             "reason": reason, "confidence": "medium",
             "source": "known_hostnames"}]


def _rule_t3_capable_findings(hosts, creds, loot_dir):  # noqa: ARG001
    """Vulns rated at (or one step below) the initial-access boundary →
    external-tool handoff card carrying the finding's exploit_note as the
    shell hint. Reads Vuln.depth_tier (T0-T4 rubric per core.depth):
    every t3 finding qualifies (any severity — t3 already means initial-
    access-capable), plus any t2 finding at critical/high severity."""
    try:
        from ...core.depth import rank as _tier_rank
    except ImportError:
        return []
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    picks: list = []
    for h in hosts or []:
        for v in (getattr(h, "vulns", None) or []):
            tier = (getattr(v, "depth_tier", "") or "").lower()
            sev = (getattr(v, "severity", "") or "").lower()
            if tier == "t3" or (tier == "t2" and sev in ("critical", "high")):
                picks.append(v)
    if not picks:
        return []
    picks.sort(
        key=lambda v: (
            _tier_rank((getattr(v, "depth_tier", "") or "").lower()),
            1 if getattr(v, "kev", False) else 0,
            _sev_rank.get((getattr(v, "severity", "") or "").lower(), 0),
            float(getattr(v, "epss", 0.0) or 0.0),
        ),
        reverse=True,
    )
    out: list[dict] = []
    for v in picks[:10]:
        tier = (getattr(v, "depth_tier", "") or "").lower()
        conf = ("high" if getattr(v, "kev", False)
                else ("medium" if tier == "t3" else "low"))
        out.append({
            "key": f"depth:{v.ip}:{v.port}:{v.script_id}",
            "command": "", "field": "", "suggested_value": "",
            "reason": (f"{v.title} on {v.ip}:{v.port} — "
                       f"depth-tier {v.depth_tier}, {v.severity} severity"),
            "confidence": conf, "source": "depth_tier_gate",
            "external_cmd": getattr(v, "exploit_note", "") or "",
        })
    return out


# Ordering here is load-bearing for the suggestion feed — the per-service
# rules run first, then the multi-trigger chain rules from chain_rules.py
# (identical order to _CHAIN_RULES) are appended verbatim.
_SUGGESTION_RULES = (
    _rule_domain,
    _rule_admin_user,
    _rule_hashes_potfile,
    _rule_relay_targets,
    _rule_ot_sweep,
    _rule_devices_vulns,
    _rule_mail_cross_transport,
    _rule_hostkey_reuse,
    _rule_hostname_vhosts,
    _rule_t3_capable_findings,
    *CHAIN_RULE_CALLABLES,
)


def _detected_count(cmd: str, hosts) -> int | None:
    """How many up hosts actually EXPOSE this command's service — i.e. have its port
    open (or a service name that matches). Distinct from the module target predicate,
    which for UDP/undetectable services counts every up host ("worth trying"). Returns
    None when we don't know the command's port (the long-tail modules), so the caller
    falls back to the predicate count for those."""
    from ...services import toolcmd
    dp = toolcmd._DEFAULT_PORTS.get(cmd)
    port = int(dp) if (dp and str(dp).isdigit()) else 0
    tok = cmd.replace("-", "").replace("_", "").lower()
    if not port and cmd not in toolcmd._DEFAULT_PORTS:
        return None                        # unknown port -> let the predicate count stand
    ips: set = set()
    for h in hosts:
        for p in (h.open_ports or []):
            svc = (p.service or "").lower().replace("-", "")
            if (port and p.portid == port) or (len(tok) >= 3 and tok in svc):
                ips.add(h.ip)
                break
    return len(ips)


def register_scan_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    jobs = ctx.jobs
    broker = ctx.broker

    @app.get("/api/commands")
    def list_commands():
        """The command surface the UI renders its runner from (grouped, with the fields/
        flags each command accepts). `tool_cmd` is the raw external-tool command +
        syntax the recce command wraps, so an operator can run the tool by hand."""
        from ...services import toolcmd
        from ...core.store import Store
        with Store(db_path) as st:
            hosts, creds = st.all_hosts(), st.all_credentials()
        domain = toolcmd.discovered_domain(hosts, creds)
        # No specific target at the palette level, so only domain-authenticated
        # commands prefill a (domain) credential; everything else keeps <user>/
        # <pass> placeholders rather than guess.
        return {k: {**{kk: v[kk] for kk in
                       ("label", "group", "targets", "profile", "creds", "lhost", "flags")},
                    "tool_cmd": toolcmd.for_command(k, creds=creds, domain=domain)}
                for k, v in _COMMANDS.items()}

    # Commands whose surface a plain TCP `enum` will never find, with the scan
    # that does find it. Without this a tester runs `recce ntp`, gets "no
    # targets", and has no way to know the reason is that 123 is UDP-only.
    _PREREQ = {
        "snmp": "SNMP is 161/udp — run `enum -U` (UDP sweep) first.",
        "ntp": "NTP is 123/udp — run `enum -U` (UDP sweep) first.",
        "ipmi": "IPMI is 623/udp — run `enum -U` (UDP sweep) first.",
        "modbus": "Modbus is 502/tcp but rarely in the default top-ports — "
                  "run `enum --all-ports` or scan 502 explicitly.",
        "winrm": "WinRM is 5985/5986 — outside the default top-ports on some profiles; "
                 "try `enum --all-ports` if the sweep missed it.",
        "netbios": "NetBIOS Name Service is 137/udp — run `enum -U` (UDP sweep) first.",
        "tftp": "TFTP is 69/udp — run `enum -U` (UDP sweep) first.",
        "ipp": "IPP/CUPS is 631/tcp — usually caught by the default sweep; try "
               "`enum` if not already run.",
        "x11": "X11 is 6000-6009/tcp — outside the default top-ports; try "
               "`enum --all-ports` or scan explicitly.",
        "sip": "SIP runs on both 5060/udp and 5060/tcp — a TCP-only sweep will miss "
               "many PBXes; run `enum -U` too.",
        "rservices": "The r-services (512/513/514) are outside the default sweep on "
                     "most profiles; scan explicitly if you suspect legacy Unix.",
    }

    # scan/context evaluates ~70 module target-predicates over every up-host — the
    # heaviest read in the tab. Cache the result per datastore mtime so repeated
    # Scan-tab opens (and its polling) don't recompute it; writes bump the mtime.
    _ctx_cache: dict = {"sig": None, "value": None}
    import threading as _threading
    _ctx_lock = _threading.Lock()

    def _scan_db_sig():
        sig = []
        for suffix in ("", "-wal"):
            try:
                sig.append(_os.stat(ctx.db_path + suffix).st_mtime_ns)
            except OSError:
                sig.append(0)
        return tuple(sig)

    @app.get("/api/scan/context")
    def scan_context():
        """Which discovered hosts qualify for each command.

        The targets field is free text, so a tester picking `mssql` has no way to
        know whether anything in the engagement even runs MSSQL. Counts come from
        each module's OWN `*_targets()` predicate rather than a port list copied
        into the web layer, so a module that changes what it matches cannot drift
        away from the hint shown here. Cached per datastore mtime (see above).
        """
        import importlib
        from ...cli._service_helpers import _MODULE_PATH
        from ...core.store import Store

        sig = _scan_db_sig()
        with _ctx_lock:
            if _ctx_cache["sig"] == sig and _ctx_cache["value"] is not None:
                return _ctx_cache["value"]

        with Store(ctx.db_path) as st:
            hosts = [h for h in st.all_hosts() if h.is_up]

        out: dict = {}
        for cmd, path in sorted(_MODULE_PATH.items()):
            try:
                mod = importlib.import_module(path)
            except ImportError:
                continue
            # Require the canonical `<slug>_targets(hosts)` (e.g.
            # `ldap_targets` for cmd "ldap") — modules whose short-form
            # name differs (elasticsearch → es_targets, zookeeper →
            # zk_targets, jenkins-jnlp → jnlp_targets, cups_lpd →
            # lpd_targets, nbd_ndmp → nbd_ndmp_targets union,
            # guacamole → guacd_targets, nisyp → nis_targets) alias
            # the canonical name in their own module. Modules with
            # NO targets predicate (kubernetes, api, cloud_metadata)
            # fall through this loop and are handled specially below.
            canonical = cmd.replace("-", "_") + "_targets"
            fn = getattr(mod, canonical, None)
            if not callable(fn):
                continue
            try:
                ips = sorted({t["ip"] for t in fn(hosts) if t.get("ip")})
            except Exception:                # noqa: BLE001 - a hint must never 500 the tab
                continue
            entry = {"count": len(ips), "sample": ips[:8]}
            # `count` above is the module's target predicate — for a UDP / otherwise
            # undetectable service (e.g. SNMP) that's every up host ("worth trying"),
            # which reads as if 100 hosts run it. Add `detected` = hosts where the
            # service's port is actually OPEN, so the chip can show the honest number
            # and keep the broad candidate set as a tooltip. Only when we know the
            # port (toolcmd default) — the long tail keeps the predicate count.
            det = _detected_count(cmd, hosts)
            if det is not None:
                entry["detected"] = det
            if not ips and cmd in _PREREQ:
                entry["hint"] = _PREREQ[cmd]
            elif not ips:
                entry["hint"] = (f"No host in this engagement exposes {cmd}. "
                                 "Run `enum` first, or scan a host directly.")
            out[cmd] = entry

        # web/api have no *_targets(): they apply to every discovered HTTP surface.
        web_ips = sorted({h.ip for h in hosts for p in h.open_ports
                          if (p.service or "").lower().startswith("http")
                          or p.portid in (80, 443, 8080, 8443, 8000, 8888)})
        for cmd in ("web", "api"):
            out[cmd] = {"count": len(web_ips), "sample": web_ips[:8],
                        **({} if web_ips else
                           {"hint": "No HTTP surface discovered yet — run `enum` first."})}
        result = {"hosts": len(hosts), "commands": out}
        with _ctx_lock:
            _ctx_cache.update(sig=sig, value=result)
        return result

    @app.get("/api/scan/suggestions")
    def scan_suggestions():
        """"recce suggests…" — facts learned across the engagement, framed as
        prefills the Scan tab can apply with one click.

        The 10 shared-surface readers (known_domains / known_users / known_hashes
        / known_hostnames / known_hostkeys / known_mail_accounts / known_devices /
        known_ot_assets / relay_targets / hashloot) collectively hold every fact
        recce has learned; each rule below turns one class of fact into a small
        suggestion dict the frontend can dedup (`key`) and prefill against.

        Each rule is import-tolerant — a missing shared-surface module means
        that rule skips, never a 500. Rules are individually tiny (<20 LOC each)
        and idempotent: the same fact produces the same `key`, so a dismissed
        suggestion stays dismissed across page reloads.
        """
        import os as _os

        from ...core.store import Store
        with Store(ctx.db_path) as st:
            hosts = st.all_hosts()
            try:
                creds = st.all_credentials()
            except Exception:                    # noqa: BLE001
                creds = []
        loot_dir = _os.path.join(ctx.eng_dir, "loot")

        suggestions: list[dict] = []
        seen_keys: set[str] = set()
        for rule in _SUGGESTION_RULES:
            try:
                for sug in rule(hosts, creds, loot_dir) or []:
                    k = sug.get("key")
                    if not k or k in seen_keys:
                        continue
                    seen_keys.add(k)
                    suggestions.append(sug)
            except Exception:                    # noqa: BLE001 — no rule may 500 the tab
                continue
        return {"suggestions": suggestions}

    @app.get("/api/wordlists")
    def list_wordlists(kind: str | None = None):
        """The bundled wordlist catalog. Frontend renders these as a
        dropdown next to the free-text `--wordlist FILE` input. `kind`
        query param filters to a single family (paths / creds / users) so
        the postgres card's dropdown doesn't show HTTP path lists."""
        from ...services.wordlists import list_bundled
        return {"wordlists": list_bundled(kind)}

    @app.post("/api/scan")
    def start_scan(body: dict = Body(...), x_tester: str = Header(default="someone")):
        # `command` (any catalog entry); `phase` kept for older clients.
        command = str(body.get("command") or body.get("phase") or "run")
        spec = _COMMANDS.get(command)
        if spec is None:
            raise HTTPException(400, f"unknown command {command!r}")
        # Targets: split on whitespace OR commas (the field placeholder invites
        # comma lists — "10.0.0.0/24, 10.0.0.5, hostname"). Empty tokens
        # dropped; anything starting with '-' dropped (no flag injection).
        import re as _re
        # Sorted so the same scan with targets in a different order produces the
        # same command string — the running-duplicate guard below is exact-match,
        # and reordered/whitespace-different targets should still be caught (#3).
        targets = sorted({t for t in _re.split(r"[\s,]+", str(body.get("targets", "")))
                          if t and not t.startswith("-")})
        if spec["targets"] == "required" and not targets:
            raise HTTPException(400, "this command needs targets")
        argv = [command, "-o", eng_dir]
        if spec["profile"]:
            profile = str(body.get("profile", "")).lower()
            if profile in ("quick", "standard", "thorough", "stealth"):
                argv += ["--profile", profile]
        if spec["creds"]:
            user = str(body.get("username", "")).strip()
            if user:
                argv += ["-u", user]
                pw = body.get("password")
                if pw not in (None, ""):
                    argv += ["-p", str(pw)]
                dom = str(body.get("domain", "")).strip()
                if dom:
                    argv += ["-d", dom]
        if spec["lhost"]:
            lh = str(body.get("lhost", "")).strip()
            if lh:
                argv += ["--lhost", lh]
        # Boolean flags: silent-drop anything not in the catalog.
        allowed = {f["name"]: f for f in spec["flags"]}
        for name in (body.get("flags") or []):
            f = allowed.get(name)
            if f and f.get("kind", "bool") == "bool" and f["flag"] not in argv:
                argv.append(f["flag"])
        # Value-carrying flags: `flag_values: {name: value}`. Splits list-kind
        # inputs on whitespace/commas so `--skip mssql,docker` becomes
        # `--skip mssql docker` (nargs='*' on the parser side).
        import re as _re
        used_list_flag = False
        for name, raw in (body.get("flag_values") or {}).items():
            f = allowed.get(name)
            if f is None or f.get("kind", "bool") == "bool":
                continue
            val = str(raw).strip()
            if not val:
                continue
            kind = f.get("kind", "bool")
            if kind == "int":
                try:
                    int(val)
                except ValueError:
                    # Don't silently drop a value the operator typed — a scan that
                    # differs from what they asked for is worse than an error (#4).
                    raise HTTPException(400, f"'{name}' expects a number, got {val!r}")
                argv += [f["flag"], val]
            elif kind == "list":
                toks = [t for t in _re.split(r"[\s,]+", val) if t and not t.startswith("-")]
                if toks:
                    argv += [f["flag"], *toks]
                    used_list_flag = True
            elif kind == "wordlist":
                # Same wire shape as "text"; the wordlist loader on the
                # backend resolves `bundled:<name>` to an on-disk path.
                # Refuse dash-leading values (no flag injection) and refuse
                # `bundled:<name>` where the name isn't in the registry —
                # a typo shouldn't silently degrade to "no wordlist".
                if val.startswith("-"):
                    continue
                if val.startswith("bundled:"):
                    from ...services.wordlists import BUNDLED_WORDLISTS
                    name = val[len("bundled:"):].strip()
                    known = {e["name"] for e in BUNDLED_WORDLISTS}
                    if name not in known:
                        continue                # bad bundled name → drop
                argv += [f["flag"], val]
            else:                                # "text"
                if not val.startswith("-"):
                    argv += [f["flag"], val]
        # Resume an interrupted run: skip hosts already enumerated in the datastore.
        # enum/scan accept --resume (sweep/vulns don't); silently ignore elsewhere.
        if bool(body.get("resume")) and command in ("enum", "scan"):
            argv.append("--resume")
        if spec["targets"] != "none":
            # `--` separator when a list-kind flag was used: those flags declare
            # nargs='*' on the parser side, so argparse would otherwise eat the
            # trailing target IP into the list (--skip mssql 10.0.0.1 → skip=
            # [mssql, 10.0.0.1], no target). The explicit terminator forces
            # argparse to stop consuming for the option and treat what follows
            # as positionals.
            if used_list_flag:
                argv.append("--")
            argv += targets
        label = f"{command} {' '.join(targets)}".strip()
        full_argv = recce_argv(*argv)
        full_cmd = " ".join(full_argv)
        for j in jobs.list():
            if j.status == "running" and j.cmd == full_cmd:
                raise HTTPException(409, "an identical scan is already running")

        # Auto-triggered per-service enum: when enum finishes discovery, chain the
        # deep sweep (every applicable service module, each self-skipping) so the
        # operator doesn't have to hand-launch each one. Opt-in per launch.
        then_sweep = bool(body.get("then_sweep")) and command == "enum"

        def _done(job):
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": label})
            if then_sweep and job.status == "done":
                try:
                    sj = jobs.start(recce_argv("sweep", "-o", eng_dir),
                                    on_done=lambda j: broker.publish(
                                        {"type": "scan", "status": j.status,
                                         "tester": x_tester, "targets": "deep sweep (auto)"}))
                    broker.publish({"type": "scan_started", "tester": x_tester,
                                    "targets": "deep sweep (auto after enum)", "id": sj.id})
                except Exception:  # noqa: BLE001 — a full job queue must not crash the callback
                    broker.publish({"type": "scan", "status": "skipped", "tester": x_tester,
                                    "targets": "auto deep-sweep skipped (job queue full)"})

        job = jobs.start(full_argv, on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

    # --- custom nmap: the tester's own scan, folded into the engagement ----------
    import os as _os
    import shlex as _shlex
    import shutil as _shutil
    import time as _time

    _NMAP_OUT_FLAGS = {"-oX", "-oN", "-oG", "-oS", "-oA"}

    def _sanitize_nmap_args(raw: list[str]) -> list[str]:
        """Drop output/redirect flags so recce owns where results go (parseable +
        resumable) and the tester can't write to arbitrary paths. The job runs the
        argv list-form (no shell), so there's no command-injection surface beyond
        this — a missing/odd nmap flag just makes nmap error, which the job shows."""
        out: list[str] = []
        skip = False
        for tok in raw:
            if skip:
                skip = False
                continue
            key = tok.split("=", 1)[0]            # normalise --datadir=/x to --datadir
            if key in _NMAP_OUT_FLAGS or key in ("--stylesheet", "--datadir", "--resume"):
                skip = "=" not in tok             # bare form drops its value too; --flag=val is self-contained
                continue
            if any(tok.startswith(p) for p in _NMAP_OUT_FLAGS):
                continue                          # joined form, e.g. -oXout
            out.append(tok)
        return out

    @app.post("/api/scan/nmap")
    def start_nmap(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Run a tester-specified nmap scan and fold results into the engagement.
        recce owns the -oX/-oG output (parseable + resumable); `resume` continues an
        interrupted scan from its greppable log."""
        if not _shutil.which("nmap"):
            raise HTTPException(400, "nmap not found on PATH")
        scans_dir = _os.path.join(eng_dir, "nmap-custom")
        _os.makedirs(scans_dir, exist_ok=True)
        resume = str(body.get("resume", "")).strip()
        if resume:
            gnmap = _os.path.join(scans_dir, _os.path.basename(resume))   # basename: no path escape
            if not (gnmap.endswith(".gnmap") and _os.path.isfile(gnmap)):
                raise HTTPException(400, "resume log not found")
            xml = gnmap[:-len(".gnmap")] + ".xml"
            argv = ["nmap", "--resume", gnmap]
            label = f"nmap --resume {_os.path.basename(gnmap)}"
        else:
            try:
                raw = _sanitize_nmap_args(_shlex.split(str(body.get("args", ""))))
            except ValueError:
                raise HTTPException(400, "could not parse the nmap arguments")
            if not raw:
                raise HTTPException(400, "enter nmap arguments and target(s)")
            base = _os.path.join(scans_dir, "scan-" + _time.strftime("%Y%m%d-%H%M%S"))
            xml, gnmap = base + ".xml", base + ".gnmap"
            argv = ["nmap", *raw, "-oX", xml, "-oG", gnmap]
            label = "nmap " + " ".join(raw)

        def _fold(job):
            folded = 0
            try:
                from ...core import parser as _np
                from ...core.store import Store
                if _os.path.isfile(xml):
                    hosts = _np.parse_nmap_xml(xml)
                    with Store(db_path) as st:
                        for h in hosts:
                            st.upsert_host(h, merge=True)   # merge: never clobber prior scans
                    folded = len(hosts)
            except Exception:  # noqa: BLE001 — folding must never crash the callback
                pass
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": label, "folded": folded,
                            "gnmap": _os.path.basename(gnmap)})

        try:
            job = jobs.start(argv, on_done=_fold)
        except Exception as e:  # noqa: BLE001 — e.g. TooManyJobs
            raise HTTPException(409, str(e))
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
        return {"id": job.id, "status": job.status, "cmd": job.cmd,
                "gnmap": _os.path.basename(gnmap)}

    @app.get("/api/scan/nmap/logs")
    def nmap_logs():
        """Greppable logs from past custom nmap runs — each resumable via --resume.
        `complete` flags a scan that already finished (nothing to resume)."""
        scans_dir = _os.path.join(eng_dir, "nmap-custom")
        out = []
        if _os.path.isdir(scans_dir):
            for fn in sorted(_os.listdir(scans_dir), reverse=True):
                if not fn.endswith(".gnmap"):
                    continue
                p = _os.path.join(scans_dir, fn)
                try:
                    complete = "# Nmap done" in open(p, errors="replace").read()[-4000:]
                except OSError:
                    complete = False
                out.append({"gnmap": fn, "complete": complete,
                            "mtime": int(_os.path.getmtime(p))})
        return {"items": out[:50]}

    @app.post("/api/jobs/{jid}/cancel")
    def cancel_job(jid: str):
        if not jobs.cancel(jid):
            raise HTTPException(404, "no running job with that id")
        return {"ok": True}

    @app.get("/api/jobs")
    def list_jobs():
        # P7-C5: expose `progress` (parsed from stdout by JobManager). Callable
        # jobs never populate it and stay {progress: null}, which the frontend
        # renders as a bare "N lines" chip with no bar.
        return [{"id": j.id, "cmd": j.cmd, "status": j.status, "lines": len(j.lines),
                 "started": j.started, "progress": j.progress}
                for j in jobs.list()]

    @app.get("/api/jobs/{jid}")
    def get_job(jid: str):
        """P7-C1: single-job endpoint with the callable-job `result` payload.
        The async spray + act/run endpoints return a job id; polling here
        gives the caller the full structured result (same shape as the sync
        endpoints return inline) once status flips out of running."""
        job = jobs.get(jid)
        if job is None:
            raise HTTPException(404, "no such job")
        return {"id": job.id, "cmd": job.cmd, "status": job.status,
                "started": job.started, "ended": job.ended,
                "returncode": job.returncode, "lines": len(job.lines),
                "progress": job.progress, "result": job.result}

    @app.get("/api/jobs/{jid}/events")
    async def job_events(jid: str):
        job = jobs.get(jid)
        if job is None:
            raise HTTPException(404, "no such job")

        async def gen():
            i = 0
            last_progress = None
            while True:
                while i < len(job.lines):
                    yield f"data: {json.dumps({'line': job.lines[i]})}\n\n"
                    i += 1
                # P7-C5: emit a `progress` event whenever the parsed
                # {done, total, phase} dict changes so the frontend can
                # move the bar without waiting for the next stdout line.
                if job.progress != last_progress:
                    last_progress = dict(job.progress) if job.progress else None
                    yield f"data: {json.dumps({'progress': last_progress})}\n\n"
                if job.status != "running":
                    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
                    return
                await asyncio.sleep(0.3)

        return StreamingResponse(gen(), media_type="text/event-stream")
