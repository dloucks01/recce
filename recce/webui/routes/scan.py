"""Scan jobs + live progress + the command catalog."""
from __future__ import annotations

import asyncio
import json

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from ..jobs import recce_argv
from .._common import _COMMANDS


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
    reason = (f"Learned AD realm `{primary}` from NTLM/LDAP enumeration "
              f"across {kd.get('total_known', 0)} host(s).")
    return [{"key": f"domain-{cmd}-{realm}", "command": cmd, "field": "domain",
             "suggested_value": realm, "reason": reason,
             "confidence": "high", "source": "known_domains"}
            for cmd in _DOMAIN_TARGETS]


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
    reason = (f"`{name}` is flagged adminCount=1 (or well-known-admin) — "
              f"prefer it for authenticated checks over an arbitrary user.")
    return [{"key": f"user-{cmd}-{name.lower()}", "command": cmd,
             "field": "username", "suggested_value": name, "reason": reason,
             "confidence": "high", "source": "known_users"}
            for cmd in _USER_TARGETS]


def _rule_hashes_potfile(hosts, creds, loot_dir):  # noqa: ARG001
    """known_hashes > 0 → surface the hashcat + `recce creds --potfile` handoff."""
    try:
        from ...creds.known_hashes import known_hashes
    except ImportError:
        return []
    r = known_hashes(creds, loot_dir=loot_dir)
    if not r.get("total"):
        return []
    cats = ", ".join(sorted(r.get("categories") or {})) or "nthash"
    total = r["total"]
    reason = (f"{total} crackable hash(es) captured ({cats}). Crack with "
              f"hashcat against `<eng>/loot/*.hash`, then feed the potfile "
              f"back with `recce creds --potfile <pot>`.")
    return [{"key": f"hashes-potfile-{total}", "command": "",
             "field": "", "suggested_value": "",
             "external_cmd": "hashcat -m <mode> <eng>/loot/<file>.hash <wordlist>",
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
)


def register_scan_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    jobs = ctx.jobs
    broker = ctx.broker

    @app.get("/api/commands")
    def list_commands():
        """The command surface the UI renders its runner from (grouped, with the fields/
        flags each command accepts)."""
        return {k: {kk: v[kk] for kk in
                    ("label", "group", "targets", "profile", "creds", "lhost", "flags")}
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

    @app.get("/api/scan/context")
    def scan_context():
        """Which discovered hosts qualify for each command.

        The targets field is free text, so a tester picking `mssql` has no way to
        know whether anything in the engagement even runs MSSQL. Counts come from
        each module's OWN `*_targets()` predicate rather than a port list copied
        into the web layer, so a module that changes what it matches cannot drift
        away from the hint shown here.
        """
        import importlib
        from ...cli._service_helpers import _MODULE_PATH
        from ...core.store import Store

        with Store(ctx.db_path) as st:
            hosts = [h for h in st.all_hosts() if h.is_up]

        out: dict = {}
        for cmd, path in sorted(_MODULE_PATH.items()):
            try:
                mod = importlib.import_module(path)
            except ImportError:
                continue
            fn = next((getattr(mod, n) for n in dir(mod)
                       if n.endswith("_targets") and callable(getattr(mod, n))), None)
            if fn is None:
                continue                     # web/api are HTTP-wide; handled below
            try:
                ips = sorted({t["ip"] for t in fn(hosts) if t.get("ip")})
            except Exception:                # noqa: BLE001 - a hint must never 500 the tab
                continue
            entry = {"count": len(ips), "sample": ips[:8]}
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
        return {"hosts": len(hosts), "commands": out}

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
        targets = [t for t in _re.split(r"[\s,]+", str(body.get("targets", "")))
                   if t and not t.startswith("-")]
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
                    continue                     # bad int → drop silently
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

        def _done(job):
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": label})

        job = jobs.start(full_argv, on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

    @app.post("/api/jobs/{jid}/cancel")
    def cancel_job(jid: str):
        if not jobs.cancel(jid):
            raise HTTPException(404, "no running job with that id")
        return {"ok": True}

    @app.get("/api/jobs")
    def list_jobs():
        return [{"id": j.id, "cmd": j.cmd, "status": j.status, "lines": len(j.lines),
                 "started": j.started} for j in jobs.list()]

    @app.get("/api/jobs/{jid}/events")
    async def job_events(jid: str):
        job = jobs.get(jid)
        if job is None:
            raise HTTPException(404, "no such job")

        async def gen():
            i = 0
            while True:
                while i < len(job.lines):
                    yield f"data: {json.dumps({'line': job.lines[i]})}\n\n"
                    i += 1
                if job.status != "running":
                    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
                    return
                await asyncio.sleep(0.3)

        return StreamingResponse(gen(), media_type="text/event-stream")
