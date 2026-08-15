"""The Act phase: turn findings into a ranked, guided action plan.

recce enumerates ("find"); this module answers "so what do I do now?". It maps each
significant finding to an ACTION ARCHETYPE and emits an ActionCard - the specific next
move, its preconditions, the exact command, the expected yield, and how to prove it.

Archetypes (atomic):
    loot      - unauth service / exposure -> read-only extract (creds, data)
    crack     - a captured hash -> offline crack -> plaintext
    spray     - a usable cred + a login surface -> reuse -> new access
    exploit   - a KEV / high-severity vuln with an exploit -> shell
    escalate  - a foothold -> local priv-esc -> SYSTEM/root
    pivot     - access on a segmented host -> reach a new scope

Chains (loot->spray, AD->DA, foothold->escalate->pivot) are leverage relationships
OVER those atomics, captured by the `leverage` score factor rather than as separate
rankable items.

Ranking is two-level for explainability: a coarse TIER (readiness x safety x
confidence) then score = impact x confidence x leverage within the tier. Read-only /
reversible actions are auto-eligible (executed by the `act` command in a later slice);
intrusive ones are guided (exact command printed, never auto-fired). See the design in
docs/ACT-PHASE.md. This slice (P1) is guidance-only: it classifies, ranks, and prints.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import qod

# --- tiers (primary, coarse sort - readiness x safety x confidence) --------------
AUTO, READY, BLOCKED, LEAD = 0, 1, 2, 3
_TIER_LABEL = {
    AUTO: "recce can do these now (read-only / reversible)",
    READY: "do now - ready, ranked by value",
    BLOCKED: "unlocks next - needs a prerequisite first",
    LEAD: "verify first - low-confidence leads",
}
_TIER_ICON = {AUTO: "*", READY: ">", BLOCKED: "#", LEAD: "?"}

# --- impact: yield value, 0-100 (what success actually gives you) ----------------
_IMPACT = {"da": 100, "domain": 90, "system": 70, "shell": 55,
           "password": 45, "nthash": 40, "hash": 30, "data": 20, "info": 5}

# Finding markers that mean "unauthenticated read access" -> a loot action. Matched
# against a vuln's script_id + title (lowercased).
_LOOT_MARKERS = (
    "unauth", "trust-auth", "trust authentication", "empty-password", "empty password",
    "null-session", "null session", "anonymous", "world-export", "world-readable",
    "no_root_squash", "gitconfig", "-git", "dotenv", ".env", "-aws", "secret-file",
    "secret files", "exposed", "public community", "default community",
)
# ...of those, the ones that specifically yield CREDENTIALS (not just data) - a higher
# impact and a leverage boost, because they feed the spray chain.
_CRED_LOOT_MARKERS = (
    "trust-auth", "trust authentication", "empty-password", "empty password",
    "gitconfig", "dotenv", ".env", "-aws", "secret-file", "pg_shadow", "mysql.user",
    "gpp", "cpassword", "unattend",
)
_EXPLOIT_HINTS = ("rce", "remote code execution", "eternalblue", "zerologon",
                  "log4shell", "bluekeep", "unauthenticated command", "deserial",
                  "arbitrary file", "sqli", "sql injection", "path traversal")

_SPRAY_PROTOS = ("smb", "winrm", "ssh", "mssql", "ldap", "rdp")
_HASHCAT_MODE = {"nthash": "1000", "hash": "0"}     # default; notes may override


@dataclass
class ActionCard:
    archetype: str                 # loot | crack | spray | exploit | escalate | pivot
    title: str
    target: str                    # ip / ip:port / "engagement"
    command: str                   # the exact next command
    yields: str                    # what success gives you
    safety: str = "read-only"      # read-only | reversible | intrusive
    tier: int = READY
    impact: int = 0
    confidence: float = 1.0        # 0..1, from QoD (state-based actions = 1.0)
    leverage: float = 1.0          # chain multiplier, 1.0..~2.0
    preconditions: list = field(default_factory=list)   # [(desc, met_bool)]
    prove: str = ""                # how to confirm the outcome
    why: str = ""                  # short rationale (the ranking factors), for trust
    count: int = 1                 # findings/hosts this one card covers (loot aggregates)
    verify_first: bool = False     # action rests on an UNVERIFIED lead -> "candidate"
    tool: str = ""                 # the concrete tool this action uses (msf/impacket/...)
    attack_id: str = ""            # MITRE ATT&CK technique id, e.g. "T1558.003"
    attack_name: str = ""          # e.g. "Kerberoasting"

    @property
    def score(self) -> float:
        return round(self.impact * self.confidence * self.leverage, 2)

    @property
    def auto(self) -> bool:
        """recce may run it unattended: read-only, or a reversible PLAN-generation."""
        return self.tier == AUTO


# --- confidence from QoD ---------------------------------------------------------

def _confidence(qod_val: int) -> float:
    if qod_val >= qod.MIN_QOD_VERIFIED:      # >=95: confirmed
        return 1.0
    if qod_val >= qod.MIN_QOD_VISIBLE:       # >=70: likely
        return 0.75
    return 0.4                                # a lead


def _is_dc(host) -> bool:
    return "Domain Controller" in (getattr(host, "roles", None) or [])


# --- per-finding classification --------------------------------------------------

def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _index_exploit_actions(host) -> dict:
    """Map a normalised finding -> its best concrete exploit action (real msf/tool
    command, prereq, verified flag) from exploitplan. Post-shell steps are skipped
    (they come AFTER a foothold, they're not the exploit itself)."""
    from . import exploitplan
    idx: dict = {}
    try:
        actions = exploitplan.actions_for_host(host)
    except Exception:  # noqa: BLE001 - the plan must never crash on one odd host
        return {}
    for a in actions:
        if a.get("kind") == "post-shell":
            continue
        k = _norm(a.get("finding", ""))
        if not k:
            continue
        # prefer a verified action over an unverified one for the same finding
        if k not in idx or (a.get("verified") and not idx[k].get("verified")):
            idx[k] = a
    return idx


def _match_action(v, xp_idx: dict) -> dict | None:
    if not xp_idx:
        return None
    nt = _norm(v.title)
    if nt in xp_idx:
        return xp_idx[nt]
    for k, a in xp_idx.items():                # substring either way (titles vary)
        if k and (k in nt or nt in k):
            return a
    return None


def _classify_vuln(host, v, o: str, xp_idx: dict | None = None) -> ActionCard | None:
    """Map one finding to a loot or exploit card, or None if it isn't actionable."""
    text = f"{v.script_id} {v.title}".lower()
    qv = qod.qod_of(v)
    conf = _confidence(qv)

    # A CLEAR exploit (KEV, or an explicit exploit hint like RCE/EternalBlue) wins over
    # loot even if the title says "unauth" - an unauthenticated RCE is an exploit, not a
    # read-only read. Ambiguous "unauth service" findings (redis-unauth: data access, no
    # exploit hint) still fall through to loot below.
    clear_exploit = v.severity in ("critical", "high") and (
        v.kev or any(h in text for h in _EXPLOIT_HINTS))
    if clear_exploit:
        return _exploit_card(host, v, o, xp_idx, qv, conf, text)

    if any(m in text for m in _LOOT_MARKERS):
        yields_cred = any(m in text for m in _CRED_LOOT_MARKERS)
        impact = _IMPACT["password"] if yields_cred else _IMPACT["data"]
        lev = 1.3 if yields_cred else 1.0        # cred loot feeds the spray chain
        # loot is read-only; it's an AUTO card unless it's really a low-confidence lead.
        tier = AUTO if qv >= qod.MIN_QOD_VISIBLE else LEAD
        command, label = _loot_action(v, o)
        return ActionCard(
            archetype="loot", title=f"Loot {label}", target=v.ip,
            command=command, safety="read-only", tier=tier,
            impact=impact, confidence=conf, leverage=lev,
            yields="credentials -> spray" if yields_cred else "sensitive data",
            prove=f"recce prove -o {o}",
            why=_why(v, qv, "read-only loot"))

    if v.severity in ("critical", "high") and v.ids:
        # has a CVE but no explicit exploit hint (e.g. a version->CVE match)
        return _exploit_card(host, v, o, xp_idx, qv, conf, text)
    return None


def _exploit_card(host, v, o, xp_idx, qv, conf, text) -> ActionCard:
    impact = _exploit_impact(host, v)
    ident = (v.ids[0] if v.ids else v.ip)
    # Yield label is about ACCESS LEVEL (who you become), not the EPSS-inflated score:
    # a DC RCE = domain compromise; a critical elsewhere likely lands you SYSTEM/root;
    # otherwise a shell. (KEV/EPSS still raise the ranking score.)
    if _is_dc(host):
        yields = "domain compromise"
    elif v.severity == "critical":
        yields = "a shell (likely SYSTEM/root)"
    else:
        yields = "a shell"
    # P3: attach the concrete PoC from exploitplan (real msf/tool command + prereq +
    # whether the underlying finding is QoD-verified) when recce knows one.
    action = _match_action(v, xp_idx or {})
    if action:
        command, tool = action["cmd"], action.get("tool", "")
        verified = bool(action.get("verified"))
        preconds = [(action["prereq"], True)] if action.get("prereq") else []
    else:
        command = f"recce writeup {ident} -o {o}   # exploit steps + PoC in the " \
                  "Exploitation sheet"
        tool, preconds = "", []
        verified = qv >= qod.MIN_QOD_VERIFIED
    # SQLi has a purpose-built tool - bridge to sqlmap (recce doesn't reimplement a SQLi
    # engine), overriding the generic writeup even when no msf module matched.
    if ("sqli" in text or "sql injection" in text) and not (action and action.get("tool")):
        scheme = "https" if (v.port or 0) in (443, 8443) else "http"
        command = (f"sqlmap -u '{scheme}://{host.ip}:{v.port or 80}/' --batch --crawl=2 "
                   "--forms --level=3 --risk=2 --dbs   # confirm + dump the injectable endpoint")
        tool = "sqlmap"
    # A confirmed finding is a ready action; an unverified version-inference lead is a
    # LEAD (verify before you fire an exploit at it).
    tier = READY if verified or qv >= qod.MIN_QOD_VISIBLE else LEAD
    return ActionCard(
        archetype="exploit", title=f"Exploit {v.title}", target=_tgt(v),
        command=command, tool=tool, safety="intrusive", tier=tier, impact=impact,
        confidence=conf, leverage=1.5 if _is_dc(host) else 1.0, yields=yields,
        preconditions=preconds, verify_first=not verified,
        prove=f"recce prove -o {o}",
        why=_why(v, qv, "exploit", kev=v.kev, epss=v.epss))


def _exploit_impact(host, v) -> int:
    dc = _is_dc(host)
    if dc and v.severity == "critical":
        base = _IMPACT["da"]                     # crit on a DC = path to Domain Admin
    elif dc and v.severity == "high":
        base = _IMPACT["domain"]
    elif v.severity == "critical":
        base = _IMPACT["system"]
    else:
        base = _IMPACT["shell"]
    if v.kev:
        base += 15
    base += int(round((v.epss or 0.0) * 10))
    return min(120, base)


def _tgt(v) -> str:
    return f"{v.ip}:{v.port}" if v.port else v.ip


# (marker substrings, command template, human label). First match wins; the command
# operates engagement-wide, so all findings that share it collapse into one card.
_LOOT_ACTIONS = [
    (("git", "dotenv", ".env", "-aws", "web-"), "recce web --creds -o {o}",
     "web credential exposures (.git / .env / .aws)"),
    (("null-session", "secret-file", "smb"), "recce smb --spider -o {o}",
     "SMB shares (null session / secret files)"),
    (("nfs", "world-export", "no_root_squash", "showmount"), "recce nfs -o {o}",
     "NFS exports"),
    (("trust", "empty-password", "empty password", "mysql", "postgres", "redis",
      "mongo"), "recce db -o {o}", "exposed databases (trust / empty-pw / unauth)"),
    (("ldap", "anonymous"), "recce ldap -o {o}", "LDAP anonymous bind"),
    (("snmp", "public community", "default community"), "recce snmp -o {o}",
     "SNMP public community"),
]


def _loot_action(v, o: str) -> tuple[str, str]:
    t = f"{v.script_id} {v.title}".lower()
    for markers, cmd, label in _LOOT_ACTIONS:
        if any(k in t for k in markers):
            return cmd.format(o=o), label
    return f"recce vulns -o {o}", v.title


# --- foothold / pivot (host-state driven) ----------------------------------------

def _escalate_card(host, o: str) -> ActionCard:
    return ActionCard(
        archetype="escalate", title=f"Priv-esc on foothold {host.ip}", target=host.ip,
        command=f"recce privesc -o {o}   # or: recce deploy {host.ip} (push on-target enum)",
        safety="intrusive", tier=READY, impact=_IMPACT["system"], confidence=1.0,
        leverage=1.4 if _is_dc(host) else 1.1, yields="SYSTEM / root on this host",
        preconditions=[("a foothold on the host", True)],
        prove=f"recce status -o {o}",
        why="you already have access here; local priv-esc has not been mapped yet")


def _pivot_card(host, subnets: set, o: str) -> ActionCard | None:
    # A foothold host whose subnet is one of several in scope is a natural pivot into
    # segments your scanner may not reach directly. Simple P1 heuristic; refined later.
    if len(subnets) < 2:
        return None
    return ActionCard(
        archetype="pivot", title=f"Pivot through {host.ip}", target=host.ip,
        command=f"recce run <segmented-range> --proxy socks5://127.0.0.1:1080 -o {o}",
        safety="intrusive", tier=READY, impact=_IMPACT["shell"] + 5, confidence=1.0,
        leverage=1.3, yields="reach into a segment you can't scan directly",
        preconditions=[("a foothold to tunnel through", True)],
        why="a foothold on a multi-segment engagement opens the other segments")


# --- credential-driven cards (crack / spray / blocked auth enum) ------------------

def _cred_cards(hosts, creds, o: str) -> list[ActionCard]:
    from . import credentials as cr
    out: list[ActionCard] = []
    surface = cr.spray_targets(hosts)              # {proto: [ips]}
    surface_hosts = sorted({ip for proto in _SPRAY_PROTOS for ip in surface.get(proto, [])})
    usable = [c for c in creds if c.secret and c.kind in ("password", "nthash", "blank")]
    hashes = [c for c in creds if c.kind in ("hash", "nthash") and c.secret]

    # CRACK: a captured hash -> plaintext (offline, safe to queue).
    for c in hashes:
        mode = _crack_mode(c)
        out.append(ActionCard(
            archetype="crack", title=f"Crack {c.kind} for {c.label}",
            target=c.origin_ip or "engagement",
            command=f"hashcat -m {mode} <hash> /usr/share/wordlists/rockyou.txt",
            safety="read-only", tier=READY, impact=_IMPACT["password"], confidence=1.0,
            leverage=1.4,                          # a cracked cred unlocks the spray
            yields="a plaintext credential -> spray",
            why=f"offline crack of a captured {c.kind} ({c.source})"))

    # SPRAY: a usable cred + a login surface -> reuse for new access.
    if usable and surface_hosts:
        lev = 1 + min(1.0, len(surface_hosts) / 20)
        protos = [p for p in _SPRAY_PROTOS if surface.get(p)]
        out.append(ActionCard(
            archetype="spray", title=f"Spray {len(usable)} credential(s) across "
            f"{len(surface_hosts)} host(s)", target="engagement",
            command=f"recce creds --plan -o {o}   # paired, lockout-safe netexec plan",
            safety="reversible", tier=AUTO, impact=_IMPACT["shell"], confidence=1.0,
            leverage=round(lev, 2), yields="validated logins -> new access / lateral move",
            preconditions=[("at least one credential", True),
                           (f"a login surface ({', '.join(protos)})", True)],
            prove=f"recce credenum -o {o}",
            why=f"{len(usable)} cred(s) vs a {', '.join(protos)} surface; "
                "check lockout policy first"))
    elif surface_hosts and not usable:
        # BLOCKED: there IS an auth surface but no credential yet - show what unlocks it.
        out.append(ActionCard(
            archetype="spray", title="Authenticated SMB/AD enum + spray",
            target="engagement",
            command=f"recce credenum -u USER -p PASS -o {o}",
            safety="intrusive", tier=BLOCKED, impact=_IMPACT["shell"], confidence=1.0,
            leverage=1 + min(1.0, len(surface_hosts) / 20),
            yields="shares, local-admin reach, secretsdump -> lateral",
            preconditions=[("a valid credential (crack a hash, or loot one)", False)],
            why=f"{len(surface_hosts)} host(s) expose an auth surface; you need a cred"))
    return out


def _adpath_card(hosts, o: str) -> ActionCard | None:
    """The keystone: a synthesized route to Domain Admin from attackpath. This is a
    CHAIN card (over the atomic exploit/loot/spray steps), the 'here's the whole way to
    DA' headline. Max leverage - it's the highest-value thing to look at first."""
    from . import attackpath
    try:
        steps = attackpath.build(hosts)
    except Exception:  # noqa: BLE001
        return None
    dom = [s for s in steps if s.get("stage") == "Domain Dominance"]
    if not dom:
        return None
    route = "; ".join(_norm_title(s.get("title", "")) for s in dom[:3])
    return ActionCard(
        archetype="ad-path",
        title=f"Route to Domain Admin ({len(dom)} dominance step(s))",
        target=dom[0].get("ip", "engagement"),
        command=f"recce attackpath -o {o}   # full route + graph (network-architecture.svg)",
        safety="intrusive", tier=READY, impact=_IMPACT["da"], confidence=0.95,
        leverage=2.0, yields="Domain Admin",
        preconditions=[("execute the chain step by step (see the route)", True)],
        prove=f"recce prove -o {o}",
        why=f"synthesised path to DA across {len(dom)} step(s): {route}")


def _norm_title(s: str) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    return (s[:39] + "…") if len(s) > 40 else s


def _default_cred_cards(hosts, o: str) -> list[ActionCard]:
    """One guided card per service type that has known default creds, aggregated across
    the hosts exposing it. Default creds are instant access for near-zero effort - but
    testing them sends auth attempts (lockout risk), so these are guided, not auto."""
    from . import defaultcreds
    by_svc: dict[str, list[str]] = {}
    for h in hosts:
        for p in getattr(h, "open_ports", []):
            key = defaultcreds.service_key(p)
            if key and defaultcreds.creds_for(p):
                by_svc.setdefault(key, [])
                if h.ip not in by_svc[key]:
                    by_svc[key].append(h.ip)
    out: list[ActionCard] = []
    for svc, ips in by_svc.items():
        out.append(ActionCard(
            archetype="default-cred",
            title=f"Test default credentials on {len(ips)} {svc.upper()} host(s)",
            target=ips[0] if len(ips) == 1 else "engagement", count=len(ips),
            command=defaultcreds.test_command(svc, ips),
            safety="intrusive", tier=READY, impact=_IMPACT["shell"], confidence=1.0,
            leverage=1 + min(0.6, len(ips) / 20), yields="a valid login (instant access)",
            preconditions=[("check the account-lockout policy first", True)],
            why=f"{svc} ships with well-known default creds; {len(ips)} host(s) expose it"))
    return out


def _crack_mode(c) -> str:
    # Prefer an explicit "hashcat -m NNN" the loot module already worked out (mysql/pg).
    note = (c.notes or "").lower()
    if "hashcat -m " in note:
        try:
            return note.split("hashcat -m ", 1)[1].split()[0].strip(".,;)")
        except (IndexError, ValueError):
            pass
    return _HASHCAT_MODE.get(c.kind, "0")


def _why(v, qv, kind, kev=False, epss=0.0) -> str:
    bits = [f"{v.severity}", f"QoD {qv}"]
    if kev:
        bits.append("KEV (exploited in the wild)")
    if epss:
        bits.append(f"EPSS {epss:.0%}")
    bits.append(kind)
    return " · ".join(bits)


# --- the plan: classify everything, then rank ------------------------------------

def action_plan(hosts, credentials=None, output_dir: str = "engagement") -> list[ActionCard]:
    """Every actionable next move for the engagement, ranked (best first)."""
    o = output_dir
    creds = list(credentials or [])
    cards: list[ActionCard] = []
    subnets = {h.subnet for h in hosts if getattr(h, "subnet", "")}

    for h in hosts:
        xp_idx = _index_exploit_actions(h)
        for v in getattr(h, "vulns", []):
            card = _classify_vuln(h, v, o, xp_idx)
            if card:
                cards.append(card)
        if getattr(h, "access_gained", False):
            if not getattr(h, "privesc_checked", False):
                cards.append(_escalate_card(h, o))
            piv = _pivot_card(h, subnets, o)
            if piv:
                cards.append(piv)

    cards.extend(_cred_cards(hosts, creds, o))
    cards.extend(_default_cred_cards(hosts, o))
    ad = _adpath_card(hosts, o)                    # the synthesized route to DA (keystone)
    if ad:
        cards.append(ad)
    cards = _dedup_loot(cards)
    _tag_attack(cards)
    cards.sort(key=_rank_key)
    return cards


def _tag_attack(cards: list[ActionCard]) -> None:
    """Annotate each card with its MITRE ATT&CK technique: the specific one implied by
    the finding title, else the archetype's default."""
    from . import attack
    for c in cards:
        tech = attack.technique_for_text(c.title) or attack.technique_for_archetype(c.archetype)
        if tech:
            c.attack_id, c.attack_name = tech.id, tech.name


def _dedup_loot(cards: list[ActionCard]) -> list[ActionCard]:
    """A loot command (`recce web --creds`, `recce db`, ...) loots EVERY matching host
    in one run, so N per-host loot findings that share a command are one action. Collapse
    them: keep the highest-scoring representative, sum the count, prefer a cred yield."""
    out: list[ActionCard] = []
    by_cmd: dict[str, ActionCard] = {}
    for c in cards:
        if c.archetype != "loot":
            out.append(c)
            continue
        rep = by_cmd.get(c.command)
        if rep is None:
            by_cmd[c.command] = c
            out.append(c)
            continue
        rep.count += 1
        if "credentials" in c.yields:
            rep.yields = c.yields
        if c.score > rep.score:              # promote the stronger representative
            rep.title, rep.impact, rep.confidence, rep.leverage, rep.why, rep.tier = (
                c.title, c.impact, c.confidence, c.leverage, c.why, c.tier)
    return out


def _rank_key(c: ActionCard):
    # tier ascending, then score descending, then a stable tie-break on target.
    return (c.tier, -c.score, c.target)


def top_moves(cards: list[ActionCard], n: int = 3) -> list[ActionCard]:
    """The single highest-value things to do RIGHT NOW, by raw score across the doable
    tiers (AUTO + READY). The grouped plan is organised by 'what recce does vs. what you
    drive'; this cuts across that so a time-boxed operator sees the instant-DA exploit
    up top instead of buried under trivial read-only loot. Excludes blocked/lead items
    (not doable yet / unverified)."""
    doable = [c for c in cards if c.tier in (AUTO, READY)]
    return sorted(doable, key=lambda c: (-c.score, c.tier, c.target))[:n]


# --- P2: auto-run the read-only / reversible links + the feedback loop -----------
# These execute ONLY read-only wire-protocol loot (the cheap creds we already extract)
# and a read-only spray-PLAN generation. Nothing intrusive ever runs here. Each is
# scoped to hosts that ALREADY carry the matching loot finding, so `act --run` never
# blind-rescans the whole scope. Every call is defensively wrapped: one unreachable or
# hostile target can't abort the loop.

def _has_finding(host, *needles: str) -> bool:
    for v in getattr(host, "vulns", []):
        t = f"{v.script_id} {v.title}".lower()
        if any(n in t for n in needles):
            return True
    return False


def _loot_db(store, hosts, o) -> list:
    """Re-run the read-only DB loot (Postgres trust-auth, MySQL empty-password) on hosts
    already flagged for it; persist any NEW credential. Returns the new creds."""
    from . import mysql, postgres
    flagged = [h for h in hosts if _has_finding(h, "trust", "empty-password",
                                                "empty password", "postgres", "mysql")]
    new: list = []
    for mod in (postgres, mysql):
        try:
            analysis = mod.analyze(flagged, active=True)
        except Exception:  # noqa: BLE001 - a bad target never aborts the loop
            continue
        for c in analysis.get("credentials", []):
            if store.add_credential(c):
                new.append(c)
    return new


def _loot_web(store, hosts, o) -> list:
    """Re-run the read-only web loot (.git/.env/.aws) on hosts already flagged; persist
    any NEW credential."""
    from . import web
    new: list = []
    for h in hosts:
        if not _has_finding(h, "web-git", "gitconfig", "dotenv", ".env", "web-aws"):
            continue
        try:
            profiles = web.scan_host(h, active=True)
        except Exception:  # noqa: BLE001
            continue
        for pr in profiles:
            for c in pr.get("credentials", []):
                if store.add_credential(c):
                    new.append(c)
    return new


# command prefix (as emitted by _loot_action) -> executor
_AUTO_LOOT = {"recce db": _loot_db, "recce web": _loot_web}


def execute_auto(store, output_dir: str = "engagement", max_passes: int = 3) -> dict:
    """Run the AUTO read-only links and feed yields back until nothing new appears.

    Loop: loot the flagged unauth services -> persist new creds -> re-plan. A looted
    cred changes the plan (a Spray card appears / leverage rises), which is exactly the
    'found -> act -> new access -> act again' loop, bounded by max_passes. Finally
    (re)generate the lockout-safe spray PLAN from the accumulated cred set. Read-only
    throughout: loot is non-mutating, the spray plan only WRITES local files (it does
    not spray). Returns a summary for the caller to print."""
    from . import credentials as cr
    summary = {"looted": [], "passes": 0, "spray": {}}
    for _ in range(max(1, max_passes)):
        hosts = store.all_hosts()
        cards = action_plan(hosts, store.all_credentials(), output_dir)
        auto_loot_cmds = {c.command for c in cards
                          if c.tier == AUTO and c.archetype == "loot"}
        new: list = []
        for cmd in auto_loot_cmds:
            for prefix, fn in _AUTO_LOOT.items():
                if cmd.startswith(prefix):
                    new.extend(fn(store, hosts, output_dir))
        summary["passes"] += 1
        summary["looted"].extend(new)
        if not new:                    # fixpoint: nothing new to loot -> stop
            break
    # Regenerate the spray plan from the final accumulated credential set.
    hosts = store.all_hosts()
    stacked = cr.stack(hosts, store.all_credentials())
    if stacked:
        try:
            summary["spray"] = cr.build_spray(stacked, hosts, output_dir)
        except Exception:  # noqa: BLE001 - plan generation must not crash the phase
            summary["spray"] = {}
    return summary


# --- rendering -------------------------------------------------------------------

def format_plan(cards: list[ActionCard], top: int = 0) -> list[str]:
    """Group the ranked cards by tier for the CLI. `top` (>0) caps cards per tier."""
    if not cards:
        return ["Nothing actionable yet - enumerate first (recce run <targets>)."]
    lines: list[str] = []
    by_tier: dict[int, list[ActionCard]] = {}
    for c in cards:
        by_tier.setdefault(c.tier, []).append(c)
    for tier in (AUTO, READY, BLOCKED, LEAD):
        group = by_tier.get(tier)
        if not group:
            continue
        lines.append("")
        lines.append(f"{_TIER_ICON[tier]} {_TIER_LABEL[tier].upper()}")
        for c in (group[:top] if top else group):
            unmet = [d for d, met in c.preconditions if not met]
            tag = f"  (needs: {', '.join(unmet)})" if unmet else ""
            where = "" if c.target == "engagement" else f" @ {c.target}"
            if c.count > 1:
                where += f" (+{c.count - 1} more host(s))"
            flag = "  [candidate — verify first]" if c.verify_first else ""
            lines.append(f"  [{c.archetype}] {c.title}{where}  ->  {c.yields}{tag}{flag}")
            lines.append(f"      $ {c.command}")
            att = f"  ·  ATT&CK {c.attack_id} {c.attack_name}" if c.attack_id else ""
            lines.append(f"      · {c.why}  ·  score {c.score} "
                         f"(impact {c.impact} × conf {c.confidence:g} × lev {c.leverage:g})"
                         + att)
    return lines
