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

def _classify_vuln(host, v, o: str) -> ActionCard | None:
    """Map one finding to a loot or exploit card, or None if it isn't actionable."""
    text = f"{v.script_id} {v.title}".lower()
    qv = qod.qod_of(v)
    conf = _confidence(qv)

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

    if v.severity in ("critical", "high") and (
            v.kev or v.ids or any(h in text for h in _EXPLOIT_HINTS)):
        impact = _exploit_impact(host, v)
        # confirmed/likely -> a real ready action; a low-QoD version lead -> verify first.
        tier = READY if qv >= qod.MIN_QOD_VISIBLE else LEAD
        ident = (v.ids[0] if v.ids else v.ip)
        # Yield label is about ACCESS LEVEL (who you become), not the EPSS-inflated
        # score: a DC RCE = domain compromise; a critical elsewhere likely lands you
        # SYSTEM/root; otherwise a shell. (KEV/EPSS still raise the ranking score.)
        if _is_dc(host):
            yields = "domain compromise"
        elif v.severity == "critical":
            yields = "a shell (likely SYSTEM/root)"
        else:
            yields = "a shell"
        return ActionCard(
            archetype="exploit", title=f"Exploit {v.title}", target=_tgt(v),
            command=f"recce writeup {ident} -o {o}   # exploit steps + PoC in the "
                    "Exploitation sheet",
            safety="intrusive", tier=tier, impact=impact, confidence=conf,
            leverage=1.5 if _is_dc(host) else 1.0, yields=yields,
            prove=f"recce prove -o {o}",
            why=_why(v, qv, "exploit", kev=v.kev, epss=v.epss))
    return None


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
        for v in getattr(h, "vulns", []):
            card = _classify_vuln(h, v, o)
            if card:
                cards.append(card)
        if getattr(h, "access_gained", False):
            if not getattr(h, "privesc_checked", False):
                cards.append(_escalate_card(h, o))
            piv = _pivot_card(h, subnets, o)
            if piv:
                cards.append(piv)

    cards.extend(_cred_cards(hosts, creds, o))
    cards = _dedup_loot(cards)
    cards.sort(key=_rank_key)
    return cards


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
            lines.append(f"  [{c.archetype}] {c.title}{where}  ->  {c.yields}{tag}")
            lines.append(f"      $ {c.command}")
            lines.append(f"      · {c.why}  ·  score {c.score} "
                         f"(impact {c.impact} × conf {c.confidence:g} × lev {c.leverage:g})")
    return lines
