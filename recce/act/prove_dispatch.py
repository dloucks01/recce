"""Per-finding dispatch to the T2 verification prover.

Both `recce prove` (CLI, in `recce/cli/_act.py`) and the WebUI's
`POST /api/prove/{finding_key}` endpoint run the same recipe for a given
finding — this module is the single dispatch point they share.

The CLI walks every host + vuln via `proofs.verify_hosts(hosts)`; the WebUI
proves ONE finding at a time (the tester clicked a "Prove" button on that
row). This helper resolves a `finding_key` back to the underlying vuln,
runs its recipe from `recce.vuln.proofs`, and returns a verdict record with
the same shape `proofs.verify_host` emits — so any downstream renderer can
consume both.

Returns ``None`` when the finding_key doesn't match any loaded vuln, and
returns a record with ``verdict == INCONCLUSIVE`` when the vuln matches but
carries no proof recipe.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..core.tracking import vuln_row_key
from ..vuln import proofs

# Ports where the finish/verify command should dial TLS rather than cleartext.
_TLS_PORTS = {443, 636, 989, 990, 993, 995, 3269, 5986, 8443, 2376}


def _pick_cred(host, creds):
    """A credential that is CORRECT to prefill for this host — captured FROM it
    (origin_ip match) or, for a domain-joined host, a domain credential. Never a
    guessed one (a wrong credential is worse than a visible placeholder)."""
    usable = [c for c in (creds or [])
              if getattr(c, "secret", "")
              and (getattr(c, "kind", "") or "").lower() in ("", "password", "plaintext", "cleartext")]
    for c in usable:
        if getattr(c, "origin_ip", "") == host.ip:
            return c
    if str((getattr(host, "ntlm", {}) or {}).get("dns_domain") or ""):
        for c in usable:
            if getattr(c, "domain", ""):
                return c
    return None


def _fill_cmd(text: str, host, port, ctx: dict | None) -> str:
    """Turn a recipe's placeholder command into a copy-paste-ready one by
    substituting the real target facts recce already holds: <ip>, <port>,
    <scheme>, the host's NetBIOS/hostname, the AD realm + base DN, and a known
    credential when one is correct for this host. Tokens with no known value are
    left as-is (never guessed). Case-insensitive so <IP> / <DC-netbios-name> fill
    too. `ctx` (optional) carries engagement-wide {domain, creds}."""
    if not text or "<" not in text:
        return text
    ctx = ctx or {}
    ntlm = getattr(host, "ntlm", {}) or {}
    short = (host.hostname or "").split(".")[0]
    dom = str(ctx.get("domain") or ntlm.get("dns_domain") or "")
    base = str(ntlm.get("default_naming_context") or "")
    if not base and dom:
        base = ",".join(f"DC={p}" for p in dom.split(".") if p)
    try:
        pnum = int(port)
    except (TypeError, ValueError):
        pnum = 0
    reps = {
        "<ip>": host.ip, "<target>": host.ip,
        "<port>": str(port or "") if port else "",
        "<scheme>": "https" if pnum in _TLS_PORTS else "http",
        "<dc-netbios-name>": short.upper(), "<netbios-name>": short.upper(),
        "<netbios>": short.upper(), "<hostname>": host.hostname or host.ip,
        "<host>": host.hostname or host.ip,
        "<domain>": dom, "<realm>": dom.upper(), "<base>": base,
        "<community>": "public",           # SNMP default community — a real default, not a guess
    }
    cred = _pick_cred(host, ctx.get("creds"))
    if cred:
        for k in ("<u>", "<user>", "<username>"):
            reps[k] = cred.username or ""
        for k in ("<pass>", "<password>"):
            reps[k] = cred.secret or ""
    out = text
    for token, val in reps.items():
        if val:
            out = re.sub(re.escape(token), lambda _m, v=val: v, out, flags=re.IGNORECASE)
    return out


def _fill_result(result: dict, host, ctx: dict | None) -> dict:
    """Fill placeholders in the command-bearing fields of a verdict record so the
    'finish' step and evidence lines are runnable, not templates."""
    port = result.get("port") or 0
    if result.get("finish"):
        result["finish"] = _fill_cmd(result["finish"], host, port, ctx)
    if result.get("evidence"):
        result["evidence"] = [_fill_cmd(e, host, port, ctx) for e in result["evidence"]]
    return result


def has_prover(vuln) -> bool:
    """True when this vuln has a proof recipe registered — i.e. clicking
    "Prove" on it would produce a real verdict rather than a fallback
    INCONCLUSIVE."""
    return proofs.recipe_for(vuln) is not None


def provable_keys(hosts: Iterable) -> list[str]:
    """Every `vuln_row_key` in `hosts` whose vuln has a proof recipe. The
    WebUI's exploit-surface tab calls this so the "Prove" button renders
    only for the findings that actually have a prover."""
    keys: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        for v in h.vulns:
            if not has_prover(v):
                continue
            k = vuln_row_key(v)
            if k in seen:
                continue
            seen.add(k)
            keys.append(k)
    return keys


def _verdict_for_vuln(host, v, ctx: dict | None = None) -> dict:
    """Run the matched recipe against a single vuln, mirroring
    `proofs.verify_host`'s per-vuln branch (recipe lookup, port lookup,
    the source='version-db' over-claim guard, verdict shape). Placeholder
    commands in the result are filled with the host's real facts + `ctx`."""
    r = proofs.recipe_for(v)
    if r is None:
        # Caller decides whether to expose this; keeping the shape stable
        # lets a "not provable" click still render something legible.
        return {
            "ip": host.ip, "port": v.port, "vuln": "",
            "finding": v.title or v.script_id or "finding",
            "verdict": proofs.INCONCLUSIVE,
            "evidence": ["No proof recipe matches this finding — "
                         "recce doesn't know how to prove this one non-"
                         "intrusively yet."],
            "preconditions": [], "finish": "", "fp": "",
            "key": f"verify:{host.ip}:{v.port or 0}:none",
        }
    port = proofs._port_of(host, v)
    verdict, evidence = r["fn"](host, port, v)
    # Same guard `verify_host` applies: a "we authenticated / read with no
    # credential" phrasing coming out of a version-db banner match gets
    # capped at LIKELY (recce didn't actually probe the live service).
    if verdict == proofs.CONFIRMED and v.source == "version-db" \
            and proofs._LIVE_ACCESS_RE.search(" ".join(evidence)):
        verdict = proofs.LIKELY
        action = list(evidence[1:]) if len(evidence) > 1 else []
        evidence = [
            "Version/advisory match only - recce did NOT authenticate or "
            "read this service live; treat it as a lead to verify, not a "
            "confirmed observation.", *action]
    result = {
        "ip": host.ip, "port": v.port, "vuln": r["name"],
        "finding": v.title or v.script_id or r["name"],
        "verdict": verdict, "evidence": evidence,
        "preconditions": r["pre"], "finish": r["finish"], "fp": r["fp"],
        "key": f"verify:{host.ip}:{v.port or 0}:{r['id']}",
    }
    return _fill_result(result, host, ctx)


def locate_finding(hosts: Iterable, finding_key: str, ctx: dict | None = None):
    """Return ``(host, vuln, verdict_record)`` for the vuln whose
    `vuln_row_key` matches `finding_key`, or ``None`` when nothing matches.
    A caller that wants to persist the verdict needs the host + vuln, not
    just the record — that's what this exposes over `prove_finding_key`.
    `ctx` (optional {domain, creds}) fills placeholder commands in the record."""
    if not finding_key:
        return None
    for h in hosts:
        for v in h.vulns:
            if vuln_row_key(v) != finding_key:
                continue
            return h, v, _verdict_for_vuln(h, v, ctx)
    return None


def prove_finding_key(hosts: Iterable, finding_key: str, ctx: dict | None = None) -> dict | None:
    """Locate the vuln whose `vuln_row_key` matches `finding_key` and
    return its verdict record. `None` when no vuln matches."""
    located = locate_finding(hosts, finding_key, ctx)
    return located[2] if located else None


def apply_verdict(v, result: dict) -> None:
    """Fold a verdict record back onto its vuln in place, mirroring
    `cmd_prove`'s write-back (recce/cli/_act.py): set verdict / evidence /
    finish, and on a CONFIRMED verdict promote `depth_tier` to t2 (proof of
    exploit) when it was unstamped/t0/t1 — never demoting an already-deeper
    finding. Persisting the mutated host afterwards is the caller's job."""
    v.verdict = result.get("verdict", "") or ""
    v.verdict_evidence = list(result.get("evidence") or [])
    v.verdict_finish = result.get("finish", "") or ""
    if result.get("verdict") == proofs.CONFIRMED:
        cur = (getattr(v, "depth_tier", "") or "").lower()
        if cur in ("", "t0", "t1"):
            v.depth_tier = "t2"
            if not v.output and v.verdict_evidence:
                v.output = "proof-verdict:\n  " + "\n  ".join(
                    v.verdict_evidence[:6])
