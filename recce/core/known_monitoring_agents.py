"""Cross-service "monitoring agents known to this engagement" reader.

A monitoring agent — Zabbix agent (ZBXD on 10050), NRPE (Nagios/Icinga on
5666), Prometheus exporter / server (9090/9100) — is a pivot signal in
a class by itself: the agent already runs on every monitored host under
a privileged account, and the monitoring server holds a stored trust
relationship to it (Server= allow-list, allowed_hosts, scrape_configs
with bearer tokens). Compromise ONE monitoring agent — via NRPE arg
injection, Zabbix `system.run[]`, or a reachable `/-/reload` — and the
adversary walks every host the same fleet monitors.

Producers WRITE via `record_monitoring_agent(host, port, kind, ...)`;
the reader never invents agents — the store is the authority. The
`gated` flag is the producer's judgement about whether access-control
still stands from OUR source IP:

  * gated=True   — TLS/PSK required, cert-auth accepted, or the daemon
                   refused our probe. Exploit path is closed from here.
  * gated=False  — the daemon answered our probe. The IP allow-list is
                   missing, wildcarded, or admits the scanner subnet;
                   every registered command is invocable.

`server_hints` collects upstream server IPs the agent has been told
about (Zabbix `Server=`/`ServerActive=`, NRPE `nsca_host`, Prometheus
`external_labels`+scrape hints), so a compromised agent's outbound trust
targets are named at reader time.

Case-insensitive dedup on (ip, port, kind) with first-seen `version`
casing preserved for display — vendor version strings vary by build
(`Zabbix agent 6.0.14` vs `zabbix_agentd 6.0.14`).
"""
from __future__ import annotations

from typing import Any

from .models import Host


# Canonical kinds. Producers must pass one of these — the reader refuses
# unknown kinds so a typo (`prometheus_exporter` vs `prometheus-exporter`)
# doesn't silently create a parallel bucket.
KINDS = ("zabbix-agent", "zabbix-trapper", "nrpe", "prometheus-exporter")


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _lc(v: Any) -> str:
    return _norm(v).lower()


def _agent_key(ip: str, port: int, kind: str) -> tuple[str, int, str]:
    return (_lc(ip), int(port or 0), _lc(kind))


def record_monitoring_agent(host: Host, port: int, kind: str, *,
                            version: str = "", gated: bool = False,
                            server_hints: list[str] | None = None,
                            source: str = "") -> None:
    """Producer entry point. Appends or merges one monitoring-agent
    observation on `host`. Merges on (ip, port, kind): a later probe
    fills in fields the earlier one left blank, but never overwrites
    first-seen `version` casing. `server_hints` are unioned (dedup
    case-insensitive on IP text). `source` is appended to `sources`.

    A `gated=True` observation NEVER downgrades a prior `gated=False` —
    once a bypass has been proven from this scanner IP, a later probe
    that hits a TLS-required error does not un-prove it.
    """
    kind = _lc(kind)
    if kind not in KINDS:
        return
    ip = _norm(getattr(host, "ip", "")) or ""
    if not ip:
        return
    version = _norm(version)
    src = _norm(source)
    hints = [_norm(h) for h in (server_hints or []) if _norm(h)]

    existing = getattr(host, "monitoring_agents", None)
    if existing is None:
        existing = []
        host.monitoring_agents = existing  # type: ignore[attr-defined]

    key = _agent_key(ip, port, kind)
    for rec in existing:
        if _agent_key(rec.get("ip", ""), rec.get("port", 0),
                      rec.get("kind", "")) == key:
            if version and not rec.get("version"):
                rec["version"] = version
            # gated latches to False (bypass proven) — never upgrades.
            if not gated:
                rec["gated"] = False
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            sh = rec.setdefault("server_hints", [])
            seen = {s.lower() for s in sh}
            for h in hints:
                if h.lower() not in seen:
                    sh.append(h)
                    seen.add(h.lower())
            return

    rec = {"ip": ip, "port": int(port or 0), "kind": kind,
           "version": version, "gated": bool(gated),
           "server_hints": list(dict.fromkeys(hints)),
           "sources": [src] if src else []}
    existing.append(rec)


def monitoring_agents_for(host: Host) -> list[dict]:
    """Every monitoring agent recorded on this host, insertion order.
    Returned dicts are shallow copies — consumer mutation cannot corrupt
    the store."""
    out: list[dict] = []
    for rec in getattr(host, "monitoring_agents", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        copy["server_hints"] = list(rec.get("server_hints") or [])
        out.append(copy)
    return out


def known_monitoring_agents(hosts: list[Host]) -> dict:
    """Engagement-wide monitoring-agent inventory.

    Returns:
      {"agents":         [{"ip","port","kind","version","gated",
                           "server_hints",[ip], "sources": [str]}, ...],
       "by_kind":        {kind: count},
       "reachable_from": [ip, ...]}   # hosts with at least one
                                      # gated=False monitoring agent —
                                      # the pivot-open surface

    Priority order for `agents`: gated=False (exploitable now) first,
    then by kind (zabbix-agent, zabbix-trapper, nrpe, prometheus-exporter
    — the canonical `KINDS` ordering), then by ip/port for stability.
    """
    agents: list[dict] = []
    seen: dict[tuple[str, int, str], dict] = {}
    for h in hosts:
        for rec in monitoring_agents_for(h):
            k = _agent_key(rec.get("ip", ""), rec.get("port", 0),
                           rec.get("kind", ""))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                agents.append(rec)
                continue
            if rec.get("version") and not entry.get("version"):
                entry["version"] = rec["version"]
            if not rec.get("gated"):
                entry["gated"] = False
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)
            hint_seen = {s.lower() for s in entry.get("server_hints") or []}
            for h_ip in rec.get("server_hints") or []:
                if h_ip and h_ip.lower() not in hint_seen:
                    entry["server_hints"].append(h_ip)
                    hint_seen.add(h_ip.lower())

    kind_order = {k: i for i, k in enumerate(KINDS)}
    agents.sort(key=lambda r: (0 if not r.get("gated") else 1,
                               kind_order.get(_lc(r.get("kind", "")), 99),
                               _lc(r.get("ip", "")),
                               int(r.get("port", 0))))

    by_kind: dict[str, int] = {}
    for a in agents:
        k = _lc(a.get("kind", ""))
        if k:
            by_kind[k] = by_kind.get(k, 0) + 1

    reachable_from: list[str] = []
    seen_r: set[str] = set()
    for a in agents:
        if a.get("gated"):
            continue
        ip = a.get("ip", "")
        key = ip.lower()
        if ip and key not in seen_r:
            seen_r.add(key)
            reachable_from.append(ip)

    return {"agents": agents, "by_kind": by_kind,
            "reachable_from": reachable_from}
