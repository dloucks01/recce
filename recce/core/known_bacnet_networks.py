"""Cross-service "BACnet BBMD topology" reader.

Every BACnet Broadcast Management Device (BBMD) that returns a readable
Broadcast-Distribution-Table (BVLC Read-BDT, ASHRAE 135 clause J.4)
reveals the other BBMDs it can flood broadcasts to — the multi-network
BACnet topology, which a Read-Property against any single Device Object
does not disclose. Recording the (self, peer) edges here yields an
engagement-wide BBMD graph.

Producers today:
  * `recce/services/bacnet.py` — BBMD topology probe (`_read_bdt`) fires
    from `probe()`; `analyze()` records each peer entry here.

Consumers (this pass ships the reader only):
  * a future OT-engagement reporter that visualises the BAS multi-network
    topology (each edge = one BDT peer entry).

Peers are keyed by (ip, port, peer_ip, peer_port) — a re-probe against
the same BBMD records only once. Peer IPs are compared verbatim (BACnet
BDT peer addresses are numeric IPv4 dotted-quads, no case).
"""
from __future__ import annotations

from .models import Host


def _norm(v: str) -> str:
    return (v or "").strip()


def record_bacnet_network(host: Host, ip: str, port: int,
                          bdt_peer: str, bdt_port: int,
                          mask: str = "",
                          source: str = "bacnet:read-bdt") -> None:
    """Attach one BDT peer entry to `host`. Idempotent per
    (self_port, bdt_peer, bdt_port). Silently drops empty peer IPs."""
    peer = _norm(bdt_peer)
    if host is None or not peer:
        return
    existing = getattr(host, "bacnet_networks", None)
    if existing is None:
        existing = []
        host.bacnet_networks = existing  # type: ignore[attr-defined]
    for e in existing:
        if (e.get("bdt_peer") == peer
                and int(e.get("bdt_port", 0)) == int(bdt_port)
                and int(e.get("port", 0)) == int(port)):
            return
    existing.append({"ip": ip or getattr(host, "ip", "") or "",
                     "port": int(port), "bdt_peer": peer,
                     "bdt_port": int(bdt_port),
                     "mask": _norm(mask),
                     "source": source or "bacnet:read-bdt"})


def bacnet_networks_for(host: Host) -> list[dict]:
    """Every BDT peer recorded against `host`, insertion order."""
    return [dict(e) for e in (getattr(host, "bacnet_networks", None) or [])]


def known_bacnet_networks(hosts: list[Host]) -> dict:
    """Engagement-wide BBMD topology.

    Returns:
      {"networks": [{ip, port, bdt_peer, bdt_port, mask, source}, ...],
       "by_ip":    {ip: [{bdt_peer, bdt_port}, ...]},
       "ips":      [ip, ...]}

    `by_ip` groups by the BBMD that DISCLOSED the peer (self_ip), not by
    peer — the reporter draws an edge from ip -> bdt_peer per entry."""
    networks: list[dict] = []
    by_ip: dict[str, list[dict]] = {}
    for h in hosts:
        for rec in bacnet_networks_for(h):
            ip = rec.get("ip") or getattr(h, "ip", "") or ""
            networks.append(rec)
            by_ip.setdefault(ip, []).append(
                {"bdt_peer": rec.get("bdt_peer", ""),
                 "bdt_port": int(rec.get("bdt_port") or 0)})
    return {"networks": networks, "by_ip": by_ip, "ips": sorted(by_ip)}
