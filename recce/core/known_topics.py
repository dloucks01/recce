"""Cross-service "MQTT topic namespace known to this engagement" reader.

Every enumeration path that observes a topic on an MQTT broker — a
retained-message replay after SUBSCRIBE `#` (OASIS MQTT v3.1.1 §3.3
RETAIN=1, replayed to new subscribers per §3.3.1.3), a live PUBLISH
arriving in the subscribe window (RETAIN=0), the $SYS/# scrape
(non-standard but universally implemented), Last-Will topics observed
after a client disconnect — lands the same fact about the same broker:
this topic exists in its namespace, and here's what we know about the
payload behind it. Consumers today reach into each `probe.retained` /
`probe.live` list directly, but the wanted view is one topic inventory:

  * for THIS broker, every distinct topic observed (deduped by topic
    string; a retained observation and a subsequent live observation on
    the same topic collapse into one row)
  * for the WHOLE engagement, indexes by broker and by first-segment
    prefix so an operator can see "shelly/ appears on 3 brokers"
    without walking the raw retained-message lists

Producers WRITE via `record_topic(host, topic, ...)`; the reader
never invents identity — the store is the authority.

Topics are strictly case-SENSITIVE on the wire (§4.7.1.1) but IoT
vendors ship consistent casing per device family, so the inventory
deduplicates case-insensitively with first-seen casing preserved for
display — the same "shelly/" family reported as `Shelly/1` by one
device and `shelly/1` by another is one entry, not two.
"""
from __future__ import annotations

from .models import Host


def _clean(topic: str) -> str:
    """Lower-case + strip. Trailing `/` is not part of the level path
    per §4.7.1.1 so it's dropped for the dedup key only."""
    t = (topic or "").strip()
    if len(t) > 1 and t.endswith("/"):
        t = t.rstrip("/")
    return t.lower()


def record_topic(host: Host, topic: str, *, retained: bool = False,
                 payload_size: int = 0, source: str = "") -> None:
    """Producer entry point. Attach one topic observation to `host` (the
    broker), or merge into the existing row when the same topic (case-
    insensitive) has been seen before on this broker.

    Merge rules:
      * `retained` is a monotonic OR — if ANY sighting of this topic
        carried RETAIN=1, the aggregated row is retained (a broker with
        no retained message for this topic today may have had one
        cleared moments before we joined).
      * `payload_size` keeps the largest observation — the retained
        payload is usually the meaningful size to surface.
      * `source` is appended to the sources list, deduped.
    Silently drops empty topic strings so callers don't have to guard
    the "no retained messages" path."""
    t = (topic or "").strip()
    if host is None or not t:
        return
    key = _clean(t)
    if not key:
        return
    src = (source or "").strip()
    existing = getattr(host, "topics", None)
    if existing is None:
        existing = []
        # Dataclass without __slots__ — arbitrary attr assignment fine.
        # Not persisted through to_json/from_json; live in-session store.
        object.__setattr__(host, "topics", existing)
    for rec in existing:
        if _clean(rec.get("topic", "")) == key:
            if retained:
                rec["retained"] = True
            sz = int(payload_size or 0)
            if sz > int(rec.get("payload_size") or 0):
                rec["payload_size"] = sz
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            return
    rec = {"broker_ip": host.ip, "topic": t, "retained": bool(retained),
           "payload_size": int(payload_size or 0), "sources": []}
    if src:
        rec["sources"].append(src)
    existing.append(rec)


def topics_for(host: Host) -> list[dict]:
    """Every topic recorded on this broker, insertion order preserved.
    Returned dicts are shallow copies so consumer mutation cannot
    corrupt the store."""
    out: list[dict] = []
    for rec in getattr(host, "topics", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def _first_segment(topic: str) -> str:
    """The topic's first level (before the first `/`). Per §4.7.1.2 a
    leading `$` marks a broker-reserved namespace (`$SYS/...`) and we
    keep it verbatim — it's the meaningful prefix, not noise."""
    t = (topic or "").strip().lstrip("/")
    if not t:
        return ""
    return t.split("/", 1)[0]


def known_topics(hosts: list[Host]) -> dict:
    """Engagement-wide MQTT topic-namespace inventory.

    Returns:
      {"topics":    [{"broker_ip", "topic", "retained",
                      "payload_size", "sources": [str]}, ...],
       "by_broker": {ip: [topic, ...]},
       "by_prefix": {first_segment: count}}

    `topics` is deduped per (broker_ip, topic_lc) — the same topic seen
    both retained and live on one broker is one row. `by_prefix` counts
    distinct (broker, topic) pairs, so "shelly/" appearing on three
    brokers reads 3, not (retained+live) doubled.
    """
    topics: list[dict] = []
    seen: dict[tuple[str, str], dict] = {}
    by_broker: dict[str, list[str]] = {}
    by_prefix: dict[str, int] = {}
    for h in hosts:
        broker_seen: set[str] = set()
        for rec in topics_for(h):
            k = (h.ip, _clean(rec.get("topic", "")))
            if not k[1]:
                continue
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                topics.append(rec)
                bucket = by_broker.setdefault(h.ip, [])
                if rec["topic"] not in bucket:
                    bucket.append(rec["topic"])
                if k[1] not in broker_seen:
                    broker_seen.add(k[1])
                    seg = _first_segment(rec["topic"])
                    if seg:
                        by_prefix[seg] = by_prefix.get(seg, 0) + 1
                continue
            # Duplicate rows within one host's store — merge conservatively.
            if rec.get("retained"):
                entry["retained"] = True
            sz = int(rec.get("payload_size") or 0)
            if sz > int(entry.get("payload_size") or 0):
                entry["payload_size"] = sz
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)
    return {"topics": topics, "by_broker": by_broker,
            "by_prefix": by_prefix}
