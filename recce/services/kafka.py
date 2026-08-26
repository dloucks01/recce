"""Apache Kafka MetadataRequest probe.

Kafka (9092/tcp) speaks a binary protocol over TCP. Without SASL/SSL, any
client can send a MetadataRequest v0 and receive back the full list of
brokers and topics — the cluster's public inventory. On SASL_SSL-configured
brokers this either returns an error code or drops the connection at the
protocol handshake stage.

Findings:
  * kafka_metadata_leaked (HIGH) — MetadataRequest returned brokers/topics
    without any authentication. Topic names alone often disclose intent
    (billing-events, user-pii-*, audit-log-prod).
  * kafka_saslgated (info) — reachable but the metadata request was
    denied or dropped, suggesting SASL/mTLS is enforcing.

Airgap-safe: stdlib socket + struct only. Bounded (single request/response).
"""
from __future__ import annotations

import socket
import struct

from ..models import Host, Port


_DEFAULT_PORT = 9092
_TIMEOUT = 4.0

# API keys we use
_API_METADATA = 3
_API_VERSIONS = 18


def is_kafka(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (9092, 9093, 9094)
            or "kafka" in svc or "kafka" in prod)


def _string(s: str | None) -> bytes:
    """Kafka NULLABLE_STRING wire format: int16 length + UTF-8 bytes;
    length=-1 means null."""
    if s is None:
        return struct.pack(">h", -1)
    b = s.encode("utf-8")
    return struct.pack(">h", len(b)) + b


def _array_nullable(items: list | None) -> bytes:
    """Kafka NULLABLE array: int32 count (-1 = null); items serialized in
    caller-appropriate format. Used here only for topic-name lists."""
    if items is None:
        return struct.pack(">i", -1)
    out = struct.pack(">i", len(items))
    for it in items:
        out += _string(it)
    return out


def _build_request(api_key: int, api_version: int,
                   correlation_id: int, body: bytes,
                   client_id: str = "recce") -> bytes:
    """Kafka request framing: size + header + body. Header is api_key(int16),
    api_version(int16), correlation_id(int32), client_id(nullable_string)."""
    hdr = (struct.pack(">h", api_key)
           + struct.pack(">h", api_version)
           + struct.pack(">i", correlation_id)
           + _string(client_id))
    payload = hdr + body
    return struct.pack(">i", len(payload)) + payload


def _build_metadata_request_v0(topics: list | None = None) -> bytes:
    """MetadataRequest v0: topics=null asks for ALL topics; empty list is
    invalid in v0 (server errors) — we default to null."""
    return _build_request(_API_METADATA, 0, 1, _array_nullable(topics))


def _read_response(sock: socket.socket, timeout: float) -> bytes | None:
    """Read one length-prefixed Kafka response. Returns the body (post-size),
    or None on any transport-level failure."""
    try:
        sock.settimeout(timeout)
        size_bytes = _recvn(sock, 4)
        if not size_bytes or len(size_bytes) < 4:
            return None
        size = struct.unpack(">i", size_bytes)[0]
        if size < 0 or size > 10_000_000:      # 10 MB sanity cap
            return None
        return _recvn(sock, size)
    except (OSError, struct.error):
        return None


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes or return whatever we got (short-circuit on EOF)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_string_at(data: bytes, i: int) -> tuple[str, int]:
    """Parse Kafka STRING at offset i; return (value, next_offset).
    STRING is int16 length + bytes; -1 = null (represented as '')."""
    if i + 2 > len(data):
        return "", i
    n = struct.unpack(">h", data[i:i + 2])[0]
    i += 2
    if n <= 0:
        return "", i
    s = data[i:i + n].decode("utf-8", "replace")
    return s, i + n


def _parse_metadata_v0(body: bytes) -> dict | None:
    """Parse a MetadataResponse v0 body (post-size, post-correlation-id):
      correlation_id (int32) — already sliced off before this
      brokers: [{node_id: int32, host: string, port: int32}]
      topics:  [{error: int16, name: string, partitions: [...]}]
    Return {brokers, topics} on success; None on parse failure."""
    if len(body) < 4:
        return None
    try:
        # Skip correlation_id (already consumed by caller? — no, keep it here).
        i = 4  # correlation_id
        # Brokers
        n_brokers = struct.unpack(">i", body[i:i + 4])[0]; i += 4
        if n_brokers < 0 or n_brokers > 10_000:
            return None
        brokers: list[dict] = []
        for _ in range(n_brokers):
            node_id = struct.unpack(">i", body[i:i + 4])[0]; i += 4
            host, i = _parse_string_at(body, i)
            port = struct.unpack(">i", body[i:i + 4])[0]; i += 4
            brokers.append({"node_id": node_id, "host": host, "port": port})
        # Topics
        if i + 4 > len(body):
            return {"brokers": brokers, "topics": []}
        n_topics = struct.unpack(">i", body[i:i + 4])[0]; i += 4
        if n_topics < 0 or n_topics > 100_000:
            return {"brokers": brokers, "topics": []}
        topics: list[dict] = []
        for _ in range(n_topics):
            if i + 2 > len(body): break
            err = struct.unpack(">h", body[i:i + 2])[0]; i += 2
            name, i = _parse_string_at(body, i)
            # Skip partition array — we don't need per-partition detail.
            if i + 4 > len(body): break
            n_parts = struct.unpack(">i", body[i:i + 4])[0]; i += 4
            for _ in range(max(0, n_parts)):
                # Each partition: error(2) + partition_id(4) + leader(4) +
                # replicas array + isr array. Skip past all of it.
                if i + 14 > len(body): break
                i += 2 + 4 + 4                # error + partition + leader
                n_repl = struct.unpack(">i", body[i:i + 4])[0]; i += 4
                i += 4 * max(0, n_repl)
                if i + 4 > len(body): break
                n_isr = struct.unpack(">i", body[i:i + 4])[0]; i += 4
                i += 4 * max(0, n_isr)
            topics.append({"error": err, "name": name})
        return {"brokers": brokers, "topics": topics}
    except (struct.error, IndexError):
        return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Send MetadataRequest v0 and parse the reply. Returns
    {reachable, brokers, topics, error} — brokers/topics empty if the
    request was dropped or the parse failed."""
    out = {"reachable": False, "brokers": [], "topics": [], "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_metadata_request_v0())
            body = _read_response(s, timeout)
    except OSError as e:
        out["error"] = str(e)
        return out
    if body is None or len(body) < 8:
        # Reachable at TCP but no metadata came back — SASL/mTLS likely required.
        out["reachable"] = True
        out["error"] = "no metadata response — SASL/mTLS may be required"
        return out
    parsed = _parse_metadata_v0(body)
    if parsed is None:
        out["reachable"] = True
        out["error"] = "response parse failed (not Kafka? SASL required?)"
        return out
    out["reachable"] = True
    out["brokers"] = parsed["brokers"]
    out["topics"] = [t["name"] for t in parsed["topics"] if t["name"]]
    return out


def kafka_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_kafka(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "kcat", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_kafka(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            brokers = pr.get("brokers") or []
            topics = pr.get("topics") or []
            if brokers or topics:
                broker_txt = ", ".join(f"{b['host']}:{b['port']}" for b in brokers[:5])
                topic_txt = ", ".join(topics[:12])
                out.append(_finding(
                    "high", "Kafka broker returns metadata without authentication",
                    tgt,
                    f"MetadataRequest v0 succeeded without SASL/mTLS. "
                    f"{len(brokers)} broker(s): {broker_txt or 'none'}. "
                    f"{len(topics)} topic(s): {topic_txt or 'none'}"
                    + ("… (truncated)" if len(topics) > 12 else "")
                    + ". Topic names often disclose data intent (pii, billing, audit).",
                    f"kcat -L -b {h.ip}:{p.portid}",
                    "Enable SASL_SSL (SASL_PLAINTEXT at minimum) on the listener; "
                    "disable ANONYMOUS ACLs; bind Kafka to a private interface.",
                    ["CWE-306", "CWE-200"], kind="kafka_metadata_leaked"))
            else:
                out.append(_finding(
                    "info", "Kafka endpoint reachable (SASL/mTLS suspected)", tgt,
                    f"TCP connect succeeded but MetadataRequest was refused "
                    f"({pr.get('error','')[:100]}). Broker likely requires "
                    f"SASL_SSL — any looted credential targets this endpoint.",
                    f"kcat -L -b {h.ip}:{p.portid} -X security.protocol=SASL_SSL",
                    "Ensure SASL/mTLS enforcement stays on.",
                    [], kind="kafka_saslgated"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Metadata (list brokers + topics)",
         "cmd": f"kcat -L -b {ip}:{port}"},
        {"step": "Consume from a topic (if leaked)",
         "cmd": f"kcat -C -b {ip}:{port} -t <topic> -o beginning -c 10"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kafka", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from .. import svcprobe
    targets = kafka_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["topics"] = len(pr.get("topics", []))
                t["brokers"] = len(pr.get("brokers", []))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
