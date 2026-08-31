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
  * kafka_version_fingerprint (info) — the ApiVersionsResponse's advertised
    (api_key, min, max) tuple set pinned the broker to a release line
    (>=2.7 / >=2.8 / >=3.0 / >=3.7 depending on which KIP-introduced keys
    are present). Feeds the version-DB pass, not itself a vulnerability.
  * kafka_sasl_mechanisms_enumerated (medium) — on SASL-gated brokers a
    KIP-43 SaslHandshake probe returns enabled_mechanisms unconditionally,
    telling downstream credential-spray which mechanism to use (PLAIN vs
    SCRAM vs GSSAPI vs OAUTHBEARER).

Airgap-safe: stdlib socket + struct only. Bounded (single request/response).
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 9092
_TIMEOUT = 4.0

# API keys we use
_API_METADATA = 3
_API_VERSIONS = 18
_API_SASL_HANDSHAKE = 17         # KIP-43 SaslHandshakeRequest

# Any-mechanism string we send in SaslHandshakeRequest solely to elicit the
# UNSUPPORTED_SASL_MECHANISM path — the broker's response then always contains
# the array of ACTUALLY enabled mechanisms (KIP-43 §"Server response"). Using a
# nonsense value keeps us from accidentally initiating a real SASL exchange on
# a listener where that mechanism happens to be configured.
_SASL_PROBE_MECH = "RECCE-PROBE"


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


def _build_metadata_request_v1(topics: list | None = None) -> bytes:
    """MetadataRequest v1: topics=null asks for ALL topics. Same request body
    as v0 but Apache Kafka 3.x KRaft rejects v0 outright despite the
    ApiVersions handshake claiming min=0 — v1 works on both modern and
    legacy brokers, and adds broker.rack + controller_id + topic.is_internal
    to the response (which we skip past — we only need broker/topic names)."""
    return _build_request(_API_METADATA, 1, 1, _array_nullable(topics))


def _build_api_versions_v0() -> bytes:
    """ApiVersionsRequest v0 — an empty body. Modern Kafka (>= 2.4) refuses
    to answer any other request from a client that hasn't done ApiVersions
    first (KIP-511). Sending this handshake keeps the probe working against
    both legacy and modern brokers."""
    return _build_request(_API_VERSIONS, 0, 100, b"")


def _build_sasl_handshake_v1(mechanism: str,
                             correlation_id: int = 2) -> bytes:
    """SaslHandshakeRequest v1 (KIP-43): a single STRING mechanism (int16 len +
    UTF-8). Both v0 and v1 have the same body shape; v1 is what modern brokers
    negotiate and what SaslAuthenticate expects to follow. We send it with a
    deliberately nonsense mechanism ('RECCE-PROBE'): the broker replies with
    error_code=UNSUPPORTED_SASL_MECHANISM (33) and, in the same body, the array
    of ENABLED mechanisms — which is exactly the fact we want to enumerate,
    without any risk of accidentally opening a real SASL exchange."""
    return _build_request(_API_SASL_HANDSHAKE, 1, correlation_id,
                          _string(mechanism))


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


def _parse_metadata_v1(body: bytes) -> dict | None:
    """Parse a MetadataResponse v1 body (post-size):
      correlation_id (int32)
      brokers: [{node_id: int32, host: string, port: int32, rack: nullable_string}]
      controller_id: int32
      topics: [{error: int16, name: string, is_internal: bool,
                partitions: [{error, id, leader, replicas[], isr[]}]}]
    Return {brokers, topics} on success; None on parse failure."""
    if len(body) < 4:
        return None
    try:
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
            # v1 adds `rack` as a nullable_string.
            _rack, i = _parse_string_at(body, i)
            brokers.append({"node_id": node_id, "host": host, "port": port})
        # controller_id (v1 addition)
        if i + 4 > len(body):
            return {"brokers": brokers, "topics": []}
        i += 4                                # skip controller_id
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
            # v1 adds is_internal bool
            if i + 1 > len(body): break
            i += 1                            # skip is_internal
            # Skip partition array — we don't need per-partition detail.
            if i + 4 > len(body): break
            n_parts = struct.unpack(">i", body[i:i + 4])[0]; i += 4
            for _ in range(max(0, n_parts)):
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


# Back-compat alias for tests that reference the v0 name.
_parse_metadata_v0 = _parse_metadata_v1


def _parse_api_versions(body: bytes) -> dict | None:
    """Parse an ApiVersionsResponse v0/v1 body (post-size):
      correlation_id (int32)
      error_code    (int16)
      api_versions: [{api_key: int16, min_version: int16, max_version: int16}]
      (v1 appends throttle_time_ms int32 — we don't need it)
    Return {"error": int, "apis": {api_key: (min, max)}} or None on parse fail."""
    if len(body) < 10:
        return None
    try:
        i = 4                                              # correlation_id
        err = struct.unpack(">h", body[i:i + 2])[0]; i += 2
        n = struct.unpack(">i", body[i:i + 4])[0]; i += 4
        if n < 0 or n > 300:                               # sanity cap
            return None
        apis: dict[int, tuple[int, int]] = {}
        for _ in range(n):
            if i + 6 > len(body):
                break
            k, mn, mx = struct.unpack(">hhh", body[i:i + 6]); i += 6
            apis[k] = (mn, mx)
        return {"error": err, "apis": apis}
    except (struct.error, IndexError):
        return None


def _fingerprint(apis: dict) -> str:
    """Best-effort Kafka release-line label from advertised (api_key, max_version)
    tuples. Signals (from Kafka KIPs / release notes):
      * ApiKey 68 present (ConsumerGroupHeartbeat, KIP-848)     -> ">=3.7"
      * ApiKey 60 present (DescribeCluster, KIP-700)            -> ">=2.8"
      * ApiKey 50 present (DescribeUserScramCredentials, KIP-554) -> ">=2.7"
      * max Produce (ApiKey 0) >= 10                            -> ">=3.0"
      * ApiKey 22 present (InitProducerId)                      -> ">=0.11"
    Return "" when nothing is conclusive. Deliberately no CVE claims — that
    mapping belongs to a version-DB layer, not this parser."""
    if not apis:
        return ""
    if 68 in apis:
        return ">=3.7"
    if 60 in apis and apis.get(0, (0, 0))[1] >= 10:
        return ">=3.0"
    if 60 in apis:
        return ">=2.8"
    if 50 in apis:
        return ">=2.7"
    if apis.get(0, (0, 0))[1] >= 10:
        return ">=3.0"
    if 22 in apis:
        return ">=0.11"
    return ""


def _parse_sasl_handshake(body: bytes) -> dict | None:
    """Parse a SaslHandshakeResponse v0/v1 body (post-size):
      correlation_id (int32)
      error_code     (int16)   -- 0 = supported, 33 = UNSUPPORTED_SASL_MECHANISM
      enabled_mechanisms: [STRING]  -- int32 count + [int16 len + UTF-8 bytes]
    The enabled_mechanisms array is returned whether or not error_code is 0
    (KIP-43 §"Server response"), so a nonsense probe mechanism reliably yields
    the real list. Return {"error": int, "mechanisms": [str]} or None."""
    if len(body) < 10:
        return None
    try:
        i = 4                                              # correlation_id
        err = struct.unpack(">h", body[i:i + 2])[0]; i += 2
        n = struct.unpack(">i", body[i:i + 4])[0]; i += 4
        if n < 0 or n > 64:                                # sanity cap
            return None
        mechs: list[str] = []
        for _ in range(n):
            m, i = _parse_string_at(body, i)
            if m:
                mechs.append(m)
        return {"error": err, "mechanisms": mechs}
    except (struct.error, IndexError):
        return None


def _probe_sasl_mechanisms(ip: str, port: int, timeout: float) -> list[str]:
    """Open a separate short-lived TCP session to <ip:port>, negotiate the
    ApiVersions handshake, then send one SaslHandshakeRequest v1 with a
    nonsense mechanism and parse the enabled_mechanisms array from the reply.
    Returns [] on any transport failure or parse failure.

    Bounded: single TCP connect, two request/response exchanges, one timeout.
    Uses a fresh connection because a broker that rejected our earlier request
    (SASL-gated) may have already half-closed the metadata probe's socket."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_api_versions_v0())
            _read_response(s, timeout)                    # discard: handshake
            s.sendall(_build_sasl_handshake_v1(_SASL_PROBE_MECH))
            body = _read_response(s, timeout)
    except OSError:
        return []
    if not body:
        return []
    parsed = _parse_sasl_handshake(body)
    if not parsed:
        return []
    return parsed["mechanisms"]


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Send MetadataRequest v1 and parse the reply. Returns
    {reachable, brokers, topics, api_versions, fingerprint, sasl_mechanisms,
    error}. brokers/topics empty if the request was dropped or the parse
    failed; api_versions/fingerprint populated when the ApiVersions handshake
    reply parsed; sasl_mechanisms populated on SASL-gated brokers only."""
    out: dict = {"reachable": False, "brokers": [], "topics": [],
                 "api_versions": {}, "fingerprint": "",
                 "sasl_mechanisms": [], "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # ApiVersions handshake first — modern Kafka (KIP-511) closes
            # the connection on any non-ApiVersions first request. We now
            # PARSE the reply too: its (api_key, min, max) tuple set uniquely
            # fingerprints the broker's release line (see _fingerprint).
            s.sendall(_build_api_versions_v0())
            apiv_body = _read_response(s, timeout)
            if apiv_body:
                apiv = _parse_api_versions(apiv_body)
                if apiv:
                    out["api_versions"] = apiv["apis"]
                    out["fingerprint"] = _fingerprint(apiv["apis"])
            # Now the real query.
            s.sendall(_build_metadata_request_v1())
            body = _read_response(s, timeout)
    except OSError as e:
        out["error"] = str(e)
        return out
    if body is None or len(body) < 8:
        # Reachable at TCP but no metadata came back — SASL/mTLS likely required.
        # Enumerate advertised SASL mechanisms on a fresh connection (KIP-43):
        # this is the single most useful pre-auth fact against a SASL-gated
        # broker, since it dictates which mechanism a spray campaign must use.
        out["reachable"] = True
        out["error"] = "no metadata response — SASL/mTLS may be required"
        out["sasl_mechanisms"] = _probe_sasl_mechanisms(ip, port, timeout)
        return out
    parsed = _parse_metadata_v1(body)
    if parsed is None:
        out["reachable"] = True
        out["error"] = "response parse failed (not Kafka? SASL required?)"
        out["sasl_mechanisms"] = _probe_sasl_mechanisms(ip, port, timeout)
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


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "kcat", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


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
                    ["CWE-306", "CWE-200"], kind="kafka_metadata_leaked",
                    exploit_note=(
                        f"kcat -L -b {h.ip}:{p.portid}  ; then: kcat -C -b "
                        f"{h.ip}:{p.portid} -t <leaked-topic> -o beginning "
                        "-c 20  # read messages"),
                    depth_tier="t1"))
            else:
                out.append(_finding(
                    "info", "Kafka endpoint reachable (SASL/mTLS suspected)", tgt,
                    f"TCP connect succeeded but MetadataRequest was refused "
                    f"({pr.get('error','')[:100]}). Broker likely requires "
                    f"SASL_SSL — any looted credential targets this endpoint.",
                    f"kcat -L -b {h.ip}:{p.portid} -X security.protocol=SASL_SSL",
                    "Ensure SASL/mTLS enforcement stays on.",
                    [], kind="kafka_saslgated"))
            # ApiVersions release-line fingerprint (informational, always emit
            # when the handshake reply parsed cleanly enough to derive one).
            fp = pr.get("fingerprint") or ""
            if fp:
                napis = len(pr.get("api_versions") or {})
                out.append(_finding(
                    "info", f"Kafka broker release fingerprint {fp}", tgt,
                    f"ApiVersionsResponse advertised {napis} API keys; the set "
                    f"is consistent with Kafka {fp}. Use this to scope the "
                    f"version-DB / KEV lookup for this broker.",
                    f"kcat -L -b {h.ip}:{p.portid}",
                    "Fingerprint alone is not a vulnerability; feed it to the "
                    "version-DB pass to enumerate patched vs affected releases.",
                    ["CWE-200"], kind="kafka_version_fingerprint"))
            # SaslHandshake enumeration — attempted only on SASL-gated brokers
            # (probe() gates the second connection there). Non-empty means the
            # broker told us exactly which mechanisms are enabled, which is the
            # single most useful pre-auth fact for a credentialed pivot.
            mechs = pr.get("sasl_mechanisms") or []
            if mechs:
                mech_txt = ", ".join(mechs[:8]) + (
                    "…" if len(mechs) > 8 else "")
                out.append(_finding(
                    "medium",
                    "Kafka SASL mechanisms enumerated (KIP-43 SaslHandshake)",
                    tgt,
                    f"SaslHandshakeRequest with a probe mechanism returned the "
                    f"broker's enabled_mechanisms array: {mech_txt}. Any spray "
                    f"campaign against this broker must select one of these; "
                    f"presence of PLAIN typically means reused LDAP/DB "
                    f"passwords are viable, GSSAPI implies a Kerberos KDC, "
                    f"OAUTHBEARER implies a JWT issuer (Keycloak / Okta).",
                    f"kcat -L -b {h.ip}:{p.portid} "
                    f"-X security.protocol=SASL_SSL "
                    f"-X sasl.mechanism={mechs[0]}",
                    "SASL mechanism enumeration is by design in KIP-43; the "
                    "mitigation is to strip PLAIN unless the listener is "
                    "TLS-wrapped and to restrict which listeners advertise "
                    "SASL at all (private-network listeners only).",
                    ["CWE-200"], kind="kafka_sasl_mechanisms_enumerated"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Metadata (list brokers + topics)",
         "cmd": f"kcat -L -b {ip}:{port}"},
        {"step": "Consume from a topic (if leaked)",
         "cmd": f"kcat -C -b {ip}:{port} -t <topic> -o beginning -c 10"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kafka", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
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
                t["fingerprint"] = pr.get("fingerprint", "")
                t["sasl_mechanisms"] = pr.get("sasl_mechanisms", [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
