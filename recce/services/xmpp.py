"""Deep XMPP enumeration (stdlib only). RFC 6120 c2s / s2s streams.

Two probe layers, both airgapped:

  * **Passive fingerprint (credfree):** open a stream, read <stream:features/>,
    record advertised SASL mechanisms, STARTTLS presence / required, in-band
    registration, bind, compression, and the 'from' attribute (canonical XMPP
    domain). A second stream-open with a bogus 'to' triggers a <stream:error/>
    whose text distinguishes Prosody / ejabberd / OpenFire.
  * **Active probes (post-STARTTLS if offered):** anonymous SASL bind (ANONYMOUS
    mechanism) yielding a JID, jabber:iq:register (XEP-0077) form availability,
    jabber:iq:version (XEP-0092) product name, and disco#items / disco#info
    (XEP-0030) to enumerate MUC / HTTP-Upload / proxy65 / pubsub components.

Every response is parsed defensively with narrow regexes (no ET on untrusted
stream XML - keeps entity-expansion and namespace-prefix quirks out of scope).

Findings fold into the severity totals via svccommon (source='xmpp').
"""
from __future__ import annotations

import re
import socket
import ssl

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder

_DEFAULT_PORT = 5222
_PORTS = (5222, 5223, 5269)
_LEGACY_TLS_PORT = 5223
_S2S_PORT = 5269
_TIMEOUT = 4.0

_XMLNS_CLIENT = "jabber:client"
_XMLNS_SERVER = "jabber:server"
_XMLNS_STREAMS = "http://etherx.jabber.org/streams"
_XMLNS_TLS = "urn:ietf:params:xml:ns:xmpp-tls"
_XMLNS_SASL = "urn:ietf:params:xml:ns:xmpp-sasl"
_XMLNS_BIND = "urn:ietf:params:xml:ns:xmpp-bind"
_XMLNS_DISCO_ITEMS = "http://jabber.org/protocol/disco#items"
_XMLNS_DISCO_INFO = "http://jabber.org/protocol/disco#info"
_XMLNS_REGISTER = "jabber:iq:register"
_XMLNS_VERSION = "jabber:iq:version"
_XMLNS_MUC = "http://jabber.org/protocol/muc"
_XMLNS_HTTP_UPLOAD = "urn:xmpp:http:upload:0"

_STREAM_OPEN_RE = re.compile(rb"<stream:stream[^>]*")
_FROM_RE = re.compile(rb'''from=(?:"([^"]+)"|'([^']+)')''')
_MECHANISM_RE = re.compile(rb"<mechanism>([^<]+)</mechanism>", re.I)
_STARTTLS_OFFERED_RE = re.compile(
    rb"<starttls[^>]*xmlns=(?:\"|')urn:ietf:params:xml:ns:xmpp-tls(?:\"|')", re.I)
_STARTTLS_REQUIRED_RE = re.compile(
    rb"<starttls[^>]*xmlns=(?:\"|')urn:ietf:params:xml:ns:xmpp-tls(?:\"|')[^>]*>"
    rb"\s*<required\s*/?>", re.I)
_REGISTER_FEATURE_RE = re.compile(
    rb"<register[^>]*xmlns=(?:\"|')http://jabber\.org/features/iq-register(?:\"|')",
    re.I)
_BIND_FEATURE_RE = re.compile(
    rb"<bind[^>]*xmlns=(?:\"|')urn:ietf:params:xml:ns:xmpp-bind(?:\"|')", re.I)
_SESSION_FEATURE_RE = re.compile(
    rb"<session[^>]*xmlns=(?:\"|')urn:ietf:params:xml:ns:xmpp-session(?:\"|')", re.I)
_COMPRESSION_FEATURE_RE = re.compile(
    rb"<compression[^>]*xmlns=(?:\"|')http://jabber\.org/features/compress(?:\"|')",
    re.I)
_DIALBACK_FEATURE_RE = re.compile(
    rb"<dialback[^>]*xmlns=(?:\"|')urn:xmpp:features:dialback(?:\"|')", re.I)
_STREAM_ERROR_RE = re.compile(rb"<stream:error[^>]*>(.*?)</stream:error>", re.I | re.S)
_STREAM_VERSION_RE = re.compile(rb'''version=(?:"([^"]+)"|'([^']+)')''')

# Server-fingerprint substrings observed in <stream:error/> bodies and greetings.
_PRODUCT_HINTS = [
    (re.compile(rb"Prosody", re.I), "Prosody"),
    (re.compile(rb"ejabberd", re.I), "ejabberd"),
    (re.compile(rb"OpenFire|Openfire|Jive Software", re.I), "Openfire"),
    (re.compile(rb"Tigase", re.I), "Tigase"),
    (re.compile(rb"M-?Link|Isode", re.I), "M-Link"),
]

# Weak SASL mechanisms — deprecated / plaintext / relay-abusable.
_WEAK_SASL = {"PLAIN", "LOGIN", "DIGEST-MD5", "CRAM-MD5"}
_MODERN_SASL = {"SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-1-PLUS",
                "SCRAM-SHA-256-PLUS", "SCRAM-SHA-512", "SCRAM-SHA-512-PLUS"}


def is_xmpp(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid in _PORTS:
        return True
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return ("xmpp" in svc or "jabber" in svc
            or "xmpp" in prod or "jabber" in prod)


def _stream_open(domain: str, is_s2s: bool) -> bytes:
    ns = _XMLNS_SERVER if is_s2s else _XMLNS_CLIENT
    return (f"<?xml version='1.0'?>"
            f"<stream:stream xmlns='{ns}' xmlns:stream='{_XMLNS_STREAMS}' "
            f"to='{domain}' version='1.0'>").encode("utf-8")


def _read_until(sock, needles: tuple[bytes, ...], timeout: float,
                cap: int = 32768) -> bytes:
    """Read until any needle appears, EOF, timeout, or `cap` bytes."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < cap:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            for n in needles:
                if n in buf:
                    return buf
    except (OSError, socket.timeout):
        pass
    return buf


def _parse_features(buf: bytes) -> dict:
    """Extract stream features from a stream-open + features response."""
    out: dict = {"sasl_mechs": [], "starttls_offered": False,
                 "starttls_required": False, "register_offered": False,
                 "bind_offered": False, "session_offered": False,
                 "compression_offered": False, "dialback_offered": False,
                 "stream_version": "", "from_domain": ""}
    m = _FROM_RE.search(buf)
    if m:
        out["from_domain"] = (m.group(1) or m.group(2) or b"").decode(
            "utf-8", "replace")
    m = _STREAM_VERSION_RE.search(buf)
    if m:
        out["stream_version"] = (m.group(1) or m.group(2) or b"").decode(
            "ascii", "replace")
    out["sasl_mechs"] = sorted({
        m.group(1).decode("ascii", "replace").strip()
        for m in _MECHANISM_RE.finditer(buf) if m.group(1).strip()
    })
    out["starttls_offered"] = bool(_STARTTLS_OFFERED_RE.search(buf))
    out["starttls_required"] = bool(_STARTTLS_REQUIRED_RE.search(buf))
    out["register_offered"] = bool(_REGISTER_FEATURE_RE.search(buf))
    out["bind_offered"] = bool(_BIND_FEATURE_RE.search(buf))
    out["session_offered"] = bool(_SESSION_FEATURE_RE.search(buf))
    out["compression_offered"] = bool(_COMPRESSION_FEATURE_RE.search(buf))
    out["dialback_offered"] = bool(_DIALBACK_FEATURE_RE.search(buf))
    return out


def _fingerprint(buf: bytes) -> str:
    for pat, name in _PRODUCT_HINTS:
        if pat.search(buf):
            return name
    return ""


def _connect(ip: str, port: int, timeout: float, legacy_tls: bool = False):
    sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    if legacy_tls:
        ctx = ssl._create_unverified_context()
        sock = ctx.wrap_socket(sock, server_hostname=ip)
    return sock


def _stream_error_probe(ip: str, port: int, timeout: float,
                        is_s2s: bool) -> dict:
    """Open a stream to a bogus 'to' domain and capture the stream error text.
    Returns {product, error_text}."""
    out: dict = {"product": "", "error_text": ""}
    try:
        sock = _connect(ip, port, timeout, legacy_tls=(port == _LEGACY_TLS_PORT))
    except OSError:
        return out
    try:
        sock.sendall(_stream_open("recce-bogus.invalid", is_s2s))
        buf = _read_until(sock, (b"</stream:error>", b"</stream:stream>"),
                          timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    out["product"] = _fingerprint(buf)
    m = _STREAM_ERROR_RE.search(buf)
    if m:
        out["error_text"] = re.sub(rb"<[^>]+>", b" ", m.group(1)).decode(
            "utf-8", "replace").strip()[:400]
    return out


def _starttls_upgrade(sock, timeout: float) -> ssl.SSLSocket | None:
    """Send <starttls/> and, on <proceed/>, wrap the socket. Returns the wrapped
    socket or None on refusal."""
    sock.sendall(f"<starttls xmlns='{_XMLNS_TLS}'/>".encode("ascii"))
    buf = _read_until(sock, (b"<proceed", b"<failure"), timeout)
    if b"<proceed" not in buf:
        return None
    ctx = ssl._create_unverified_context()
    try:
        return ctx.wrap_socket(sock, server_hostname="xmpp")
    except (OSError, ssl.SSLError):
        return None


def _send_iq(sock, iq: str, timeout: float,
             end_needle: bytes = b"</iq>") -> bytes:
    sock.sendall(iq.encode("utf-8"))
    return _read_until(sock, (end_needle,), timeout)


def _sasl_anonymous(sock, timeout: float) -> bool:
    sock.sendall(
        f"<auth xmlns='{_XMLNS_SASL}' mechanism='ANONYMOUS'/>".encode("ascii"))
    buf = _read_until(sock, (b"<success", b"<failure"), timeout)
    return b"<success" in buf


def _bind_resource(sock, timeout: float) -> str:
    iq = (
        f"<iq type='set' id='bind1'>"
        f"<bind xmlns='{_XMLNS_BIND}'><resource>recce</resource></bind>"
        f"</iq>"
    )
    buf = _send_iq(sock, iq, timeout)
    m = re.search(rb"<jid>([^<]+)</jid>", buf)
    return m.group(1).decode("utf-8", "replace") if m else ""


def _register_probe(sock, timeout: float, to_domain: str) -> dict:
    """Send jabber:iq:register get. Returns {offered, error}."""
    iq = (
        f"<iq type='get' id='reg1' to='{to_domain}'>"
        f"<query xmlns='{_XMLNS_REGISTER}'/></iq>"
    )
    buf = _send_iq(sock, iq, timeout)
    offered = (b"jabber:iq:register" in buf
               and b"<error" not in buf
               and (b"<username" in buf or b"<x xmlns='jabber:x:data'" in buf
                    or b"<instructions" in buf
                    or b"<query" in buf))
    return {"offered": bool(offered), "response": buf[:2000].decode(
        "utf-8", "replace")}


def _version_probe(sock, timeout: float, to_domain: str) -> dict:
    iq = (
        f"<iq type='get' id='ver1' to='{to_domain}'>"
        f"<query xmlns='{_XMLNS_VERSION}'/></iq>"
    )
    buf = _send_iq(sock, iq, timeout)
    name = re.search(rb"<name>([^<]+)</name>", buf)
    ver = re.search(rb"<version>([^<]+)</version>", buf)
    os_ = re.search(rb"<os>([^<]+)</os>", buf)
    return {
        "name": name.group(1).decode("utf-8", "replace").strip() if name else "",
        "version": ver.group(1).decode("utf-8", "replace").strip() if ver else "",
        "os": os_.group(1).decode("utf-8", "replace").strip() if os_ else "",
    }


def _disco_items(sock, timeout: float, to: str, node: str = "") -> list[dict]:
    node_attr = f" node='{node}'" if node else ""
    iq = (
        f"<iq type='get' id='di1' to='{to}'>"
        f"<query xmlns='{_XMLNS_DISCO_ITEMS}'{node_attr}/></iq>"
    )
    buf = _send_iq(sock, iq, timeout)
    items = []
    for m in re.finditer(rb"<item\b([^/>]*)/?>", buf):
        attrs = m.group(1)
        j = re.search(rb'''jid=(?:"([^"]+)"|'([^']+)')''', attrs)
        n = re.search(rb'''name=(?:"([^"]+)"|'([^']+)')''', attrs)
        if not j:
            continue
        items.append({
            "jid": (j.group(1) or j.group(2) or b"").decode("utf-8", "replace"),
            "name": ((n.group(1) or n.group(2)).decode("utf-8", "replace")
                     if n else ""),
        })
    return items


def _disco_info(sock, timeout: float, to: str) -> dict:
    iq = (
        f"<iq type='get' id='df1' to='{to}'>"
        f"<query xmlns='{_XMLNS_DISCO_INFO}'/></iq>"
    )
    buf = _send_iq(sock, iq, timeout)
    identities = []
    for m in re.finditer(rb"<identity\b([^/>]*)/?>", buf):
        attrs = m.group(1)
        cat = re.search(rb'''category=(?:"([^"]+)"|'([^']+)')''', attrs)
        typ = re.search(rb'''type=(?:"([^"]+)"|'([^']+)')''', attrs)
        nm = re.search(rb'''name=(?:"([^"]+)"|'([^']+)')''', attrs)
        identities.append({
            "category": ((cat.group(1) or cat.group(2)).decode("utf-8", "replace")
                         if cat else ""),
            "type": ((typ.group(1) or typ.group(2)).decode("utf-8", "replace")
                     if typ else ""),
            "name": ((nm.group(1) or nm.group(2)).decode("utf-8", "replace")
                     if nm else ""),
        })
    features = sorted({
        (m.group(1) or m.group(2)).decode("utf-8", "replace")
        for m in re.finditer(
            rb'''<feature\s+var=(?:"([^"]+)"|'([^']+)')\s*/?>''', buf)
    })
    return {"identities": identities, "features": features}


def _classify_component(identities: list[dict], features: list[str]) -> str:
    """Map a disco#info result to a coarse component kind."""
    for ident in identities:
        cat, typ = ident.get("category", ""), ident.get("type", "")
        if cat == "conference" and typ == "text":
            return "muc"
        if cat == "store" and typ == "file":
            return "http_upload"
        if cat == "proxy" and typ == "bytestreams":
            return "proxy65"
        if cat == "pubsub":
            return "pubsub"
    if _XMLNS_MUC in features:
        return "muc"
    if _XMLNS_HTTP_UPLOAD in features:
        return "http_upload"
    return ""


# --- top-level probe --------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          domain: str = "", active: bool = True) -> dict:
    """Full XMPP capability probe. Returns:
      {reachable, transport, features (dict), server_from, product, version,
       stream_error, tls_negotiated, anonymous, anon_jid, ibr_offered,
       ibr_response, sw_version (dict), disco_items, components,
       legacy_tls_cert}
    `active` gates the anonymous-bind / IBR / disco round-trips; when False the
    probe returns only the passive stream-features view (safe on prod boxes).
    """
    is_s2s = (port == _S2S_PORT)
    legacy_tls = (port == _LEGACY_TLS_PORT)
    to = domain or ip
    out: dict = {
        "reachable": False, "transport": "tcp",
        "features": {}, "server_from": "", "product": "", "version": "",
        "stream_error": "", "tls_negotiated": False,
        "anonymous": False, "anon_jid": "",
        "ibr_offered": False, "ibr_response": "",
        "sw_version": {}, "disco_items": [], "components": [],
        "legacy_tls_cert": {}, "post_tls_features": {},
        "is_s2s": is_s2s, "legacy_tls": legacy_tls,
    }
    try:
        sock = _connect(ip, port, timeout, legacy_tls=legacy_tls)
    except OSError:
        return out
    if legacy_tls:
        out["legacy_tls_cert"] = _grab_legacy_cert(sock)
    try:
        sock.sendall(_stream_open(to, is_s2s))
        buf = _read_until(sock, (b"</stream:features>", b"</stream:error>"),
                          timeout)
        if not _STREAM_OPEN_RE.search(buf):
            try:
                sock.close()
            except OSError:
                pass
            return out
        out["reachable"] = True
        feats = _parse_features(buf)
        out["features"] = feats
        out["server_from"] = feats.get("from_domain", "")
        out["product"] = _fingerprint(buf)
        # Grab any stream error text emitted on the first probe (some servers
        # emit host-unknown when 'to' is unfamiliar).
        m = _STREAM_ERROR_RE.search(buf)
        if m:
            out["stream_error"] = re.sub(rb"<[^>]+>", b" ", m.group(1)).decode(
                "utf-8", "replace").strip()[:400]
    except OSError:
        try:
            sock.close()
        except OSError:
            pass
        return out

    working = sock
    # STARTTLS upgrade if offered — matches how a compliant client would proceed.
    if feats.get("starttls_offered") and not legacy_tls:
        try:
            upgraded = _starttls_upgrade(sock, timeout)
        except OSError:
            upgraded = None
        if upgraded is not None:
            out["tls_negotiated"] = True
            working = upgraded
            try:
                working.sendall(_stream_open(to, is_s2s))
                buf2 = _read_until(
                    working, (b"</stream:features>", b"</stream:error>"),
                    timeout)
                out["post_tls_features"] = _parse_features(buf2)
            except OSError:
                pass

    active_feats = out["post_tls_features"] or feats
    if active and not is_s2s:
        if "ANONYMOUS" in (active_feats.get("sasl_mechs") or []):
            try:
                if _sasl_anonymous(working, timeout):
                    out["anonymous"] = True
                    working.sendall(_stream_open(to, is_s2s))
                    _read_until(working, (b"</stream:features>",), timeout)
                    out["anon_jid"] = _bind_resource(working, timeout)
            except OSError:
                pass
        try:
            reg = _register_probe(working, timeout, to)
            out["ibr_offered"] = reg["offered"]
            out["ibr_response"] = reg["response"]
        except OSError:
            pass
        try:
            out["sw_version"] = _version_probe(working, timeout, to)
        except OSError:
            pass
        try:
            items = _disco_items(working, timeout, to)
            out["disco_items"] = items
            for item in items[:12]:
                try:
                    info = _disco_info(working, timeout, item["jid"])
                except OSError:
                    continue
                kind = _classify_component(info["identities"], info["features"])
                out["components"].append({
                    "jid": item["jid"], "name": item["name"], "kind": kind,
                    "identities": info["identities"],
                    "features": info["features"],
                })
        except OSError:
            pass

    try:
        working.sendall(b"</stream:stream>")
    except OSError:
        pass
    try:
        working.close()
    except OSError:
        pass
    return out


def _grab_legacy_cert(ssock) -> dict:
    """Extract cert facts from a legacy-TLS (5223) connection."""
    try:
        cert = ssock.getpeercert()
    except (ValueError, ssl.SSLError, OSError):
        return {}
    sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
    subj = {p[0][0]: p[0][1] for p in cert.get("subject", ())
            if p and len(p[0]) >= 2}
    issuer = {p[0][0]: p[0][1] for p in cert.get("issuer", ())
              if p and len(p[0]) >= 2}
    return {"sans": sans, "subject_cn": subj.get("commonName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_after": cert.get("notAfter", "")}


# --- MUC room enumeration ---------------------------------------------------

def enum_muc_rooms(ip: str, port: int, muc_jid: str,
                   timeout: float = _TIMEOUT, domain: str = "",
                   cap: int = 25) -> list[dict]:
    """List public MUC rooms hosted by a discovered conference component.
    Only lists — never joins. Returns a bounded room list."""
    try:
        sock = _connect(ip, port, timeout)
    except OSError:
        return []
    try:
        sock.sendall(_stream_open(domain or ip, is_s2s=False))
        _read_until(sock, (b"</stream:features>",), timeout)
        rooms: list[dict] = []
        try:
            items = _disco_items(sock, timeout, muc_jid)
        except OSError:
            items = []
        for it in items[:cap]:
            try:
                info = _disco_info(sock, timeout, it["jid"])
            except OSError:
                info = {"features": [], "identities": []}
            feats = info.get("features") or []
            rooms.append({
                "jid": it["jid"], "name": it.get("name", ""),
                "password_protected": _XMLNS_MUC + "#password" in feats
                    or "muc_passwordprotected" in feats,
                "hidden": "muc_hidden" in feats,
                "members_only": "muc_membersonly" in feats,
                "moderated": "muc_moderated" in feats,
                "logged": "muc_logged" in feats,
            })
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return rooms


def xmpp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_xmpp(p):
                out.append({"ip": h.ip, "hostname": h.hostname,
                            "port": p.portid,
                            "product": p.product or "",
                            "version": p.version or ""})
    return out


# --- narratives -------------------------------------------------------------

_NARRATIVE = {
    "xmpp_starttls_missing": (
        "The XMPP stream does not offer STARTTLS (or offers it without "
        "<required/>). Every SASL exchange on this port crosses the wire in "
        "the clear - a passive sniffer captures PLAIN/LOGIN credentials, and "
        "on 5269 the whole federation stream is readable."),
    "xmpp_ibr_open": (
        "In-band registration (XEP-0077) is open: any unauthenticated peer "
        "can spawn accounts on the server. Directly enables spam / abuse and "
        "gives an attacker a base identity for authenticated features (MUC, "
        "file transfer, roster)."),
    "xmpp_anon_bind": (
        "SASL ANONYMOUS granted an unauthenticated session with an assigned "
        "JID. Any anonymous client can send messages, join public MUC rooms, "
        "and probe rosters - typical of a dev instance left exposed."),
    "xmpp_weak_sasl": (
        "The server advertises PLAIN/LOGIN over an unencrypted transport, or "
        "DIGEST-MD5 / CRAM-MD5 on any transport - all offline-crackable or "
        "sniffable. A modern SCRAM-SHA-* mechanism should be the only option."),
    "xmpp_s2s_dialback_weak": (
        "The s2s (5269) stream offers server-dialback (XEP-0220) without "
        "requiring TLS. Dialback authenticates federation peers by DNS "
        "resolution alone - spoofable on any shared network."),
    "xmpp_muc_public_rooms": (
        "The MUC component lists public rooms whose names / subjects often "
        "leak internal team names, project codewords, and hostnames."),
    "xmpp_disco_components": (
        "Service discovery exposed the server's component map (MUC, "
        "HTTP-Upload, proxy65, pubsub, adhoc). Each is a new probe surface; "
        "an unauthenticated HTTP-Upload endpoint in particular is a common "
        "cross-service pivot."),
    "xmpp_legacy_tls_5223": (
        "5223 is legacy implicit TLS (deprecated per RFC 6120 App B). Clients "
        "using it never negotiate STARTTLS, and 5223-only deployments cannot "
        "be upgraded on the fly."),
    "xmpp_sw_version": (
        "XEP-0092 disclosed the server product + version to an unauthenticated "
        "or anonymous peer - concrete fingerprint that feeds the CVE mapper "
        "(Prosody / ejabberd / Openfire families)."),
    "xmpp_fingerprint": (
        "The stream error / greeting identifies the XMPP server family. "
        "Enough to key vendor-specific CVEs and pick a targeted exploit."),
    "xmpp_cert_mismatch": (
        "The legacy-TLS certificate on 5223 does not cover the stream's own "
        "'from' domain - passive downgrade / MITM is realistic against "
        "clients that do not pin."),
}

_finding = finding_builder("xmpp", _NARRATIVE)


# --- findings ---------------------------------------------------------------

def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_xmpp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            feats = pr.get("features") or {}
            mechs = set(feats.get("sasl_mechs") or [])
            is_s2s = pr.get("is_s2s", False)
            legacy = pr.get("legacy_tls", False)

            # STARTTLS posture. Legacy 5223 already encrypts; skip that leg.
            if not legacy:
                if not feats.get("starttls_offered"):
                    out.append(_finding(
                        "high",
                        "XMPP STARTTLS not offered (cleartext stream)", tgt,
                        f"stream:features on {tgt} advertises no <starttls/>. "
                        f"Every SASL exchange and payload crosses the wire in "
                        f"the clear.",
                        "openssl", f"openssl s_client -starttls xmpp -connect "
                        f"{h.ip}:{p.portid} -xmpphost {pr.get('server_from') or h.ip}",
                        "Enable STARTTLS with <required/> (RFC 7590) and modern "
                        "ciphers; migrate 5223-only clients to 5222+STARTTLS.",
                        ["CWE-319", "CWE-326"], kind="xmpp_starttls_missing"))
                elif not feats.get("starttls_required"):
                    out.append(_finding(
                        "medium",
                        "XMPP STARTTLS offered but not required", tgt,
                        f"stream:features on {tgt} offers <starttls/> without "
                        f"<required/> - a client can skip TLS and auth in clear.",
                        "openssl", f"openssl s_client -starttls xmpp -connect "
                        f"{h.ip}:{p.portid}",
                        "Add <required/> under the STARTTLS feature "
                        "(mandatory-to-implement per RFC 7590).",
                        ["CWE-319"], kind="xmpp_starttls_missing"))

            # In-band registration.
            if pr.get("ibr_offered"):
                out.append(_finding(
                    "high", "XMPP in-band registration open (XEP-0077)", tgt,
                    f"An unauthenticated IQ get for jabber:iq:register on {tgt} "
                    f"returned a registration form: any peer can create accounts.",
                    "python", "python -c 'see recce probe xmpp'",
                    "Disable mod_register (Prosody) / mod_register (ejabberd) "
                    "or restrict it to a trusted network.",
                    ["CWE-306", "CWE-284"], kind="xmpp_ibr_open"))

            # Anonymous SASL success.
            if pr.get("anonymous"):
                jid = pr.get("anon_jid") or "(unnamed)"
                out.append(_finding(
                    "high", "XMPP anonymous SASL bind accepted", tgt,
                    f"SASL ANONYMOUS on {tgt} completed and bound JID '{jid}'. "
                    f"Anonymous peers can send messages / join MUC / probe rosters.",
                    "python", f"python -c 'anon bind to {h.ip}:{p.portid}'",
                    "Remove ANONYMOUS from mod_saslauth mechanisms (Prosody) or "
                    "the equivalent (ejabberd auth_method) on production listeners.",
                    ["CWE-287", "CWE-306"], kind="xmpp_anon_bind"))

            # Weak SASL — flag PLAIN/LOGIN on cleartext; DIGEST/CRAM anywhere.
            weak_here = mechs & _WEAK_SASL
            plain_on_cleartext = ({"PLAIN", "LOGIN"} & mechs) and not (
                legacy or pr.get("tls_negotiated"))
            digest_anywhere = {"DIGEST-MD5", "CRAM-MD5"} & mechs
            if plain_on_cleartext or digest_anywhere:
                shown = sorted(weak_here)
                out.append(_finding(
                    "medium",
                    f"XMPP weak SASL mechanism(s) advertised: {', '.join(shown)}",
                    tgt,
                    f"stream:features on {tgt} advertises {', '.join(shown)}. "
                    f"PLAIN/LOGIN pre-TLS are sniffable; DIGEST-MD5 / CRAM-MD5 "
                    f"are deprecated (RFC 6331) and offline-crackable. Modern "
                    f"SCRAM-SHA-* seen: "
                    f"{sorted(mechs & _MODERN_SASL) or 'none'}.",
                    "openssl", f"openssl s_client -starttls xmpp -connect "
                    f"{h.ip}:{p.portid}   # then look for <mechanism/> list",
                    "Restrict the advertised list to SCRAM-SHA-256(-PLUS); drop "
                    "PLAIN/LOGIN entirely unless the transport is guaranteed TLS.",
                    ["CWE-327", "CWE-319"], kind="xmpp_weak_sasl"))

            # s2s dialback posture (5269-only).
            if is_s2s and feats.get("dialback_offered") and not feats.get(
                    "starttls_required"):
                out.append(_finding(
                    "medium", "XMPP s2s dialback without TLS (spoofable)", tgt,
                    f"5269 on {tgt} offers server-dialback (XEP-0220) without "
                    f"requiring TLS - peer identity rests on DNS trust alone.",
                    "python", f"python -c 'stream 5269 to {h.ip}'",
                    "Require TLS on s2s (s2s_require_encryption = true / "
                    "s2s_use_starttls = required_trusted) and validate cert "
                    "chains against PKIX.",
                    ["CWE-295", "CWE-345"], kind="xmpp_s2s_dialback_weak"))

            # Product fingerprint (drives CVE mapper).
            sw = pr.get("sw_version") or {}
            if sw.get("name"):
                out.append(_finding(
                    "low",
                    f"XMPP software version disclosure: "
                    f"{sw['name']} {sw.get('version','')}".strip(),
                    tgt,
                    f"jabber:iq:version on {tgt} returned name='{sw['name']}' "
                    f"version='{sw.get('version','')}' os='{sw.get('os','')}'."
                    f" Feeds the CVE mapper.",
                    "python", f"python -c 'iq get {_XMLNS_VERSION} to {h.ip}'",
                    "Restrict XEP-0092 to authenticated peers (mod_version "
                    "hide_os_type / iq_version_show).", ["CWE-200"],
                    kind="xmpp_sw_version"))
            elif pr.get("product"):
                out.append(_finding(
                    "low", f"XMPP server fingerprinted: {pr['product']}", tgt,
                    f"stream error / greeting on {tgt} contained a "
                    f"{pr['product']}-specific signature: "
                    f"'{pr.get('stream_error','')[:120]}'.",
                    "python", f"python -c 'stream to bogus on {h.ip}:{p.portid}'",
                    "Suppress product strings from stream errors and greetings "
                    "where possible.", ["CWE-200"], kind="xmpp_fingerprint"))

            # Service-discovery component map.
            comps = pr.get("components") or []
            named = [f"{c.get('kind') or 'component'}={c['jid']}"
                     for c in comps if c.get("jid")]
            if named:
                out.append(_finding(
                    "medium",
                    "XMPP service discovery reveals server components", tgt,
                    f"disco#items on {tgt} enumerated {len(named)} component(s): "
                    f"{', '.join(named[:8])}"
                    + (" …" if len(named) > 8 else "")
                    + ". Each is a probe surface; sub-domain JIDs "
                    "(conference./upload./proxy.) are new hostname facts.",
                    "python", f"python -c 'disco items to {pr.get('server_from') or h.ip}'",
                    "Restrict XEP-0030 to authenticated peers on production; "
                    "disable admin/adhoc components on public listeners.",
                    ["CWE-200"], kind="xmpp_disco_components"))

            # Legacy TLS on 5223.
            if legacy:
                cert = pr.get("legacy_tls_cert") or {}
                sans = cert.get("sans") or []
                from_dom = pr.get("server_from") or ""
                cn = cert.get("subject_cn") or ""
                out.append(_finding(
                    "low", "XMPP legacy implicit-TLS port 5223 exposed", tgt,
                    f"5223 on {tgt} is RFC 6120 App B legacy TLS. Cert CN="
                    f"'{cn}' SAN={sans} expires={cert.get('not_after','')}.",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid} -showcerts",
                    "Migrate clients to 5222 + STARTTLS; retire 5223 once no "
                    "legacy client remains.",
                    ["CWE-295"], kind="xmpp_legacy_tls_5223"))
                if from_dom and sans and not any(
                        _san_covers(s, from_dom) for s in sans + [cn]):
                    out.append(_finding(
                        "low",
                        "XMPP legacy-TLS cert does not match stream 'from' domain",
                        tgt,
                        f"5223 cert (CN='{cn}', SAN={sans}) does not cover "
                        f"stream from-domain '{from_dom}'. Clients skipping "
                        f"strict verification will accept an on-path MITM.",
                        "openssl",
                        f"openssl s_client -connect {h.ip}:{p.portid}",
                        "Re-issue the cert with SAN covering the XMPP domain.",
                        ["CWE-295"], kind="xmpp_cert_mismatch"))
    return out


def _san_covers(san: str, want: str) -> bool:
    """Naive SAN/CN match — exact or single-level wildcard. Kept local to avoid
    pulling in the LDAP/HTTPS TLS helper for one XMPP call site."""
    san = (san or "").lower().rstrip(".")
    want = (want or "").lower().rstrip(".")
    if not san or not want:
        return False
    if san == want:
        return True
    if san.startswith("*."):
        return want.endswith(san[1:]) and want.count(".") == san.count(".")
    return False


# --- runbooks ---------------------------------------------------------------

def credfree_runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script xmpp-info,xmpp-brute {ip}",
         "Confirm stream, list SASL mechs, list disco components."),
        ("recon", "openssl STARTTLS",
         f"openssl s_client -starttls xmpp -connect {ip}:{port} -xmpphost {ip}",
         "Peek at the negotiated cert / SANs and post-TLS features."),
        ("recon", "manual stream-open",
         f"python -c \"import socket; s=socket.create_connection(('{ip}',{port}));"
         f" s.sendall(b\\\"<?xml version='1.0'?><stream:stream xmlns='jabber:client'"
         f" xmlns:stream='http://etherx.jabber.org/streams' to='{ip}' version='1.0'>\\\");"
         f" print(s.recv(65535).decode('utf-8','replace'))\"",
         "Read raw stream:features without touching a Python XMPP library."),
        ("enum", "disco items",
         f"# after stream-open + optional STARTTLS, send:\n"
         f"# <iq type='get' id='1' to='{ip}'>"
         f"<query xmlns='http://jabber.org/protocol/disco#items'/></iq>",
         "List MUC / HTTP-Upload / proxy65 / pubsub component JIDs."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    creds = creds or {}
    user = creds.get("user") or "<user>"
    steps = [
        ("enumerate", "roster dump (authenticated)",
         f"# SASL SCRAM as {user}, bind, then:\n"
         f"# <iq type='get' id='r1'>"
         f"<query xmlns='jabber:iq:roster'/></iq>",
         "Dump contact JIDs — internal usernames and often email addresses."),
        ("enumerate", "MUC join (public rooms only)",
         f"# join a public muc as {user}: <presence to='room@conference/{user}'/>",
         "Confirm ability to reach chat rooms enumerated via disco."),
        ("escalate", "admin adhoc",
         "# XEP-0050 command-node list against the server JID reveals admin "
         "commands available to this identity.",
         "Enumerate authorized admin adhoc commands."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return credfree_runbook(ip, port)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "xmpp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            wordlist: str | None = None, **_ignored) -> dict:
    from . import svcprobe
    targets = xmpp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"], active=True),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["product"] = pr.get("product", "") or t.get("product", "")
                t["sasl_mechs"] = (pr.get("features") or {}).get(
                    "sasl_mechs", [])
                t["anonymous"] = pr.get("anonymous", False)
                t["ibr_offered"] = pr.get("ibr_offered", False)
                t["components"] = [c.get("kind") or "component"
                                   for c in (pr.get("components") or [])]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": credfree_runbook(t["ip"], t["port"]),
                 "credentialed": cred_runbook(t["ip"], t["port"], creds)}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
