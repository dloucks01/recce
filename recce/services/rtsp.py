"""RTSP (554/tcp, 8554/tcp) fingerprint + unauth-stream + default-cred probe.

Structural analogue to sip.py: text-header request/response, OPTIONS
fingerprint, DESCRIBE for SDP, 401 challenge captured for realm/Digest,
well-known path enumeration for camera vendors, and a bounded default-cred
attempt against the discovered realm using the industry-known IP-camera
defaults. All stdlib socket + ssl.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder


_DEFAULT_PORT = 554
_ALT_PORT = 8554
_TIMEOUT = 4.0
_UA = "recce-rtsp/1.0"

_STATUS_RE = re.compile(rb"^RTSP/\d\.\d\s+(\d{3})", re.M)
_SERVER_RE = re.compile(rb"^Server:\s*(.+)$", re.I | re.M)
_PUBLIC_RE = re.compile(rb"^Public:\s*(.+)$", re.I | re.M)
_ALLOW_RE = re.compile(rb"^Allow:\s*(.+)$", re.I | re.M)
_CONTENT_TYPE_RE = re.compile(rb"^Content-Type:\s*([^;\r\n]+)", re.I | re.M)
_CONTENT_LEN_RE = re.compile(rb"^Content-Length:\s*(\d+)", re.I | re.M)
_WWW_AUTH_RE = re.compile(rb"^WWW-Authenticate:\s*(.+)$", re.I | re.M)
_SESSION_RE = re.compile(rb"^Session:\s*([^;\r\n]+)", re.I | re.M)
_DATE_RE = re.compile(rb"^Date:\s*(.+)$", re.I | re.M)

# Digest challenge param parse (RFC 7616 §3.3).
_QUOTED_PARAM_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_TOKEN_PARAM_RE = re.compile(r'(\w+)\s*=\s*([^,\s]+)')

# SDP field extraction (RFC 4566).
_SDP_S_RE = re.compile(rb"^s=(.*)$", re.M)
_SDP_I_RE = re.compile(rb"^i=(.*)$", re.M)
_SDP_TOOL_RE = re.compile(rb"^a=tool:(.*)$", re.M)
_SDP_M_RE = re.compile(rb"^m=(\w+)\s+\d+\s+(\S+)\s+(\d+)", re.M)
_SDP_RTPMAP_RE = re.compile(rb"^a=rtpmap:\d+\s+([\w-]+)/(\d+)", re.M)
_SDP_CONTROL_RE = re.compile(rb"^a=control:(.*)$", re.M)
_SDP_FMTP_RE = re.compile(rb"^a=fmtp:\d+\s+(.+)$", re.M)

# rtsp://user:pass@host[:port]/path
_CREDS_IN_URL_RE = re.compile(
    r"rtsps?://([^:/@\s]+):([^@/\s]+)@([A-Za-z0-9.\-]+)(?::(\d+))?(/[^\s'\"<>]*)?",
    re.I,
)

# Well-known vendor paths. Ordered so common cameras hit early. Each entry:
# (path, vendor-tag). Kept short — a fingerprint pass, not a discovery brute.
_WELL_KNOWN_PATHS: tuple[tuple[str, str], ...] = (
    ("/", "generic"),
    ("/Streaming/Channels/101", "hikvision"),
    ("/Streaming/Channels/1", "hikvision"),
    ("/h264/ch1/main/av_stream", "hikvision"),
    ("/ISAPI/Streaming/channels/101", "hikvision"),
    ("/cam/realmonitor?channel=1&subtype=0", "dahua"),
    ("/live", "dahua"),
    ("/axis-media/media.amp", "axis"),
    ("/mpeg4/media.amp", "axis"),
    ("/videoMain", "foscam"),
    ("/videoSub", "foscam"),
    ("/onvif/media", "onvif-generic"),
    ("/live/main", "onvif-generic"),
    ("/test", "gstreamer"),
    ("/stream", "gstreamer"),
)

# Industry-known IP-camera defaults. Bounded (<=12 pairs).
_CAMERA_DEFAULTS: tuple[tuple[str, str, str], ...] = (
    ("admin", "12345", "Hikvision pre-2015"),
    ("admin", "admin", "Dahua/Foscam"),
    ("admin", "", "blank"),
    ("admin", "888888", "Dahua backdoor era"),
    ("admin", "password", "generic"),
    ("root", "pass", "Axis pre-2018"),
    ("root", "root", "Axis pre-2018"),
    ("root", "camera", "generic"),
    ("service", "service", "Bosch"),
    ("ubnt", "ubnt", "Ubiquiti UniFi Video"),
    ("supervisor", "supervisor", "Panasonic"),
    ("Administrator", "1234", "Sony"),
)

# (compiled server-header regex, vendor, model-normaliser, [(cve, kev, cwe, note)]).
# Only well-documented, high-confidence CVEs. Firmware-bounded CVE_MATCH keys
# check the version string separately.
_CVE_MAP: tuple[tuple[re.Pattern, str, list[dict]], ...] = (
    (re.compile(r"hikvision|hipcam|dvrdvs|dnvrs", re.I), "hikvision", [
        {"cve": "CVE-2021-36260", "kev": True, "cwe": ["CWE-78"],
         "note": "unauth RCE via ISAPI (KEV)"},
        {"cve": "CVE-2017-7921", "kev": False, "cwe": ["CWE-287"],
         "note": "auth bypass via ?auth=YWRtaW46MTEK"},
    ]),
    (re.compile(r"dahua|realmonitor", re.I), "dahua", [
        {"cve": "CVE-2021-33044", "kev": False, "cwe": ["CWE-287"],
         "note": "auth bypass (blank password acceptance)"},
        {"cve": "CVE-2021-33045", "kev": False, "cwe": ["CWE-287"],
         "note": "auth bypass via loopback JSON"},
        {"cve": "CVE-2013-6117", "kev": False, "cwe": ["CWE-798"],
         "note": "port 37777 backdoor"},
    ]),
    (re.compile(r"axis", re.I), "axis", [
        {"cve": "CVE-2018-10660", "kev": False, "cwe": ["CWE-78"],
         "note": "shell command injection (pre-auth)"},
        {"cve": "CVE-2018-10661", "kev": False, "cwe": ["CWE-287"],
         "note": "auth bypass in .srv handler"},
        {"cve": "CVE-2018-10662", "kev": False, "cwe": ["CWE-200"],
         "note": "exposed internal .srv/parhand API"},
    ]),
    (re.compile(r"foscam|ipcam", re.I), "foscam", [
        {"cve": "CVE-2018-6832", "kev": False, "cwe": ["CWE-798"],
         "note": "hardcoded credentials"},
    ]),
    (re.compile(r"gstreamer|live555", re.I), "gstreamer/live555", [
        {"cve": "CVE-2019-15232", "kev": False, "cwe": ["CWE-416"],
         "note": "Live555 UAF in RTSP handler"},
    ]),
)


def is_rtsp(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid in (_DEFAULT_PORT, _ALT_PORT):
        return True
    blob = f"{port.service} {port.product}".lower()
    return "rtsp" in blob


def _request(method: str, url: str, cseq: int, headers: dict | None = None,
             body: str = "") -> bytes:
    lines = [f"{method} {url} RTSP/1.0",
             f"CSeq: {cseq}",
             f"User-Agent: {_UA}"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text.encode("ascii", "replace")


def _open_socket(ip: str, port: int, timeout: float, tls: bool):
    t = proxy.scaled(timeout)
    sock = socket.create_connection((ip, port), timeout=t)
    if tls:
        ctx = ssl._create_unverified_context()
        sock = ctx.wrap_socket(sock, server_hostname=ip)
    sock.settimeout(t)
    return sock


def _read_response(sock, timeout: float) -> bytes:
    sock.settimeout(proxy.scaled(timeout))
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65535:
        try:
            chunk = sock.recv(4096)
        except (OSError, socket.timeout):
            break
        if not chunk:
            break
        buf += chunk
    if b"\r\n\r\n" in buf:
        header_end = buf.index(b"\r\n\r\n") + 4
        m = _CONTENT_LEN_RE.search(buf[:header_end])
        if m:
            need = int(m.group(1))
            while len(buf) - header_end < need and len(buf) < 262144:
                try:
                    chunk = sock.recv(4096)
                except (OSError, socket.timeout):
                    break
                if not chunk:
                    break
                buf += chunk
    return buf


def _send(sock, payload: bytes, timeout: float) -> bytes:
    try:
        sock.sendall(payload)
    except OSError:
        return b""
    return _read_response(sock, timeout)


def _status(reply: bytes) -> int:
    m = _STATUS_RE.search(reply)
    return int(m.group(1)) if m else 0


def parse_www_authenticate(header: str) -> dict:
    """Return {scheme, realm, nonce, algorithm, qop, opaque, basic, digest}."""
    out: dict = {"schemes": [], "realm": "", "nonce": "", "algorithm": "",
                 "qop": "", "opaque": "", "basic": False, "digest": False}
    for chunk in _split_challenges(header):
        scheme, params = _parse_scheme(chunk)
        if not scheme:
            continue
        out["schemes"].append(scheme.lower())
        if scheme.lower() == "basic":
            out["basic"] = True
        if scheme.lower() == "digest":
            out["digest"] = True
            for k, v in params.items():
                if k in out and not out[k]:
                    out[k] = v
    return out


_SCHEMES = ("Basic", "Digest", "Bearer", "NTLM", "Negotiate")


def _split_challenges(header: str) -> list[str]:
    """Split possibly-multiple WWW-Authenticate schemes concatenated on one
    line (`Basic realm="x", Digest realm="y", nonce="z"`). Splits at the
    boundary ", <Scheme> " — a comma inside quoted param values will never
    match this pattern, so quotes need no separate tracking."""
    result = [header]
    changed = True
    while changed:
        changed = False
        new_result: list[str] = []
        for seg in result:
            for sch in _SCHEMES:
                marker = f", {sch} "
                if marker in seg:
                    idx = seg.index(marker)
                    new_result.append(seg[:idx])
                    new_result.append(seg[idx + 2:])
                    changed = True
                    break
            else:
                new_result.append(seg)
        result = new_result
    return [s.strip() for s in result if s.strip()]


def _parse_scheme(chunk: str) -> tuple[str, dict]:
    m = re.match(r"(\w+)\s+(.*)$", chunk.strip(), re.S)
    if not m:
        return chunk.strip(), {}
    scheme, rest = m.group(1), m.group(2)
    params: dict = {}
    for k, v in _QUOTED_PARAM_RE.findall(rest):
        params[k.lower()] = v
    for k, v in _TOKEN_PARAM_RE.findall(rest):
        if k.lower() not in params:
            params[k.lower()] = v
    return scheme, params


def _digest_response(user: str, password: str, realm: str, nonce: str,
                     method: str, uri: str, qop: str = "", nc: str = "",
                     cnonce: str = "", algorithm: str = "MD5") -> str:
    def h(x: str) -> str:
        return hashlib.md5(x.encode("utf-8")).hexdigest()
    ha1 = h(f"{user}:{realm}:{password}")
    if algorithm.lower() == "md5-sess" and cnonce:
        ha1 = h(f"{ha1}:{nonce}:{cnonce}")
    ha2 = h(f"{method}:{uri}")
    if qop:
        return h(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    return h(f"{ha1}:{nonce}:{ha2}")


def _digest_header(user: str, realm: str, nonce: str, uri: str, response: str,
                   algorithm: str = "MD5", qop: str = "", nc: str = "",
                   cnonce: str = "", opaque: str = "") -> str:
    parts = [
        f'username="{user}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if algorithm:
        parts.append(f'algorithm={algorithm}')
    if qop:
        parts.append(f'qop={qop}')
        parts.append(f'nc={nc}')
        parts.append(f'cnonce="{cnonce}"')
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


def parse_sdp(body: bytes) -> dict:
    out: dict = {"session": "", "info": "", "tool": "", "controls": [],
                 "media": [], "codecs": [], "fmtp": []}
    m = _SDP_S_RE.search(body)
    if m:
        out["session"] = m.group(1).decode("utf-8", "replace").strip()
    m = _SDP_I_RE.search(body)
    if m:
        out["info"] = m.group(1).decode("utf-8", "replace").strip()
    m = _SDP_TOOL_RE.search(body)
    if m:
        out["tool"] = m.group(1).decode("utf-8", "replace").strip()
    for kind, transport, payload in _SDP_M_RE.findall(body):
        out["media"].append({
            "kind": kind.decode("ascii", "replace"),
            "transport": transport.decode("ascii", "replace"),
            "payload": int(payload),
        })
    for codec, clock in _SDP_RTPMAP_RE.findall(body):
        out["codecs"].append({
            "codec": codec.decode("ascii", "replace"),
            "clock": int(clock),
        })
    for c in _SDP_CONTROL_RE.findall(body):
        out["controls"].append(c.decode("utf-8", "replace").strip())
    for f in _SDP_FMTP_RE.findall(body):
        out["fmtp"].append(f.decode("utf-8", "replace").strip())
    return out


def _url(ip: str, port: int, path: str = "/", scheme: str = "rtsp") -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{ip}:{port}{path}"


def _http_tunnel_probe(ip: str, port: int, timeout: float) -> dict:
    """Detect RTSP-over-HTTP tunneling (Apple/QuickTime): a GET with
    Accept: application/x-rtsp-tunnelled and x-sessioncookie should elicit
    that same content-type back from a tunnel-capable server."""
    out: dict = {"tunnel": False, "server": ""}
    payload = (
        f"GET /rtsp-tunnel HTTP/1.0\r\n"
        f"User-Agent: {_UA}\r\n"
        f"Host: {ip}\r\n"
        f"Accept: application/x-rtsp-tunnelled\r\n"
        f"Pragma: no-cache\r\n"
        f"Cache-Control: no-cache\r\n"
        f"x-sessioncookie: recce-tunnel\r\n\r\n"
    ).encode("ascii")
    try:
        with _open_socket(ip, port, timeout, tls=False) as s:
            reply = _send(s, payload, timeout)
    except OSError:
        return out
    if not reply:
        return out
    if b"application/x-rtsp-tunnelled" in reply.lower() or \
            re.search(rb"Server:\s*DSS/", reply, re.I):
        out["tunnel"] = True
    m = re.search(rb"^Server:\s*(.+)$", reply, re.I | re.M)
    if m:
        out["server"] = m.group(1).decode("ascii", "replace").strip()
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          tls: bool = False, paths: tuple[tuple[str, str], ...] | None = None) -> dict:
    """OPTIONS + DESCRIBE + optional path enum + digest capture. Returns:
      {reachable, tls, transport, server, public, allow, auth: {...},
       unauth_stream, sdp, paths: [{path, status, vendor}], liveness, cve_hits,
       digest_capture, cert_cn}
    """
    out: dict = {"reachable": False, "tls": tls, "server": "", "public": [],
                 "allow": [], "auth": {}, "unauth_stream": False, "sdp": None,
                 "paths": [], "liveness": False, "cve_hits": [],
                 "digest_capture": "", "cert_cn": ""}
    scheme = "rtsps" if tls else "rtsp"

    # OPTIONS.
    try:
        sock = _open_socket(ip, port, timeout, tls=tls)
    except OSError:
        return out
    try:
        if tls:
            try:
                cert = sock.getpeercert()
                cn = _cert_cn(cert)
                if cn:
                    out["cert_cn"] = cn
            except (ValueError, OSError):
                pass
        options_url = _url(ip, port, "/", scheme=scheme)
        reply = _send(sock, _request("OPTIONS", options_url, 1), timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not reply or not reply.startswith(b"RTSP/"):
        return out
    out["reachable"] = True
    m = _SERVER_RE.search(reply)
    if m:
        out["server"] = m.group(1).decode("ascii", "replace").strip()
    m = _PUBLIC_RE.search(reply)
    if m:
        out["public"] = [t.strip() for t in
                         m.group(1).decode("ascii", "replace").split(",") if t.strip()]
    m = _ALLOW_RE.search(reply)
    if m:
        out["allow"] = [t.strip() for t in
                        m.group(1).decode("ascii", "replace").split(",") if t.strip()]

    # GET_PARAMETER liveness — only if OPTIONS says the verb is supported.
    if "GET_PARAMETER" in out["public"]:
        try:
            with _open_socket(ip, port, timeout, tls=tls) as s2:
                r = _send(s2, _request("GET_PARAMETER", options_url, 2), timeout)
            out["liveness"] = _status(r) in (200, 401)
        except OSError:
            pass

    # DESCRIBE against the root. Captures auth challenge OR unauth SDP.
    describe_url = _url(ip, port, "/", scheme=scheme)
    try:
        with _open_socket(ip, port, timeout, tls=tls) as s3:
            reply2 = _send(s3, _request(
                "DESCRIBE", describe_url, 3,
                headers={"Accept": "application/sdp"}), timeout)
    except OSError:
        reply2 = b""

    _absorb_describe(out, reply2, describe_url)

    # Well-known path enumeration.
    paths = paths if paths is not None else _WELL_KNOWN_PATHS
    for path, vendor in paths:
        purl = _url(ip, port, path, scheme=scheme)
        try:
            with _open_socket(ip, port, timeout, tls=tls) as s4:
                r = _send(s4, _request(
                    "DESCRIBE", purl, 4,
                    headers={"Accept": "application/sdp"}), timeout)
        except OSError:
            continue
        st = _status(r)
        entry = {"path": path, "vendor": vendor, "status": st}
        out["paths"].append(entry)
        if st == 200 and not out["unauth_stream"]:
            out["unauth_stream"] = True
            body_start = r.find(b"\r\n\r\n")
            if body_start > 0 and not out.get("sdp"):
                sdp_body = r[body_start + 4:]
                if b"v=0" in sdp_body[:64]:
                    out["sdp"] = parse_sdp(sdp_body)

    out["cve_hits"] = match_cves(out["server"])
    return out


def _cert_cn(cert: dict | None) -> str:
    if not cert:
        return ""
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k.lower() == "commonname":
                return v
    return ""


def _absorb_describe(out: dict, reply: bytes, uri: str) -> None:
    if not reply or not reply.startswith(b"RTSP/"):
        return
    st = _status(reply)
    if st == 200:
        out["unauth_stream"] = True
        body_start = reply.find(b"\r\n\r\n")
        if body_start > 0:
            sdp = reply[body_start + 4:]
            if b"v=0" in sdp[:64]:
                out["sdp"] = parse_sdp(sdp)
    elif st == 401:
        wa = _WWW_AUTH_RE.findall(reply)
        if wa:
            header = ", ".join(w.decode("latin-1", "replace") for w in wa)
            out["auth"] = parse_www_authenticate(header)
            if out["auth"].get("digest") and out["auth"].get("nonce"):
                out["digest_capture"] = hashcat_line_sip(
                    realm=out["auth"]["realm"],
                    method="DESCRIBE",
                    uri=uri,
                    nonce=out["auth"]["nonce"],
                    qop=out["auth"].get("qop", ""),
                    algorithm=out["auth"].get("algorithm", "MD5"),
                )


def hashcat_line_sip(realm: str, method: str, uri: str, nonce: str,
                     qop: str = "", algorithm: str = "MD5") -> str:
    """Hashcat mode-11400 (SIP Digest MD5) line with placeholders for client-
    side fields. Format: $sip$*<realm>*<uri>*<method>*<nonce>*<nc>*<cnonce>*<qop>*<response>.

    Server-side portion is populated from the captured challenge; nc/cnonce/
    response are placeholders (`<nc>`, `<cnonce>`, `<response>`) an operator
    fills in after intercepting a valid client authentication. Without the
    client response there is no hash to crack — recce stashes what the server
    always leaks and names what still has to come from a capture."""
    _ = algorithm
    return (f"$sip$**{realm}*{uri}*{method}*{nonce}*<nc>*<cnonce>*"
            f"{qop}*<response>")


def match_cves(server_header: str) -> list[dict]:
    if not server_header:
        return []
    out: list[dict] = []
    for pat, vendor, cves in _CVE_MAP:
        if pat.search(server_header):
            for c in cves:
                out.append({"vendor": vendor, "server": server_header, **c})
            break
    return out


def default_cred_check(ip: str, port: int, auth: dict,
                       timeout: float = _TIMEOUT, tls: bool = False,
                       pairs: tuple[tuple[str, str, str], ...] | None = None,
                       max_attempts: int = 12) -> dict:
    """Bounded default-credential attempt against the discovered realm.

    Returns {tried, hits: [{user, password, note, scheme}], errors}.
    Never exceeds `max_attempts`. Prefers Digest when offered; falls back to
    Basic when only Basic is on offer.
    """
    out: dict = {"tried": 0, "hits": [], "errors": []}
    pairs = pairs if pairs is not None else _CAMERA_DEFAULTS
    scheme = "rtsps" if tls else "rtsp"
    uri = _url(ip, port, "/", scheme=scheme)
    use_digest = bool(auth.get("digest") and auth.get("nonce"))
    use_basic = bool(auth.get("basic")) and not use_digest
    if not (use_digest or use_basic):
        return out
    realm = auth.get("realm", "")
    nonce = auth.get("nonce", "")
    algorithm = auth.get("algorithm", "MD5") or "MD5"
    qop = auth.get("qop", "") or ""
    opaque = auth.get("opaque", "") or ""

    for user, password, note in pairs[:max_attempts]:
        out["tried"] += 1
        try:
            with _open_socket(ip, port, timeout, tls=tls) as s:
                if use_digest:
                    nc = "00000001"
                    cnonce = "recce"
                    resp = _digest_response(
                        user, password, realm, nonce,
                        "DESCRIBE", uri, qop=qop, nc=nc, cnonce=cnonce,
                        algorithm=algorithm)
                    hdr = _digest_header(
                        user, realm, nonce, uri, resp,
                        algorithm=algorithm, qop=qop, nc=nc, cnonce=cnonce,
                        opaque=opaque)
                else:
                    import base64
                    tok = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode()
                    hdr = f"Basic {tok}"
                reply = _send(s, _request(
                    "DESCRIBE", uri, 10,
                    headers={"Accept": "application/sdp", "Authorization": hdr}),
                    timeout)
        except OSError as e:
            out["errors"].append(f"{user}: {e}")
            continue
        st = _status(reply)
        if st == 200:
            out["hits"].append({"user": user, "password": password,
                                "note": note,
                                "scheme": "digest" if use_digest else "basic"})
            break
    return out


def find_creds_in_text(text: str) -> list[dict]:
    """Pull rtsp://user:pass@host[:port]/path out of arbitrary text. Zero traffic."""
    out: list[dict] = []
    seen: set = set()
    for user, password, host, port, path in _CREDS_IN_URL_RE.findall(text or ""):
        key = (user, password, host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append({"user": user, "password": password, "host": host,
                    "port": int(port) if port else _DEFAULT_PORT,
                    "path": path or "/"})
    return out


def rtsp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_rtsp(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or "",
                            "tls": p.tunnel.lower() == "ssl"
                                   or p.portid in (322,)})
    return out


_NARRATIVE = {
    "rtsp_fingerprint": (
        "An RTSP OPTIONS response leaks the server product line and the list of "
        "permitted verbs. That is enough to identify the camera model / firmware "
        "and to know whether the stream supports ANNOUNCE/RECORD (writable push) "
        "or only GET_PARAMETER keepalives."),
    "rtsp_sdp_disclosure": (
        "SDP returned by DESCRIBE names the tracks, codecs, resolution profile "
        "(SPS/PPS in a=fmtp) and per-track control URIs. It confirms which streams "
        "exist and gives an attacker the exact ffmpeg/openRTSP command needed to "
        "pull them."),
    "rtsp_auth_disclosure": (
        "The 401 challenge names the Digest realm — almost always vendor-branded "
        "(HikvisionDS, IPCam, AXIS_<serial>) — which fingerprints the device even "
        "when the Server header is stripped. If Basic auth is offered alongside "
        "Digest, or on its own, a legitimate client will send credentials in "
        "cleartext (base64) the moment it authenticates."),
    "rtsp_unauth_stream": (
        "The RTSP endpoint served SDP without ever demanding credentials — the "
        "stream is world-viewable. Anyone reachable to this port can pull the "
        "video with ffplay/vlc; on cameras that carry audio, they can hear it too."),
    "rtsp_path_enum": (
        "Vendor-specific stream paths responded distinctly (200 / 401 / 404), "
        "confirming the camera vendor and naming exactly which URL a valid "
        "credential would unlock."),
    "rtsp_default_cred": (
        "A factory-default username/password pair unlocked the RTSP stream. "
        "Same credentials very often work against the vendor's web UI (RCE "
        "primitives on old Hikvision/Dahua/Foscam builds) and against the "
        "co-located ONVIF endpoint (device info, PTZ control, user list)."),
    "rtsp_digest_capture": (
        "The 401 challenge (realm, nonce, algorithm, qop) is captured in "
        "hashcat mode-11400 shape. On its own it is not crackable — the "
        "cracker needs a client-side response too — but stashing the server "
        "portion lets an operator drop in an intercepted RAKP-style client "
        "response later and crack immediately."),
    "rtsp_known_vuln": (
        "The Server header matched a documented vulnerable IP-camera build. "
        "Verify the firmware version and, on a match, treat as pre-auth "
        "compromise (CVE-2021-36260 on Hikvision is on the CISA KEV list)."),
    "rtsps_probe": (
        "RTSP over TLS answered. The presented certificate's CN/SAN is a "
        "high-signal identifier (MAC / serial / model on IP-camera certs)."),
    "rtsp_http_tunnel": (
        "The port speaks RTSP-over-HTTP (Apple QTSS/Live555 tunnel) — RTSP is "
        "hiding behind an HTTP front-end. All the RTSP capabilities apply to it "
        "via the tunnel; audit tools that only speak native RTSP will miss it."),
    "rtsp_liveness": (
        "GET_PARAMETER answered — the port is a genuinely live RTSP service, "
        "not a stray SYN-ACK from a load balancer."),
    "rtsp_creds_in_url": (
        "An rtsp://user:pass@host URL was observed in previously-collected text. "
        "Extract and stack the credential — the same pair very often re-uses on "
        "the same operator's other cameras and NVRs."),
}


_finding = finding_builder("rtsp", _NARRATIVE)


def _fmt_media(sdp: dict) -> str:
    parts = []
    for m in sdp.get("media") or []:
        parts.append(f"{m['kind']}/{m['transport']}")
    codecs = [c["codec"] for c in sdp.get("codecs") or []]
    if codecs:
        parts.append("codecs=" + ",".join(codecs))
    return "; ".join(parts)


def findings(hosts: list[Host], probes: dict | None = None,
             cred_hits: dict | None = None, text_creds: list[dict] | None = None) -> list[dict]:
    probes = probes or {}
    cred_hits = cred_hits or {}
    text_creds = text_creds or []
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_rtsp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            server = pr.get("server") or "unknown"
            public = ", ".join(pr.get("public") or [])
            out.append(_finding(
                "medium", "RTSP server discloses vendor/model via OPTIONS",
                tgt,
                f"OPTIONS on {tgt} returned Server: {server}"
                + (f"; Public: {public}" if public else "")
                + ". Vendor + verb list identifies the camera family and reveals "
                "whether writable-push (ANNOUNCE/RECORD) is enabled.",
                "openRTSP / ffprobe",
                f"openRTSP -O rtsp://{h.ip}:{p.portid}/   "
                f"# also: ffprobe -rtsp_transport tcp rtsp://{h.ip}:{p.portid}/",
                "Strip the Server header at the reverse proxy or in the RTSP "
                "server config; restrict RTSP to the camera VLAN.",
                ["CWE-200"], kind="rtsp_fingerprint"))

            if pr.get("liveness"):
                out.append(_finding(
                    "low", "RTSP GET_PARAMETER keepalive answered", tgt,
                    f"{tgt} answered GET_PARAMETER — the port is a genuinely "
                    "live RTSP service (not a stray SYN-ACK).",
                    "openRTSP",
                    f"openRTSP -O rtsp://{h.ip}:{p.portid}/",
                    "None required (informational).",
                    [], kind="rtsp_liveness"))

            auth = pr.get("auth") or {}
            if auth.get("basic") and auth.get("digest"):
                out.append(_finding(
                    "medium", "RTSP offers Basic authentication alongside Digest",
                    tgt,
                    f"WWW-Authenticate on {tgt} advertises both Basic and Digest. "
                    f"A client that picks Basic sends credentials in base64 — a "
                    f"cleartext downgrade on the same port.",
                    "wireshark / tcpdump",
                    f"tcpdump -i <iface> 'tcp port {p.portid}'   "
                    "# capture and decode 'Authorization: Basic <b64>'",
                    "Disable Basic authentication in the RTSP server config; "
                    "require Digest (or, better, TLS-wrap the transport).",
                    ["CWE-319", "CWE-522"], kind="rtsp_auth_disclosure"))
            elif auth.get("basic"):
                out.append(_finding(
                    "medium", "RTSP requires Basic authentication (cleartext creds)",
                    tgt,
                    f"WWW-Authenticate on {tgt} advertises only Basic. Every valid "
                    "authentication sends the credential in base64 on the wire.",
                    "wireshark / tcpdump",
                    f"tcpdump -i <iface> 'tcp port {p.portid}'",
                    "Disable Basic; require Digest or TLS.",
                    ["CWE-319", "CWE-522"], kind="rtsp_auth_disclosure"))
            elif auth.get("digest") and auth.get("realm"):
                out.append(_finding(
                    "medium", "RTSP Digest realm discloses camera identity",
                    tgt,
                    f"WWW-Authenticate on {tgt} names realm=\"{auth['realm']}\" — "
                    "typically vendor-branded (HikvisionDS, IPCam, AXIS_<serial>) "
                    "and enough to fingerprint the device on its own.",
                    "openRTSP",
                    f"openRTSP -O rtsp://{h.ip}:{p.portid}/",
                    "Set a generic realm; better still, restrict RTSP to trusted "
                    "networks.",
                    ["CWE-200"], kind="rtsp_auth_disclosure"))

            if pr.get("digest_capture"):
                out.append(_finding(
                    "medium", "RTSP Digest challenge captured (hashcat-11400 shape)",
                    tgt,
                    "The 401 challenge was stashed as a hashcat mode-11400 line. "
                    "Not crackable alone (the cracker also needs an intercepted "
                    "client response); pair with a live capture or MitM to "
                    "produce a usable hash.\n\nCaptured challenge:\n"
                    f"{pr['digest_capture']}",
                    "hashcat",
                    "hashcat -m 11400 loot/rtsp-digest.hash wordlist.txt   "
                    "# after a client response is intercepted and dropped in",
                    "Restrict RTSP to trusted networks. A strong password policy "
                    "makes offline cracking infeasible if a hash is captured.",
                    ["CWE-522"], kind="rtsp_digest_capture"))

            if pr.get("unauth_stream"):
                sdp = pr.get("sdp") or {}
                info = _fmt_media(sdp) if sdp else ""
                out.append(_finding(
                    "critical", "RTSP stream world-viewable (no authentication)",
                    tgt,
                    f"DESCRIBE on {tgt} returned 200 OK without any Authorization "
                    "header ever being sent — the stream is unauthenticated."
                    + (f" SDP: session=\"{sdp.get('session', '')}\", tool="
                       f"\"{sdp.get('tool', '')}\", {info}" if sdp else ""),
                    "ffplay",
                    f"ffplay -rtsp_transport tcp rtsp://{h.ip}:{p.portid}/   "
                    "# or vlc rtsp://<ip>:<port>/",
                    "Require authentication on every RTSP stream; segment cameras "
                    "onto a dedicated VLAN and firewall RTSP off the general "
                    "network.",
                    ["CWE-306", "CWE-284"], kind="rtsp_unauth_stream"))
            elif pr.get("sdp"):
                sdp = pr["sdp"]
                out.append(_finding(
                    "high", "RTSP DESCRIBE discloses SDP", tgt,
                    f"DESCRIBE returned SDP describing the stream — "
                    f"session=\"{sdp.get('session', '')}\", tool=\"{sdp.get('tool', '')}\","
                    f" {_fmt_media(sdp)}. Enables targeted attack: attacker knows "
                    "exact codec / profile before spending an auth attempt.",
                    "ffprobe",
                    f"ffprobe -rtsp_transport tcp rtsp://{h.ip}:{p.portid}/",
                    "Return 401 on DESCRIBE without a valid Authorization header "
                    "rather than serving SDP unauthenticated.",
                    ["CWE-200"], kind="rtsp_sdp_disclosure"))

            paths_seen = pr.get("paths") or []
            vendor_hits = [x for x in paths_seen if x["status"] in (200, 401)]
            if vendor_hits:
                summary = ", ".join(f"{x['path']}={x['status']} ({x['vendor']})"
                                     for x in vendor_hits[:6])
                out.append(_finding(
                    "high" if any(x["status"] == 200 for x in vendor_hits) else "medium",
                    "RTSP well-known vendor paths responded", tgt,
                    f"Probed {len(paths_seen)} vendor-specific paths; "
                    f"{len(vendor_hits)} answered 200/401. First hits: {summary}. "
                    "Path fingerprint disambiguates vendor even when Server is "
                    "stripped and names streams a valid credential would unlock.",
                    "openRTSP / ffprobe",
                    f"ffprobe -rtsp_transport tcp rtsp://{h.ip}:{p.portid}"
                    f"{vendor_hits[0]['path']}",
                    "Do not expose vendor-canonical stream paths without auth; "
                    "return a uniform 401 on every DESCRIBE.",
                    ["CWE-425", "CWE-200"], kind="rtsp_path_enum"))

            for cve in pr.get("cve_hits") or []:
                sev = "critical" if cve.get("kev") else "high"
                out.append(_finding(
                    sev,
                    f"IP camera fingerprint matches known-vulnerable build ({cve['cve']})",
                    tgt,
                    f"Server header \"{cve['server']}\" matched vendor "
                    f"{cve['vendor']} → {cve['cve']}: {cve['note']}."
                    + (" On the CISA KEV catalogue." if cve.get("kev") else ""),
                    "vendor-specific PoC",
                    f"# verify firmware version, then use the documented "
                    f"{cve['cve']} PoC (searchsploit / MITRE) against "
                    f"{h.ip}:{p.portid}",
                    "Apply the vendor firmware update; if unavailable, isolate "
                    "the device on a management VLAN with no inbound access.",
                    cve.get("cwe") or ["CWE-1035"], kind="rtsp_known_vuln"))

            if pr.get("tls"):
                cn = pr.get("cert_cn") or ""
                out.append(_finding(
                    "low", "RTSP-over-TLS (RTSPS) endpoint reachable", tgt,
                    f"RTSPS handshake on {tgt} succeeded"
                    + (f"; certificate CN=\"{cn}\" (typically MAC/serial/model "
                       "on IP-camera certs — high-signal identifier)."
                       if cn else "."),
                    "openssl / openRTSP",
                    f"openssl s_client -connect {h.ip}:{p.portid} </dev/null   "
                    f"# then: openRTSP rtsps://{h.ip}:{p.portid}/",
                    "None required if TLS is intentional; ensure the certificate "
                    "chain and cipher suite are current.",
                    ["CWE-319"], kind="rtsps_probe"))

            hits = cred_hits.get((h.ip, p.portid)) or {}
            for hit in hits.get("hits") or []:
                out.append(_finding(
                    "critical",
                    f"RTSP default credentials accepted ({hit['note']}: "
                    f"{hit['user']}/{hit['password'] or '<blank>'})",
                    tgt,
                    f"DESCRIBE authenticated as {hit['user']} with the vendor "
                    f"factory-default password '{hit['password']}' ({hit['note']}, "
                    f"scheme={hit['scheme']}). Same credentials very often unlock "
                    "the co-located web UI and ONVIF endpoint; feed into the "
                    "credential store for downstream reuse.",
                    "openRTSP",
                    f"openRTSP -u {hit['user']} {hit['password'] or ''} "
                    f"rtsp://{h.ip}:{p.portid}/",
                    "Change the password on every camera immediately — the "
                    "vendor factory default is public knowledge. Enforce a "
                    "per-device unique password on provisioning.",
                    ["CWE-798", "CWE-521"], kind="rtsp_default_cred"))

    for tc in text_creds:
        tgt = f"{tc['host']}:{tc['port']}"
        out.append(_finding(
            "medium", "RTSP credentials in URL / config",
            tgt,
            f"rtsp URL with inline credentials observed: rtsp://{tc['user']}:"
            f"{tc['password']}@{tc['host']}:{tc['port']}{tc['path']}. "
            "The same pair frequently reuses on the operator's other cameras.",
            "grep",
            f"grep -RnI 'rtsp://[^@]*@{tc['host']}' loot/",
            "Rewrite RTSP client configs to use per-device credentials from a "
            "vault; never embed cleartext in URLs.",
            ["CWE-522", "CWE-598"], kind="rtsp_creds_in_url"))

    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "recon", "tool": "openRTSP",
         "command": f"openRTSP -O rtsp://{ip}:{port}/",
         "why": "OPTIONS + DESCRIBE round trip — server line, allowed verbs, SDP."},
        {"phase": "recon", "tool": "ffprobe",
         "command": f"ffprobe -rtsp_transport tcp rtsp://{ip}:{port}/",
         "why": "Codec / resolution / duration; confirms stream is playable."},
        {"phase": "recon", "tool": "cameradar",
         "command": f"cameradar -t {ip}:{port}",
         "why": "Bulk path + default-cred sweep; use only when in-scope."},
        {"phase": "loot", "tool": "ffmpeg",
         "command": f"ffmpeg -rtsp_transport tcp -i rtsp://<user>:<pass>@{ip}:{port}/"
                    " -t 30 -c copy loot/rtsp_{ip}.mkv",
         "why": "30-second proof capture from a valid stream."},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "rtsp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            do_default_creds: bool = True) -> dict:
    from . import svcprobe
    _ = creds
    targets = rtsp_targets(hosts)
    probes: dict = {}
    cred_hits: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], tls=t.get("tls", False)),
                budget=budget, progress=progress, state=state):
            if not pr:
                continue
            probes[(t["ip"], t["port"])] = pr
            t["reachable"] = pr.get("reachable", False)
            t["server"] = pr.get("server", "")
            t["unauth_stream"] = pr.get("unauth_stream", False)
            if do_default_creds and pr.get("reachable") and pr.get("auth") \
                    and (pr["auth"].get("digest") or pr["auth"].get("basic")) \
                    and not pr.get("unauth_stream"):
                try:
                    hits = default_cred_check(
                        t["ip"], t["port"], pr["auth"], tls=t.get("tls", False))
                    if hits.get("hits"):
                        cred_hits[(t["ip"], t["port"])] = hits
                except OSError:
                    pass
    fs = findings(hosts, probes, cred_hits=cred_hits)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "cred_hits": {f"{k[0]}:{k[1]}": v for k, v in cred_hits.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "cred_hits": sum(len(v.get("hits") or [])
                                       for v in cred_hits.values()),
                      "stopped": state.get("stopped")}}
