"""Tests for recce.services.webdav.

Fixture bodies are copied from RFC 4918 (WebDAV) examples and from
RFC 7235 (HTTP authentication) - never constructed by calling our own
encoder. HTTP transport is faked by monkey-patching
recce.services.svccommon.http_connect so no packet ever hits the wire.
"""
from __future__ import annotations

import unittest

from recce.core.models import Host, Port
from recce.services import webdav


class _Patch:
    """Minimal replacement for pytest's monkeypatch — records the original and
    restores it on undo(). Written this way so the test file stays plain unittest."""

    def __init__(self):
        self._saved: list[tuple[object, str, object]] = []

    def setattr(self, obj, name, value=None):
        # Accept both pytest forms: setattr("mod.attr", value) and setattr(obj, "attr", value).
        if isinstance(obj, str) and value is None:
            value = name
            mod_path, _, attr = obj.rpartition(".")
            import importlib
            obj = importlib.import_module(mod_path)
            name = attr
        self._saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def undo(self):
        while self._saved:
            obj, name, value = self._saved.pop()
            setattr(obj, name, value)


# ---------------------------------------------------------------------------
# Wire-derived fixtures. Each blob is either verbatim from an RFC example or a
# minimal capture-shaped equivalent. Do NOT call webdav.propfind() to build
# these - a fixture that round-trips through the code under test proves nothing.

# RFC 4918 s.10.1 — OPTIONS response advertising WebDAV compliance classes 1
# and 2, plus the base HTTP verbs. Header names lowered here because
# http.client normalises them on receive.
OPTIONS_HEADERS_APACHE_MOD_DAV = [
    ("Date", "Wed, 05 Aug 2020 12:00:00 GMT"),
    ("Server", "Apache/2.4.29 (Ubuntu) DAV/2 mod_dav_fs/2.4"),
    ("DAV", "1,2"),
    ("MS-Author-Via", "DAV"),
    ("Allow", "OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK,MKCOL,PUT"),
    ("Content-Length", "0"),
]

OPTIONS_HEADERS_IIS6 = [
    ("Server", "Microsoft-IIS/6.0"),
    ("MicrosoftOfficeWebServer", "5.0_Pub"),
    ("X-Powered-By", "ASP.NET"),
    ("MS-Author-Via", "MS-FP/4.0,DAV"),
    ("DAV", "1,2"),
    ("Public", "OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, "
               "PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH"),
    ("Allow", "OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK"),
    ("Content-Length", "0"),
]

# RFC 4918 s.9.1.3 (Example - Retrieving Named Properties) response body.
# Trimmed to two responses (one collection + one file) so the fixture stays
# small; xmlns declarations are preserved verbatim from the RFC.
PROPFIND_MULTISTATUS_BODY = (
    b'<?xml version="1.0" encoding="utf-8" ?>\n'
    b'<D:multistatus xmlns:D="DAV:">\n'
    b'  <D:response>\n'
    b'    <D:href>/webdav/</D:href>\n'
    b'    <D:propstat>\n'
    b'      <D:prop xmlns:R="http://ns.example.com/boxschema/">\n'
    b'        <D:creationdate>1997-12-01T17:42:21-08:00</D:creationdate>\n'
    b'        <D:displayname>Example collection</D:displayname>\n'
    b'        <D:resourcetype><D:collection/></D:resourcetype>\n'
    b'        <D:creator-displayname>alice</D:creator-displayname>\n'
    b'      </D:prop>\n'
    b'      <D:status>HTTP/1.1 200 OK</D:status>\n'
    b'    </D:propstat>\n'
    b'  </D:response>\n'
    b'  <D:response>\n'
    b'    <D:href>/webdav/.git/config</D:href>\n'
    b'    <D:propstat>\n'
    b'      <D:prop>\n'
    b'        <D:displayname>config</D:displayname>\n'
    b'        <D:getcontentlength>92</D:getcontentlength>\n'
    b'        <D:creator-displayname>bob</D:creator-displayname>\n'
    b'      </D:prop>\n'
    b'      <D:status>HTTP/1.1 200 OK</D:status>\n'
    b'    </D:propstat>\n'
    b'  </D:response>\n'
    b'</D:multistatus>\n'
)

# RFC 7235 s.4.1 example — two challenges in one header.
WWW_AUTH_BASIC_DIGEST = (
    'Basic realm="simple", '
    'Digest realm="http-auth@example.org", qop="auth, auth-int", '
    'algorithm=SHA-256, '
    'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", '
    'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"'
)


# A shell-executed nonce for the RCE probe — the module echoes 'recce-rce-'
# then the hex nonce; the fake CGI here mimics the exact stdout the shell
# would produce so the module's proven-check triggers.
RCE_STDOUT_TEMPLATE = b"recce-rce-{nonce}\n"


# ---------------------------------------------------------------------------
# Fake HTTP connection

class _FakeResponse:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self._headers = list(headers)
        self._body = body

    def getheaders(self):
        return list(self._headers)

    def read(self, n: int | None = None):
        if n is None:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data


class _FakeConn:
    """Records the last request; returns whatever the router closure produces."""

    def __init__(self, router):
        self.router = router
        self._req: tuple = ()

    def request(self, method, path, body=None, headers=None):
        self._req = (method, path, body or b"", headers or {})

    def getresponse(self):
        return self.router(*self._req)

    def close(self):
        pass


def _install_router(monkeypatch, router):
    """Point svccommon.http_connect at a factory that yields _FakeConn instances
    wired to `router(method, path, body, headers) -> _FakeResponse`."""
    def _fake_http_connect(ip, port, use_tls, timeout):
        return _FakeConn(router)
    # webdav._request calls http_connect through the module import at the top
    # of webdav.py, so patch THAT binding — patching svccommon alone would miss it.
    monkeypatch.setattr("recce.services.webdav.http_connect", _fake_http_connect)


# ---------------------------------------------------------------------------
# Tests


class ParsingTest(unittest.TestCase):
    def test_parse_www_authenticate_basic_and_digest(self):
        schemes = webdav.parse_www_authenticate(WWW_AUTH_BASIC_DIGEST)
        by_name = {s["scheme"]: s for s in schemes}
        self.assertIn("Basic", by_name)
        self.assertIn("Digest", by_name)
        self.assertEqual(by_name["Basic"]["realm"], "simple")
        self.assertEqual(by_name["Digest"]["realm"], "http-auth@example.org")
        self.assertEqual(by_name["Digest"]["algorithm"], "SHA-256")

    def test_parse_multistatus_hrefs_from_rfc_body(self):
        hrefs = webdav.parse_multistatus_hrefs(PROPFIND_MULTISTATUS_BODY)
        self.assertEqual(hrefs, ["/webdav/", "/webdav/.git/config"])

    def test_parse_creator_displaynames(self):
        users = webdav.parse_creator_displaynames(PROPFIND_MULTISTATUS_BODY)
        self.assertIn("alice", users)
        self.assertIn("bob", users)

    def test_parse_multistatus_malformed_returns_empty(self):
        self.assertEqual(webdav.parse_multistatus_hrefs(b"<not xml"), [])

    def test_cross_mount_leaks_flags_dotgit_and_wpconfig(self):
        hrefs = ["/webdav/index.html", "/webdav/.git/config",
                 "/webdav/wp-config.php", "/webdav/normal.txt"]
        sens = webdav.cross_mount_leaks(hrefs)
        self.assertIn("/webdav/.git/config", sens)
        self.assertIn("/webdav/wp-config.php", sens)
        self.assertNotIn("/webdav/normal.txt", sens)


class TransportTest(unittest.TestCase):
    def test_options_returns_dav_and_allow(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                self.assertEqual(method, "OPTIONS")
                return _FakeResponse(200, OPTIONS_HEADERS_APACHE_MOD_DAV, b"")
            _install_router(m, router)
            caps = webdav.options_capabilities("10.0.0.1", 80, False, "/")
            self.assertEqual(caps["dav"], ["1", "2"])
            self.assertIn("PROPFIND", caps["allow"])
            self.assertIn("MKCOL", caps["allow"])
            self.assertEqual(caps["ms_author_via"], "DAV")
            self.assertEqual(caps["server"],
                             "Apache/2.4.29 (Ubuntu) DAV/2 mod_dav_fs/2.4")
        finally:
            m.undo()

    def test_backend_fingerprint_iis6(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                return _FakeResponse(200, OPTIONS_HEADERS_IIS6, b"")
            _install_router(m, router)
            caps = webdav.options_capabilities("10.0.0.2", 80, False, "/")
            fp = webdav.fingerprint_backend(caps)
            self.assertEqual(fp["product"], "Microsoft-IIS/6.0")
            self.assertIn("CVE-2017-7269", fp["note"])
        finally:
            m.undo()

    def test_backend_fingerprint_apache_mod_dav(self):
        caps = {"server": "Apache/2.4 mod_dav/2.4", "x_dav_powered_by": "",
                "ms_author_via": "DAV", "x_sabre_version": ""}
        fp = webdav.fingerprint_backend(caps)
        self.assertEqual(fp["product"], "Apache mod_dav")

    def test_propfind_extracts_hrefs_and_users(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                self.assertEqual(method, "PROPFIND")
                self.assertEqual(headers.get("Depth"), "1")
                return _FakeResponse(207,
                                     [("Content-Type",
                                       "application/xml; charset=utf-8")],
                                     PROPFIND_MULTISTATUS_BODY)
            _install_router(m, router)
            rec = webdav.probe_mount_propfind("10.0.0.1", 80, False, "/webdav/")
            self.assertTrue(rec["multistatus"])
            self.assertEqual(rec["status"], 207)
            self.assertIn("/webdav/", rec["hrefs"])
            self.assertIn("alice", rec["users"])
        finally:
            m.undo()


class ExploitProbesTest(unittest.TestCase):
    """Every write verb must round-trip PUT/GET/DELETE against a fake handler."""

    def test_anonymous_put_proof_reports_proven(self):
        store: dict[str, bytes] = {}
        m = _Patch()
        try:
            def router(method, path, body, headers):
                if method == "PUT":
                    store[path] = body if isinstance(body, bytes) else body.encode()
                    return _FakeResponse(201, [], b"")
                if method == "GET":
                    if path in store:
                        return _FakeResponse(200, [], store[path])
                    return _FakeResponse(404, [], b"")
                if method == "DELETE":
                    store.pop(path, None)
                    return _FakeResponse(204, [], b"")
                return _FakeResponse(405, [], b"")
            _install_router(m, router)
            res = webdav.anonymous_put_proof("10.0.0.1", 80, False, "/webdav/")
            self.assertTrue(res["proven"])
            # Cleanup DELETE must have run.
            self.assertEqual(store, {})
        finally:
            m.undo()

    def test_anonymous_put_rejected_when_server_returns_403(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                return _FakeResponse(403, [], b"forbidden")
            _install_router(m, router)
            res = webdav.anonymous_put_proof("10.0.0.1", 80, False, "/webdav/")
            self.assertFalse(res["proven"])
            self.assertIn("rejected", res["note"])
        finally:
            m.undo()

    def test_verb_allowlist_records_mkcol_created_and_cleanup(self):
        seen: list[tuple[str, str]] = []
        m = _Patch()
        try:
            def router(method, path, body, headers):
                seen.append((method, path))
                if method == "MKCOL":
                    return _FakeResponse(201, [], b"")
                if method == "PUT":
                    return _FakeResponse(201, [], b"")
                if method == "COPY" or method == "MOVE":
                    return _FakeResponse(201, [], b"")
                if method == "PROPPATCH":
                    return _FakeResponse(207, [], b"")
                if method == "LOCK":
                    return _FakeResponse(200,
                                         [("Lock-Token",
                                           "<opaquelocktoken:recce>")], b"")
                if method == "UNLOCK":
                    return _FakeResponse(204, [], b"")
                if method == "PROPFIND":
                    return _FakeResponse(207, [], b"")
                if method == "DELETE":
                    return _FakeResponse(204, [], b"")
                return _FakeResponse(405, [], b"")
            _install_router(m, router)
            res = webdav.verb_allowlist("10.0.0.1", 80, False, "/webdav/")
            self.assertEqual(res["statuses"]["MKCOL"], 201)
            self.assertEqual(res["statuses"]["PUT"], 201)
            self.assertEqual(res["statuses"]["COPY"], 201)
            self.assertEqual(res["statuses"]["MOVE"], 201)
            self.assertEqual(res["statuses"]["LOCK"], 200)
            # Cleanup: at least one DELETE per created object.
            deletes = [p for (m_, p) in seen if m_ == "DELETE"]
            self.assertGreaterEqual(len(deletes), 3)
        finally:
            m.undo()

    def test_propfind_xxe_hits_when_passwd_is_reflected(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                # The module POSTs a PROPFIND with an XXE-carrying XML body.
                # A vulnerable server echoes /etc/passwd content back inside
                # the multistatus response.
                self.assertEqual(method, "PROPFIND")
                self.assertIn(b"file:///etc/passwd", body)
                resp = (b'<?xml version="1.0"?>\n'
                        b'<D:multistatus xmlns:D="DAV:">\n'
                        b'<D:response><D:href>/</D:href><D:propstat><D:prop>'
                        b'<D:displayname>root:x:0:0:root:/root:/bin/bash</D:displayname>'
                        b'</D:prop></D:propstat></D:response>\n'
                        b'</D:multistatus>')
                return _FakeResponse(207, [], resp)
            _install_router(m, router)
            res = webdav.propfind_xxe("10.0.0.1", 80, False, "/")
            self.assertTrue(res["hit"])
            self.assertIn("root:", res["excerpt"])
        finally:
            m.undo()

    def test_propfind_xxe_no_hit_when_body_is_clean(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                return _FakeResponse(207, [], PROPFIND_MULTISTATUS_BODY)
            _install_router(m, router)
            res = webdav.propfind_xxe("10.0.0.1", 80, False, "/")
            self.assertFalse(res["hit"])
        finally:
            m.undo()

    def test_if_header_bypass_true_when_401_becomes_207(self):
        state = {"count": 0}
        m = _Patch()
        try:
            def router(method, path, body, headers):
                state["count"] += 1
                if "If" in headers:
                    return _FakeResponse(207, [], PROPFIND_MULTISTATUS_BODY)
                return _FakeResponse(401,
                                     [("WWW-Authenticate",
                                       'Basic realm="dav"')], b"")
            _install_router(m, router)
            res = webdav.if_header_bypass("10.0.0.1", 80, False, "/webdav/")
            self.assertTrue(res["bypassed"])
            self.assertEqual(res["plain_status"], 401)
            self.assertIn(res["bypass_status"], (200, 207))
            self.assertEqual(state["count"], 2)
        finally:
            m.undo()

    def test_if_header_bypass_false_when_still_401(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                return _FakeResponse(401,
                                     [("WWW-Authenticate", 'Basic realm="dav"')],
                                     b"")
            _install_router(m, router)
            res = webdav.if_header_bypass("10.0.0.1", 80, False, "/webdav/")
            self.assertFalse(res["bypassed"])
        finally:
            m.undo()

    def test_copy_move_bypass_reports_proven_on_iis6(self):
        store: dict[str, bytes] = {}
        m = _Patch()
        try:
            def router(method, path, body, headers):
                if method == "PUT":
                    store[path] = body if isinstance(body, bytes) else body.encode()
                    return _FakeResponse(201, [], b"")
                if method == "COPY":
                    dst_url = headers.get("Destination", "")
                    # Extract path portion after host.
                    dst_path = dst_url.split("://", 1)[-1].split("/", 1)[-1]
                    dst_path = "/" + dst_path
                    if path in store:
                        store[dst_path] = store[path]
                    return _FakeResponse(201, [], b"")
                if method == "GET":
                    if path in store:
                        return _FakeResponse(200, [], store[path])
                    return _FakeResponse(404, [], b"")
                if method == "DELETE":
                    store.pop(path, None)
                    return _FakeResponse(204, [], b"")
                return _FakeResponse(405, [], b"")
            _install_router(m, router)
            res = webdav.copy_move_bypass("10.0.0.1", 80, False, "/webdav/",
                                          "Microsoft-IIS/6.0", "Microsoft-IIS/6.0")
            self.assertTrue(res["proven"])
            self.assertEqual(res["ext"], "asp")
            self.assertEqual(store, {})
        finally:
            m.undo()

    def test_put_webshell_chain_confirmed_on_nonce_echo(self):
        # The fake server writes the PUT body verbatim; on GET it "executes"
        # the shell by echoing "recce-rce-<nonce>" — the exact stdout the
        # module's confirmation regex looks for.
        store: dict[str, bytes] = {}
        m = _Patch()
        try:
            def router(method, path, body, headers):
                if method == "PUT":
                    store[path] = body if isinstance(body, bytes) else body.encode()
                    return _FakeResponse(201, [], b"")
                if method == "GET":
                    payload = store.get(path, b"")
                    # Extract the nonce the module baked into the shell body:
                    # every shell contains printf/Write of "{NONCE}" replaced
                    # by a 12-hex nonce.
                    import re as _re
                    m2 = _re.search(rb'([0-9a-f]{12})', payload)
                    if not m2:
                        return _FakeResponse(200, [], b"[handler-passthrough]")
                    nonce = m2.group(1)
                    return _FakeResponse(200, [], RCE_STDOUT_TEMPLATE.replace(
                        b"{nonce}", nonce))
                if method == "DELETE":
                    store.pop(path, None)
                    return _FakeResponse(204, [], b"")
                return _FakeResponse(405, [], b"")
            _install_router(m, router)
            res = webdav.put_webshell_chain("10.0.0.1", 80, False, "/webdav/",
                                            "Apache/2.4", "Apache mod_dav")
            self.assertTrue(res["proven"], res.get("note"))
            self.assertIn(res["ext"], ("php", "aspx", "asp", "jsp"))
            self.assertEqual(store, {})
        finally:
            m.undo()


class FullProbeAndFindingsTest(unittest.TestCase):
    """End-to-end: probe() drives options+propfind+active work; findings()
    converts the resulting dict to finding entries with stable kinds."""

    def test_probe_reports_mounts_and_findings_emit_expected_kinds(self):
        # A single mount /webdav/ answers 207 for PROPFIND depth 1 and infinity;
        # OPTIONS advertises DAV 1,2 on Apache mod_dav; verbs succeed; anonymous
        # PUT round-trips.
        store: dict[str, bytes] = {}
        m = _Patch()
        try:
            def router(method, path, body, headers):
                if method == "OPTIONS":
                    return _FakeResponse(200, OPTIONS_HEADERS_APACHE_MOD_DAV, b"")
                if method == "PROPFIND":
                    if path == "/webdav/":
                        return _FakeResponse(207, [], PROPFIND_MULTISTATUS_BODY)
                    return _FakeResponse(404, [], b"")
                if method == "MKCOL":
                    return _FakeResponse(201, [], b"")
                if method == "PROPPATCH":
                    return _FakeResponse(207, [], b"")
                if method == "PUT":
                    store[path] = body if isinstance(body, bytes) else body.encode()
                    return _FakeResponse(201, [], b"")
                if method == "GET":
                    return _FakeResponse(200, [], store.get(path, b""))
                if method == "COPY" or method == "MOVE":
                    return _FakeResponse(201, [], b"")
                if method == "LOCK":
                    return _FakeResponse(200,
                                         [("Lock-Token", "<opaquelocktoken:t>")], b"")
                if method == "UNLOCK":
                    return _FakeResponse(204, [], b"")
                if method == "DELETE":
                    store.pop(path, None)
                    return _FakeResponse(204, [], b"")
                return _FakeResponse(405, [], b"")
            _install_router(m, router)
            pr = webdav.probe("10.0.0.1", 80, False, active=True, upload_shell=False,
                              mounts=("/webdav/",))
            self.assertTrue(pr["reachable"])
            self.assertEqual(len(pr["mounts"]), 1)
            self.assertTrue(pr["anon_put"]["proven"])
            self.assertIn("alice", pr["users"])
            # Sensitive-path pivot picked up /webdav/.git/config.
            self.assertTrue(any(".git" in h for h in pr["sensitive"]))
            # Verb enum saw MKCOL and PUT succeed.
            self.assertEqual(pr["verbs"]["statuses"]["MKCOL"], 201)
            # Backend fingerprint from OPTIONS.
            self.assertEqual(pr["backend"]["product"], "Apache mod_dav")

            host = Host(ip="10.0.0.1", ports=[Port(portid=80, state="open",
                                                    service="http")])
            fs = webdav.findings([host], {("10.0.0.1", 80): pr})
            kinds = {f["kind"] for f in fs}
            self.assertIn("webdav_enabled", kinds)
            self.assertIn("webdav_verbs_enabled", kinds)
            self.assertIn("webdav_mkcol_allowed", kinds)
            self.assertIn("webdav_anon_put", kinds)
            self.assertIn("webdav_href_leak", kinds)
            self.assertIn("webdav_user_leak", kinds)
            self.assertIn("webdav_fingerprint", kinds)
            self.assertIn("webdav_lock_open", kinds)
            # No RCE was requested via upload_shell.
            self.assertNotIn("webdav_put_rce", kinds)
            # Every finding must carry a category + narrative.
            for f in fs:
                self.assertEqual(f["category"], "webdav")
                self.assertTrue(f["kind"])
                self.assertIn("severity", f)
        finally:
            m.undo()

    def test_build_findings_returns_vuln_objects_with_stable_script_ids(self):
        m = _Patch()
        try:
            def router(method, path, body, headers):
                if method == "OPTIONS":
                    return _FakeResponse(200, OPTIONS_HEADERS_APACHE_MOD_DAV, b"")
                if method == "PROPFIND" and path == "/webdav/":
                    return _FakeResponse(207, [], PROPFIND_MULTISTATUS_BODY)
                return _FakeResponse(404, [], b"")
            _install_router(m, router)
            port = Port(portid=80, state="open", service="http")
            vulns = webdav.build_findings("10.0.0.1", port, active=False,
                                          upload_shell=False)
            # At minimum an "enabled" + fingerprint finding fire.
            self.assertTrue(vulns)
            for v in vulns:
                self.assertEqual(v.source, "webdav")
                self.assertTrue(v.script_id.startswith("webdav:"))
                self.assertEqual(v.ip, "10.0.0.1")
        finally:
            m.undo()

    def test_svn_probe_fires_when_backend_is_mod_dav_svn(self):
        m = _Patch()
        try:
            svn_options = [
                ("Server", "Apache/2.4.29 mod_dav_svn/1.10.4"),
                ("DAV", "1,2,version-control,checkout,working-resource,merge,"
                        "update,label,history,workspace"),
                ("Allow", "OPTIONS,GET,HEAD,PROPFIND,REPORT"),
                ("MS-Author-Via", "DAV"),
            ]
            def router(method, path, body, headers):
                if method == "OPTIONS":
                    return _FakeResponse(200, svn_options, b"")
                if method == "PROPFIND" and path == "/svn/":
                    return _FakeResponse(207, [], PROPFIND_MULTISTATUS_BODY)
                if method == "GET" and "/!svn/vcc/default" in path:
                    return _FakeResponse(200, [], b"<D:href>/!svn/bc/1/</D:href>")
                if method == "GET":
                    return _FakeResponse(404, [], b"")
                # Every write verb rejected — svn is read-only for this test.
                return _FakeResponse(403, [], b"")
            _install_router(m, router)
            pr = webdav.probe("10.0.0.1", 80, False, active=True,
                              upload_shell=False, mounts=("/svn/",))
            self.assertTrue(pr["reachable"])
            self.assertEqual(pr["backend"]["product"], "mod_dav_svn")
            self.assertTrue(pr.get("svn", {}).get("hits"))
        finally:
            m.undo()


if __name__ == "__main__":
    unittest.main()
