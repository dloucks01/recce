"""BOLA/IDOR + CSRF-form-hygiene checks in crawl.scan_crawl.

The BOLA check is safe: it sends only GET requests that shift a numeric id
parameter by ±1 and diffs the response against the baseline. The CSRF check
is zero-request — it reads the `csrf: bool` field _parse_form populates during
crawl.

Fixtures drive a local HTTP server directly; nothing about these tests requires
network egress.
"""
from __future__ import annotations

import socket
import threading

from http.server import BaseHTTPRequestHandler, HTTPServer

from recce.core.models import Host, Port
# The web package star-imports `crawl` (the function) into its namespace, so
# `from recce.services.web import crawl` gets the function and the attribute
# access `recce.services.web.crawl` inside `import ... as crawl` resolves to
# the function too. Force the module via sys.modules.
import importlib
crawl = importlib.import_module("recce.services.web.crawl")


# --- BOLA -------------------------------------------------------------------

class _BolaHandler(BaseHTTPRequestHandler):
    """A tiny app: /order?id=N returns "user N's order" for every N — the
    classic BOLA where the app never checks that the caller owns object N."""

    def log_message(self, *a, **k):
        pass

    def do_GET(self):
        if self.path == "/":
            body = b'<html><a href="/order?id=42">order 42</a></html>'
        elif self.path.startswith("/order?id="):
            try:
                oid = int(self.path.split("=", 1)[1].split("&", 1)[0])
            except ValueError:
                self.send_response(400); self.end_headers(); return
            body = (f"<html><body>Order for user {oid}: item-{oid * 7} "
                    f"cost ${oid * 100}<br>ship-to: address-{oid}</body></html>"
                    .encode())
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_bola_scan_flags_incrementing_id_that_returns_different_data():
    """The core BOLA finding shape: same URL, different id => different 200
    body => the app is not checking ownership."""
    srv = _start_server(_BolaHandler)
    try:
        port = Port(portid=srv.server_address[1], state="open", service="http")
        host = Host(ip="127.0.0.1", ports=[port])
        crawl.scan_crawl(host)
    finally:
        srv.shutdown()
        srv.server_close()
    bola = [v for v in host.vulns if v.script_id == "web-bola"]
    assert bola, "BOLA finding not emitted against a materially-different response"
    f = bola[0]
    assert f.severity == "high"
    assert "IDOR" in f.title or "BOLA" in f.title


class _AuthorizedHandler(BaseHTTPRequestHandler):
    """Correctly-authorized app: /order?id=N returns 403 unless N == 42."""

    def log_message(self, *a, **k):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = b'<html><a href="/order?id=42">your order</a></html>'
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body); return
        if self.path == "/order?id=42":
            body = b"<html><body>Your order 42 details.</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body); return
        self.send_response(403); self.end_headers()


def test_bola_scan_does_not_false_positive_when_authorization_holds():
    """An app that returns 403 (or 404) for other users' ids must NOT trigger
    the BOLA finding — a false positive here lands a critical-severity issue
    in a client report."""
    srv = _start_server(_AuthorizedHandler)
    try:
        port = Port(portid=srv.server_address[1], state="open", service="http")
        host = Host(ip="127.0.0.1", ports=[port])
        crawl.scan_crawl(host)
    finally:
        srv.shutdown()
        srv.server_close()
    assert not any(v.script_id == "web-bola" for v in host.vulns), \
        "BOLA fired on an authorized endpoint (false positive)"


def test_looks_bola_worth_only_numeric_id_style_params():
    assert crawl._looks_bola_worth("id", "42")
    assert crawl._looks_bola_worth("user_id", "1004")
    assert crawl._looks_bola_worth("invoice", "5")
    # non-numeric values, non-id params: no
    assert not crawl._looks_bola_worth("id", "guest")
    assert not crawl._looks_bola_worth("search", "42")
    assert not crawl._looks_bola_worth("page", "42")


def test_replace_id_keeps_other_query_params_intact():
    assert crawl._replace_id("/api/orders?id=42&fmt=json", "id", 43) == \
           "/api/orders?id=43&fmt=json"
    # non-matching param name: leave alone
    assert crawl._replace_id("/api/orders?other=42", "id", 43) == \
           "/api/orders?other=42"
    # no query string at all: leave alone
    assert crawl._replace_id("/api/orders", "id", 43) == "/api/orders"


# --- CSRF -------------------------------------------------------------------

def test_csrf_scan_flags_post_form_without_a_csrf_token():
    forms = [
        {"action": "/transfer", "method": "post", "csrf": False, "password": False,
         "fields": [("amount", "text"), ("to", "text"), ("submit", "submit")]},
    ]
    from recce.core.models import Port
    port = Port(portid=80, state="open", service="http")
    findings = crawl._csrf_scan("10.0.0.1", port, forms)
    assert len(findings) == 1
    assert findings[0].script_id == "web-csrf"
    assert "/transfer" in findings[0].title


def test_csrf_scan_skips_form_that_already_carries_a_token():
    forms = [{"action": "/x", "method": "post", "csrf": True,
              "fields": [("k", "text")]}]
    port = Port(portid=80, state="open", service="http")
    assert crawl._csrf_scan("10.0.0.1", port, forms) == []


def test_csrf_scan_skips_get_forms_and_no_side_effect_forms():
    forms = [
        {"action": "/search", "method": "get", "csrf": False,
         "fields": [("q", "text")]},                          # GET = idempotent
        {"action": "/x", "method": "post", "csrf": False,
         "fields": [("submit", "submit")]},                    # no real fields
    ]
    port = Port(portid=80, state="open", service="http")
    assert crawl._csrf_scan("10.0.0.1", port, forms) == []


def test_csrf_scan_bumps_severity_for_password_carrying_forms():
    """A password-bearing form without CSRF is a login-page CSRF (session
    fixation / clickjacking pairs), meaningfully worse than an ordinary
    POST — should not sit at low severity."""
    forms = [{"action": "/login", "method": "post", "csrf": False,
              "password": True,
              "fields": [("user", "text"), ("pw", "password")]}]
    port = Port(portid=80, state="open", service="http")
    f = crawl._csrf_scan("10.0.0.1", port, forms)[0]
    assert f.severity == "medium"


def test_crawl_now_returns_params_v_with_values():
    """The BOLA scan needs the parameter's VALUE, not just its name — the
    params_v field is what supplies that. Prove it does."""
    srv = _start_server(_BolaHandler)
    try:
        port = Port(portid=srv.server_address[1], state="open", service="http")
        cres = crawl.crawl("127.0.0.1", port)
    finally:
        srv.shutdown()
        srv.server_close()
    with_values = [(p, n, v) for p, n, v in cres["params_v"] if n == "id"]
    assert with_values, "params_v didn't carry the id parameter value"
    assert with_values[0][2] == "42"


def _wait_port_closed():
    """Small helper to keep tests deterministic when adding new server tests."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
