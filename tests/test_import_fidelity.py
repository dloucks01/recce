"""High-fidelity import test: run the REAL tools against REAL listeners and import their
ACTUAL output through /api/import — not a hand-written sample. This catches the real-world
quirks (exact field layout, encodings, formatting) a synthetic fixture can miss, which is
where import bugs actually hide.

Gated on the tool being present; skips cleanly on a bare box so the normal suite is
unaffected. Credential-tool fidelity (real nxc / Kerberoast / secretsdump) is covered
separately by tests/test_credentialed_ad_integration.py against a real Samba DC.
"""
from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi.testclient import TestClient

from recce.core.store import Store
from recce.webui.app import create_app

HAVE_NMAP = shutil.which("nmap") is not None
HAVE_MASSCAN = shutil.which("masscan") is not None


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


class _Listeners:
    """A couple of real TCP listeners on 127.0.0.1 so a real scan finds real open ports."""
    def __enter__(self):
        self.ports = [_free_port(), _free_port()]
        self.servers = []
        for p in self.ports:
            srv = ThreadingHTTPServer(("127.0.0.1", p), _Quiet)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers.append(srv)
        time.sleep(0.2)
        return self.ports

    def __exit__(self, *a):
        for s in self.servers:
            s.shutdown()


def _client():
    d = tempfile.mkdtemp()
    Store(os.path.join(d, "results.sqlite")).close()
    return TestClient(create_app(d)), d


def _import_file(c, path: str, kind: str = "auto"):
    with open(path, "rb") as fh:
        raw = fh.read()
    return c.post("/api/import", json={"content": base64.b64encode(raw).decode(),
                                       "encoding": "base64", "kind": kind,
                                       "filename": os.path.basename(path)})


def _wait_host(d, ip, timeout=10.0):
    db = os.path.join(d, "results.sqlite")
    end = time.time() + timeout
    while time.time() < end:
        st = Store(db)
        try:
            h = next((x for x in st.all_hosts() if x.ip == ip), None)
        finally:
            st.close()
        if h and h.open_ports:
            return h
        time.sleep(0.15)
    return h


@unittest.skipUnless(HAVE_NMAP, "nmap not installed")
class RealNmapImport(unittest.TestCase):
    def test_real_nmap_all_output_formats(self):
        with _Listeners() as ports:
            pspec = ",".join(str(p) for p in ports)
            for flag, ext in [("-oX", "xml"), ("-oG", "gnmap"), ("-oN", "nmap")]:
                out = tempfile.mktemp(suffix=f".{ext}")
                # -sT connect scan works without root; -Pn skips host discovery on loopback.
                subprocess.run(["nmap", "-sT", "-Pn", "-n", "-p", pspec, flag, out,
                                "127.0.0.1"], capture_output=True, timeout=60)
                self.assertTrue(os.path.exists(out) and os.path.getsize(out) > 0,
                                f"nmap produced no {ext} output")
                c, d = _client()
                _import_file(c, out)
                os.remove(out)
                # job-mode: the CLI import folds asynchronously
                h = _wait_host(d, "127.0.0.1")
                self.assertIsNotNone(h, f"{ext}: host not imported")
                got = {p.portid for p in h.open_ports}
                self.assertTrue(set(ports).issubset(got),
                                f"{ext}: imported ports {got} missing real open ports {ports}")

    def test_real_nmap_reimport_no_duplicate(self):
        with _Listeners() as ports:
            pspec = ",".join(str(p) for p in ports)
            out = tempfile.mktemp(suffix=".xml")
            subprocess.run(["nmap", "-sT", "-Pn", "-n", "-p", pspec, "-oX", out,
                            "127.0.0.1"], capture_output=True, timeout=60)
            c, d = _client()
            _import_file(c, out); _wait_host(d, "127.0.0.1")
            st = Store(os.path.join(d, "results.sqlite"))
            try:
                first = sum(len(h.ports) for h in st.all_hosts())
            finally:
                st.close()
            _import_file(c, out); _wait_host(d, "127.0.0.1")   # same real file again
            time.sleep(0.5)
            os.remove(out)
            st = Store(os.path.join(d, "results.sqlite"))
            try:
                second = sum(len(h.ports) for h in st.all_hosts())
            finally:
                st.close()
            self.assertEqual(first, second, "re-importing real nmap output duplicated ports")


@unittest.skipUnless(HAVE_MASSCAN and _is_root(), "masscan needs root (raw sockets)")
class RealMasscanImport(unittest.TestCase):
    def test_real_masscan_list_and_json(self):
        with _Listeners() as ports:
            pspec = ",".join(str(p) for p in ports)
            for flag, ext in [("-oL", "list"), ("-oJ", "json")]:
                out = tempfile.mktemp(suffix=f".{ext}")
                subprocess.run(["masscan", "-p", pspec, "127.0.0.1", "--rate", "1000",
                                flag, out], capture_output=True, timeout=60)
                if not (os.path.exists(out) and os.path.getsize(out) > 0):
                    continue
                c, d = _client()
                _import_file(c, out)
                h = _wait_host(d, "127.0.0.1")
                os.remove(out)
                self.assertIsNotNone(h, f"masscan {ext}: host not imported")


if __name__ == "__main__":
    unittest.main()
