"""Short-lived HTTP stager for `deploy --stager`.

Instead of pushing the 39 KB Windows enum script to each host (too big to inline
over SMB's cmd.exe, a bloated blob over WinRM), stand up a tiny stdlib HTTP
server that serves the read-only scripts under a random token path. A Windows
host is then triggered (over its existing WinRM/SMB exec channel) to fetch + run
the script **in memory** with a one-line download cradle - no temp file, no size
limit. SSH is unaffected (its stdin-pipe already runs in memory at any size).

stdlib only (http.server); no artifact on the target; the server is bound only
for the run and torn down on exit. The scripts it serves are READ-ONLY.
"""
from __future__ import annotations

import http.server
import secrets
import socket
import threading


def detect_lhost(probe: str = "10.255.255.255") -> str | None:
    """Best-effort local IP a target would route back to (the address of the
    interface used to reach the scope). No packet is actually sent."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


class Stager:
    """Context manager. Serves {name: bytes} under a random token path on lhost.

        with Stager(lhost, {"recce-enum.ps1": data}) as st:
            url = st.url("recce-enum.ps1")   # http://lhost:port/<token>/recce-enum.ps1
    """

    def __init__(self, lhost: str, files: dict[str, bytes], port: int = 0):
        self.lhost = lhost
        self.token = secrets.token_urlsafe(12)
        self._files = {name: (data if isinstance(data, bytes) else data.encode())
                       for name, data in files.items()}
        self._port = port
        self._httpd = None
        self._thread = None
        self.hits = 0

    def url(self, name: str) -> str:
        return f"http://{self.lhost}:{self.port}/{self.token}/{name}"

    @property
    def port(self) -> int:
        return self._httpd.server_address[1] if self._httpd else self._port

    def __enter__(self) -> "Stager":
        token, files, self_ref = self.token, self._files, self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):        # keep it quiet
                pass

            def _serve(self, body: bool):
                parts = self.path.strip("/").split("/", 1)
                name = parts[1] if len(parts) == 2 else ""
                ok = (len(parts) == 2
                      and secrets.compare_digest(parts[0], token)
                      and name in files)
                if not ok:
                    self.send_error(404)
                    return
                data = files[name]
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if body:
                    self_ref.hits += 1
                    self.wfile.write(data)

            def do_GET(self):
                self._serve(body=True)

            def do_HEAD(self):
                self._serve(body=False)

        # Bind all interfaces so the target can reach us on whatever path routes
        # back; the URL we hand out advertises the operator-facing lhost.
        self._httpd = http.server.ThreadingHTTPServer(("0.0.0.0", self._port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
