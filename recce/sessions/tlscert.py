"""TLS for shell channels — encrypted shell traffic (defeats on-wire sniffing / network IDS),
a Sliver/pwncat-like property kept lightweight: python's `ssl` on both sides, no new Python
dependency. The one external need is a self-signed cert, generated once via `openssl` (a
ubiquitous runtime tool, not a Python dep) and cached in the engagement dir.
"""
from __future__ import annotations

import os
import ssl
import subprocess


def ensure_server_cert(eng_dir: str) -> tuple[str, str]:
    """(cert, key) paths — generated self-signed on first use, then reused."""
    cert = os.path.join(eng_dir, ".recce-c2-cert.pem")
    key = os.path.join(eng_dir, ".recce-c2-key.pem")
    if os.path.isfile(cert) and os.path.isfile(key):
        return cert, key
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert,
         "-days", "3650", "-nodes", "-subj", "/CN=recce"],
        check=True, capture_output=True)
    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    return cert, key


def server_ssl_context(eng_dir: str) -> ssl.SSLContext:
    """A TLS-server context for a listener; raises if openssl isn't available to make a cert."""
    cert, key = ensure_server_cert(eng_dir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx
