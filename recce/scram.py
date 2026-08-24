"""SCRAM (RFC 5802 / RFC 7677) client - stdlib only.

Shared by the PostgreSQL (SCRAM-SHA-256) and MongoDB (SCRAM-SHA-1/256) credentialed
paths so the wire math lives in one tested place. No third-party crypto: hashlib
(pbkdf2_hmac, sha1/sha256) + hmac are all standard library.

The caller drives the exchange:
    c = ScramClient("alice", "s3cret")           # SHA-256 by default
    client_first = c.first_message()             # -> "n,,n=alice,r=<nonce>"
    # send client_first, read the server-first, then:
    client_final = c.final_message(server_first)  # -> "c=biws,r=...,p=<proof>"
    # send client_final, read the server-final, then:
    ok = c.verify(server_final)                    # True if v=<ServerSignature> matches

MongoDB SCRAM-SHA-1 hashes the password as md5(user:mongo:password) before PBKDF2;
pass that via `password_digest` (see mongo_sha1_secret). PostgreSQL and mongo
SCRAM-SHA-256 use the password as-is.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _esc(name: str) -> str:
    """SCRAM username escaping: ',' -> '=2C', '=' -> '=3D'."""
    return name.replace("=", "=3D").replace(",", "=2C")


def mongo_sha1_secret(user: str, password: str) -> str:
    """MongoDB SCRAM-SHA-1 feeds md5(user:mongo:password) (hex) into PBKDF2, not the
    raw password."""
    return hashlib.md5(f"{user}:mongo:{password}".encode()).hexdigest()


class ScramClient:
    def __init__(self, user: str, password: str, mechanism: str = "SCRAM-SHA-256",
                 nonce: str | None = None):
        self.hashname = "sha1" if "SHA-1" in mechanism or "SHA1" in mechanism else "sha256"
        self.user = user
        self.password = password
        self.client_nonce = nonce or base64.b64encode(os.urandom(18)).decode("ascii")
        self.client_first_bare = f"n={_esc(user)},r={self.client_nonce}"
        self._auth_message = ""

    def first_message(self) -> str:
        return "n,," + self.client_first_bare

    @staticmethod
    def _parse(msg: str) -> dict:
        out = {}
        for field in msg.split(","):
            if "=" in field:
                k, v = field.split("=", 1)
                out[k] = v
        return out

    def final_message(self, server_first: str) -> str:
        sf = self._parse(server_first)
        nonce = sf["r"]
        if not nonce.startswith(self.client_nonce):
            raise ValueError("server nonce does not extend the client nonce")
        salt = base64.b64decode(sf["s"])
        if len(salt) > 1024:
            raise ValueError(f"server SCRAM salt {len(salt)}B exceeds sanity cap")
        iterations = int(sf["i"])
        if not 1 <= iterations <= 600_000:
            raise ValueError(f"server SCRAM i={iterations} out of range (1..600000)")
        salted = hashlib.pbkdf2_hmac(self.hashname, self.password.encode(), salt, iterations)
        client_key = hmac.new(salted, b"Client Key", self.hashname).digest()
        stored_key = hashlib.new(self.hashname, client_key).digest()
        channel = base64.b64encode(b"n,,").decode("ascii")     # "biws"
        client_final_noproof = f"c={channel},r={nonce}"
        self._auth_message = f"{self.client_first_bare},{server_first},{client_final_noproof}"
        client_sig = hmac.new(stored_key, self._auth_message.encode(), self.hashname).digest()
        proof = _xor(client_key, client_sig)
        server_key = hmac.new(salted, b"Server Key", self.hashname).digest()
        self._server_sig = hmac.new(server_key, self._auth_message.encode(),
                                    self.hashname).digest()
        return f"{client_final_noproof},p={base64.b64encode(proof).decode('ascii')}"

    def verify(self, server_final: str) -> bool:
        """Confirm the server proved knowledge of the password (mutual auth)."""
        sf = self._parse(server_final)
        v = sf.get("v")
        if not v:
            return False
        try:
            return hmac.compare_digest(base64.b64decode(v), self._server_sig)
        except (ValueError, AttributeError):
            return False
