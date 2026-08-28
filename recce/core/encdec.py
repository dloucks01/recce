"""Encoder/decoder toolbox — a compact CyberChef-style op registry.

Every operation is a pure function: string in → string out. When something
can't be applied cleanly (invalid base64, malformed JSON, wrong key size),
the operation raises EncDecError with a tester-friendly message; callers
render it as an error string in the CLI / UI.

Airgap-safe: stdlib only (base64, binascii, hashlib, hmac, html, json,
urllib.parse, codecs, zlib). No external dependencies.

Design:
  * OPERATIONS registry maps op_name -> (function, one-line description).
  * apply(op_name, input_text) is the single entry point used by both the
    CLI subcommand and the /api/encdec HTTP endpoint.
  * list_ops() returns metadata for the UI to render the op picker.
  * chain(ops, input) pipes input through multiple ops in order — the
    "recipe" pattern from CyberChef, useful for URL-decode-then-JSON-parse
    on a cookie value.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import hmac
import html
import json
import re
import urllib.parse
import zlib
from typing import Callable


class EncDecError(ValueError):
    """Raised when an operation can't be applied to the input.
    Message is safe to show verbatim to the tester."""


# ---- primitive helpers -------------------------------------------------------

def _to_bytes(s: str) -> bytes:
    return s.encode("utf-8", "surrogateescape")


def _from_bytes(b: bytes) -> str:
    return b.decode("utf-8", "replace")


# ---- base encodings ----------------------------------------------------------

def b64_encode(s: str) -> str:
    return base64.b64encode(_to_bytes(s)).decode("ascii")


def b64_decode(s: str) -> str:
    # Be lenient: strip whitespace, add padding if missing.
    stripped = re.sub(r"\s+", "", s)
    if len(stripped) % 4:
        stripped += "=" * (4 - len(stripped) % 4)
    try:
        return _from_bytes(base64.b64decode(stripped, validate=False))
    except binascii.Error as e:
        raise EncDecError(f"not valid base64: {e}")


def b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(_to_bytes(s)).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> str:
    stripped = re.sub(r"\s+", "", s)
    if len(stripped) % 4:
        stripped += "=" * (4 - len(stripped) % 4)
    try:
        return _from_bytes(base64.urlsafe_b64decode(stripped))
    except binascii.Error as e:
        raise EncDecError(f"not valid base64url: {e}")


def b32_encode(s: str) -> str:
    return base64.b32encode(_to_bytes(s)).decode("ascii")


def b32_decode(s: str) -> str:
    stripped = re.sub(r"\s+", "", s).upper()
    if len(stripped) % 8:
        stripped += "=" * (8 - len(stripped) % 8)
    try:
        return _from_bytes(base64.b32decode(stripped))
    except binascii.Error as e:
        raise EncDecError(f"not valid base32: {e}")


def b85_encode(s: str) -> str:
    return base64.b85encode(_to_bytes(s)).decode("ascii")


def b85_decode(s: str) -> str:
    try:
        return _from_bytes(base64.b85decode(_to_bytes(s.strip())))
    except (ValueError, binascii.Error) as e:
        raise EncDecError(f"not valid base85: {e}")


def hex_encode(s: str) -> str:
    return _to_bytes(s).hex()


def hex_decode(s: str) -> str:
    # Strip whitespace and common byte-list separators, then remove
    # explicit "0x" and "\x" byte prefixes without touching real hex
    # nibbles (a naive [0x] class removes every 0 and x from the digits).
    stripped = re.sub(r"[\s:,]", "", s)
    stripped = re.sub(r"\\x", "", stripped)
    stripped = re.sub(r"0x", "", stripped, flags=re.I)
    if len(stripped) % 2:
        raise EncDecError("hex string must have an even length")
    try:
        return _from_bytes(bytes.fromhex(stripped))
    except ValueError as e:
        raise EncDecError(f"not valid hex: {e}")


# ---- URL / HTML / Unicode ----------------------------------------------------

def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    return urllib.parse.unquote_plus(s)


def html_encode(s: str) -> str:
    return html.escape(s, quote=True)


def html_decode(s: str) -> str:
    return html.unescape(s)


def unicode_escape_encode(s: str) -> str:
    # \uXXXX for non-ASCII, backslash-escape controls.
    return s.encode("unicode_escape").decode("ascii")


def unicode_escape_decode(s: str) -> str:
    try:
        return codecs.decode(s, "unicode_escape")
    except UnicodeDecodeError as e:
        raise EncDecError(f"could not unescape: {e}")


def punycode_encode(s: str) -> str:
    """IDNA / Punycode — for domain names."""
    try:
        return s.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise EncDecError(f"not encodable as IDNA: {e}")


def punycode_decode(s: str) -> str:
    try:
        return s.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError) as e:
        raise EncDecError(f"not a valid Punycode/IDNA string: {e}")


# ---- classical / obfuscation ------------------------------------------------

def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def rot_n(s: str, n: int = 13) -> str:
    """Rotate letters by n positions. Symbol/digit unchanged."""
    out = []
    for ch in s:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + n) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + n) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def reverse(s: str) -> str:
    return s[::-1]


def case_flip(s: str) -> str:
    return s.swapcase()


def xor_hex_key(s: str, key_hex: str) -> str:
    """XOR the input bytes with a repeating hex-encoded key. Output is hex."""
    try:
        key = bytes.fromhex(re.sub(r"\s", "", key_hex))
    except ValueError as e:
        raise EncDecError(f"key is not valid hex: {e}")
    if not key:
        raise EncDecError("key must be non-empty")
    data = _to_bytes(s)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).hex()


def xor_decode_hex_key(hex_in: str, key_hex: str) -> str:
    """Inverse of xor_hex_key: input is hex, output is UTF-8 (replace-on-error)."""
    try:
        data = bytes.fromhex(re.sub(r"\s", "", hex_in))
    except ValueError as e:
        raise EncDecError(f"input is not valid hex: {e}")
    try:
        key = bytes.fromhex(re.sub(r"\s", "", key_hex))
    except ValueError as e:
        raise EncDecError(f"key is not valid hex: {e}")
    if not key:
        raise EncDecError("key must be non-empty")
    return _from_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(data)))


# ---- hashing ----------------------------------------------------------------

def _hash_hex(alg: str, s: str) -> str:
    return hashlib.new(alg, _to_bytes(s)).hexdigest()


def md5(s: str) -> str: return _hash_hex("md5", s)
def sha1(s: str) -> str: return _hash_hex("sha1", s)
def sha224(s: str) -> str: return _hash_hex("sha224", s)
def sha256(s: str) -> str: return _hash_hex("sha256", s)
def sha384(s: str) -> str: return _hash_hex("sha384", s)
def sha512(s: str) -> str: return _hash_hex("sha512", s)


def nt_hash(s: str) -> str:
    """NT hash (MD4 of UTF-16-LE) — the Windows NTLM 'NT' half. Testers use
    this to convert cleartext passwords into pass-the-hash-ready format."""
    return hashlib.new("md4", s.encode("utf-16-le")).hexdigest()


def hmac_sha256(s: str, key: str) -> str:
    return hmac.new(_to_bytes(key), _to_bytes(s), hashlib.sha256).hexdigest()


def hmac_sha1(s: str, key: str) -> str:
    return hmac.new(_to_bytes(key), _to_bytes(s), hashlib.sha1).hexdigest()


# ---- compression -----------------------------------------------------------

def gzip_encode_b64(s: str) -> str:
    """Gzip-compress the input, return base64-encoded bytes."""
    import gzip
    return base64.b64encode(gzip.compress(_to_bytes(s))).decode("ascii")


def gzip_decode_b64(s: str) -> str:
    """Base64-decode then gzip-decompress."""
    import gzip
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", s))
        return _from_bytes(gzip.decompress(raw))
    except (binascii.Error, OSError, EOFError) as e:
        raise EncDecError(f"not valid gzip+base64: {e}")


def deflate_encode_b64(s: str) -> str:
    """zlib deflate + base64."""
    return base64.b64encode(zlib.compress(_to_bytes(s))).decode("ascii")


def deflate_decode_b64(s: str) -> str:
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", s))
        return _from_bytes(zlib.decompress(raw))
    except (binascii.Error, zlib.error) as e:
        raise EncDecError(f"not valid deflate+base64: {e}")


# ---- structured data --------------------------------------------------------

def json_pretty(s: str) -> str:
    try:
        return json.dumps(json.loads(s), indent=2, ensure_ascii=False,
                          sort_keys=True)
    except (ValueError, TypeError) as e:
        raise EncDecError(f"not valid JSON: {e}")


def json_minify(s: str) -> str:
    try:
        return json.dumps(json.loads(s), separators=(",", ":"), ensure_ascii=False)
    except (ValueError, TypeError) as e:
        raise EncDecError(f"not valid JSON: {e}")


def jwt_decode(s: str) -> str:
    """Decode a JWT's header and payload (base64url) into a pretty JSON
    document. Does NOT verify the signature — the tester's use case is
    inspecting claims and headers, not authenticating tokens."""
    parts = s.strip().split(".")
    if len(parts) < 2:
        raise EncDecError("JWT must have at least header.payload segments")

    def _decode_segment(seg: str) -> dict:
        pad = "=" * (-len(seg) % 4)
        try:
            raw = base64.urlsafe_b64decode(seg + pad)
        except binascii.Error as e:
            raise EncDecError(f"segment is not valid base64url: {e}")
        try:
            return json.loads(raw)
        except ValueError as e:
            raise EncDecError(f"segment is not valid JSON: {e}")
    out = {"header": _decode_segment(parts[0]),
           "payload": _decode_segment(parts[1])}
    if len(parts) >= 3:
        out["signature_b64url"] = parts[2]     # opaque; not verified
    return json.dumps(out, indent=2, ensure_ascii=False)


# ---- registry ---------------------------------------------------------------

# Each entry: name -> (callable, description, requires_key: bool)
# requires_key ops accept an extra `key` positional argument.
OPERATIONS: dict[str, tuple[Callable, str, bool]] = {
    "base64-encode":        (b64_encode,               "UTF-8 → standard base64", False),
    "base64-decode":        (b64_decode,               "base64 → UTF-8 (lenient padding)", False),
    "base64url-encode":     (b64url_encode,            "UTF-8 → URL-safe base64 (no padding)", False),
    "base64url-decode":     (b64url_decode,            "URL-safe base64 → UTF-8", False),
    "base32-encode":        (b32_encode,               "UTF-8 → base32", False),
    "base32-decode":        (b32_decode,               "base32 → UTF-8", False),
    "base85-encode":        (b85_encode,               "UTF-8 → base85 (RFC 1924)", False),
    "base85-decode":        (b85_decode,               "base85 → UTF-8", False),
    "hex-encode":           (hex_encode,               "UTF-8 → hex", False),
    "hex-decode":           (hex_decode,               "hex → UTF-8 (strips spaces/colons/0x)", False),
    "url-encode":           (url_encode,               "percent-encode all chars", False),
    "url-decode":           (url_decode,               "percent-decode (+ → space)", False),
    "html-encode":          (html_encode,              "HTML entity-escape", False),
    "html-decode":          (html_decode,              "HTML entity-decode", False),
    "unicode-escape":       (unicode_escape_encode,    "\\uXXXX escapes for non-ASCII", False),
    "unicode-unescape":     (unicode_escape_decode,    "Decode \\uXXXX and \\xXX escapes", False),
    "punycode-encode":      (punycode_encode,          "Domain → Punycode (IDNA)", False),
    "punycode-decode":      (punycode_decode,          "Punycode → Unicode domain", False),
    "rot13":                (rot13,                    "Caesar cipher +13 (self-inverse)", False),
    "reverse":              (reverse,                  "Reverse the string", False),
    "case-flip":            (case_flip,                "aBc → AbC", False),
    "xor-hex-key-encode":   (xor_hex_key,              "XOR input with repeating hex key → hex", True),
    "xor-hex-key-decode":   (xor_decode_hex_key,       "hex input XOR'd with hex key → UTF-8", True),
    "md5":                  (md5,                      "MD5 hex digest", False),
    "sha1":                 (sha1,                     "SHA-1 hex digest", False),
    "sha224":               (sha224,                   "SHA-224 hex digest", False),
    "sha256":               (sha256,                   "SHA-256 hex digest", False),
    "sha384":               (sha384,                   "SHA-384 hex digest", False),
    "sha512":               (sha512,                   "SHA-512 hex digest", False),
    "nt-hash":              (nt_hash,                  "NT (NTLM) hash of password", False),
    "hmac-sha256":          (hmac_sha256,              "HMAC-SHA-256 with `key`", True),
    "hmac-sha1":            (hmac_sha1,                "HMAC-SHA-1 with `key`", True),
    "gzip-encode-b64":      (gzip_encode_b64,          "gzip-compress → base64", False),
    "gzip-decode-b64":      (gzip_decode_b64,          "base64 → gzip-decompress", False),
    "deflate-encode-b64":   (deflate_encode_b64,       "zlib-deflate → base64", False),
    "deflate-decode-b64":   (deflate_decode_b64,       "base64 → zlib-inflate", False),
    "json-pretty":          (json_pretty,              "Reformat JSON with indent + sort", False),
    "json-minify":          (json_minify,              "Compact JSON, no whitespace", False),
    "jwt-decode":           (jwt_decode,               "JWT header + payload as JSON (signature NOT verified)", False),
    "rot-n":                (rot_n,                    "Caesar cipher by N (default 13); pass `key` as an integer", True),
}


def list_ops() -> list[dict]:
    """Return metadata rows for the UI's op picker."""
    return [{"name": n, "description": d, "requires_key": rk}
            for n, (_, d, rk) in sorted(OPERATIONS.items())]


def apply(op_name: str, input_text: str, key: str = "") -> str:
    """Run one op. Raises EncDecError on any operation-specific failure."""
    if op_name not in OPERATIONS:
        raise EncDecError(f"unknown operation {op_name!r}. See list_ops() for the "
                          f"catalogue (or `recce encdec --list`).")
    fn, _desc, requires_key = OPERATIONS[op_name]
    if requires_key:
        if not key:
            raise EncDecError(f"operation {op_name!r} requires a `key` argument")
        if op_name == "rot-n":
            try:
                n = int(key)
            except ValueError:
                raise EncDecError("rot-n key must be an integer")
            return fn(input_text, n)
        return fn(input_text, key)
    return fn(input_text)


def chain(ops: list[str | tuple[str, str]], input_text: str) -> str:
    """Pipe input through a sequence of ops. Each entry is either an op name
    (no key) or a (name, key) tuple for keyed ops.

    Example:
      chain([("xor-hex-key-decode", "deadbeef"), "gzip-decode-b64", "json-pretty"], data)
    """
    out = input_text
    for step in ops:
        if isinstance(step, tuple):
            name, key = step
            out = apply(name, out, key=key)
        else:
            out = apply(step, out)
    return out
