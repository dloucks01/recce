"""Tests for recce.encdec — the encoder/decoder toolbox.

Round-trip every symmetric op pair; validate specific outputs for the
canonical fixtures (hashes, JWTs, gzip); confirm failures produce
EncDecError rather than crashing.
"""
from __future__ import annotations

import unittest

from recce.core import encdec


class RoundTripTest(unittest.TestCase):
    """encode(decode(x)) == x for every reversible pair."""

    _SAMPLE = "Hello, world! ✓ üñíçøðé 你好"

    def test_base64(self):
        self.assertEqual(encdec.apply("base64-decode",
                         encdec.apply("base64-encode", self._SAMPLE)), self._SAMPLE)
    def test_base64url(self):
        self.assertEqual(encdec.apply("base64url-decode",
                         encdec.apply("base64url-encode", self._SAMPLE)), self._SAMPLE)
    def test_base32(self):
        self.assertEqual(encdec.apply("base32-decode",
                         encdec.apply("base32-encode", self._SAMPLE)), self._SAMPLE)
    def test_base85(self):
        self.assertEqual(encdec.apply("base85-decode",
                         encdec.apply("base85-encode", self._SAMPLE)), self._SAMPLE)
    def test_hex(self):
        self.assertEqual(encdec.apply("hex-decode",
                         encdec.apply("hex-encode", self._SAMPLE)), self._SAMPLE)
    def test_url(self):
        self.assertEqual(encdec.apply("url-decode",
                         encdec.apply("url-encode", self._SAMPLE)), self._SAMPLE)
    def test_html(self):
        s = "<script>alert('x&y')</script>"
        self.assertEqual(encdec.apply("html-decode",
                         encdec.apply("html-encode", s)), s)
    def test_gzip(self):
        self.assertEqual(encdec.apply("gzip-decode-b64",
                         encdec.apply("gzip-encode-b64", self._SAMPLE)), self._SAMPLE)
    def test_deflate(self):
        self.assertEqual(encdec.apply("deflate-decode-b64",
                         encdec.apply("deflate-encode-b64", self._SAMPLE)), self._SAMPLE)
    def test_rot13(self):
        s = "The Quick Brown Fox"
        self.assertEqual(encdec.apply("rot13", encdec.apply("rot13", s)), s)
    def test_reverse(self):
        self.assertEqual(encdec.apply("reverse", encdec.apply("reverse", self._SAMPLE)),
                         self._SAMPLE)
    def test_case_flip(self):
        s = "Hello WORLD"
        self.assertEqual(encdec.apply("case-flip", encdec.apply("case-flip", s)), s)


class FixedOutputTest(unittest.TestCase):
    def test_md5_known(self):
        self.assertEqual(encdec.apply("md5", "hello"),
                         "5d41402abc4b2a76b9719d911017c592")

    def test_sha256_known(self):
        self.assertEqual(encdec.apply("sha256", "hello"),
                         "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")

    def test_nt_hash_known(self):
        # NT hash of "password" is well-known:
        self.assertEqual(encdec.apply("nt-hash", "password"),
                         "8846f7eaee8fb117ad06bdd830b7586c")

    def test_hmac_sha256_known(self):
        # RFC 4231 test vector 1: key of 20 bytes 0x0b, data "Hi There"
        # https://datatracker.ietf.org/doc/html/rfc4231#section-4.2
        # Use a simpler vector: HMAC-SHA-256("key","The quick brown fox jumps over the lazy dog")
        self.assertEqual(encdec.apply("hmac-sha256",
                                       "The quick brown fox jumps over the lazy dog",
                                       key="key"),
                         "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")

    def test_base64_known(self):
        self.assertEqual(encdec.apply("base64-encode", "hello"), "aGVsbG8=")
        self.assertEqual(encdec.apply("base64-decode", "aGVsbG8="), "hello")
        # Lenient on padding:
        self.assertEqual(encdec.apply("base64-decode", "aGVsbG8"), "hello")

    def test_jwt_decode(self):
        # Canonical JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
        token = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                 "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
                 ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        out = encdec.apply("jwt-decode", token)
        self.assertIn('"alg": "HS256"', out)
        self.assertIn('"sub": "1234567890"', out)
        self.assertIn('"name": "John Doe"', out)
        self.assertIn("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", out)


class ErrorHandlingTest(unittest.TestCase):
    def test_bad_base64_raises_encdecerror(self):
        with self.assertRaises(encdec.EncDecError):
            encdec.apply("base64-decode", "not!valid!base64!!!\x00")

    def test_bad_hex_raises(self):
        with self.assertRaises(encdec.EncDecError):
            encdec.apply("hex-decode", "not hex zz")

    def test_bad_jwt_raises(self):
        with self.assertRaises(encdec.EncDecError):
            encdec.apply("jwt-decode", "onlyonepart")

    def test_unknown_op_raises(self):
        with self.assertRaises(encdec.EncDecError):
            encdec.apply("no-such-op", "x")

    def test_keyed_op_missing_key_raises(self):
        with self.assertRaises(encdec.EncDecError):
            encdec.apply("hmac-sha256", "data")   # no key


class XorTest(unittest.TestCase):
    def test_xor_roundtrip(self):
        secret = "hello world"
        key = "deadbeef"
        enc = encdec.apply("xor-hex-key-encode", secret, key=key)
        dec = encdec.apply("xor-hex-key-decode", enc, key=key)
        self.assertEqual(dec, secret)


class ChainTest(unittest.TestCase):
    def test_url_decode_then_json_pretty(self):
        cookie_val = "%7B%22user%22%3A%22admin%22%2C%22role%22%3A%22root%22%7D"
        out = encdec.chain(["url-decode", "json-pretty"], cookie_val)
        self.assertIn('"user"', out)
        self.assertIn('"admin"', out)
        # json-pretty sorts keys, so role comes before user
        self.assertLess(out.index('"role"'), out.index('"user"'))

    def test_chain_with_keyed_op(self):
        secret = "recce loves bytes"
        key = "cafebabe"
        # Encode then round-trip via chain
        enc = encdec.apply("xor-hex-key-encode", secret, key=key)
        out = encdec.chain([("xor-hex-key-decode", key)], enc)
        self.assertEqual(out, secret)


class ListingTest(unittest.TestCase):
    def test_list_ops_has_expected_entries(self):
        ops = {o["name"] for o in encdec.list_ops()}
        for expected in ("base64-encode", "base64-decode", "url-encode",
                         "url-decode", "sha256", "nt-hash", "hmac-sha256",
                         "jwt-decode", "gzip-encode-b64"):
            self.assertIn(expected, ops)

    def test_keyed_ops_flagged(self):
        by_name = {o["name"]: o for o in encdec.list_ops()}
        self.assertTrue(by_name["hmac-sha256"]["requires_key"])
        self.assertFalse(by_name["sha256"]["requires_key"])


if __name__ == "__main__":
    unittest.main()
