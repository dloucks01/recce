"""Native (stdlib) Kerberoasting - the RC4-HMAC crypto and the message encoding.

The crypto is validated against impacket's implementation as an oracle (impacket's
crypto is correct; its Samba failure was a protocol choice, not a miscompute) - these
tests skip cleanly when impacket isn't importable. The DER round-trip tests are pure
stdlib. The live end-to-end roast lives in tests/test_credentialed_ad_integration.py,
gated on a real DC.
"""
import unittest

from recce.ad import kerberos as K
from recce.ad.ntlm import nt_hash

try:
    from impacket.krb5.crypto import _HMACMD5, _RC4, Enctype, Key
    _HAVE_IMPACKET = True
except Exception:
    _HAVE_IMPACKET = False


class KerberosCryptoTest(unittest.TestCase):
    def test_client_key_is_the_nt_hash(self):
        # RC4 (etype 23) string-to-key is just the NT hash.
        self.assertEqual(K.client_key(password="password").hex(),
                         "8846f7eaee8fb117ad06bdd830b7586c")
        # pass-the-hash form yields the same key.
        self.assertEqual(K.client_key(nthash="8846f7eaee8fb117ad06bdd830b7586c"),
                         K.client_key(password="password"))

    def test_rc4_hmac_roundtrip(self):
        key = nt_hash("Recce!Passw0rd")
        for usage in (K._U_AS_REQ_PA_ENC_TS, K._U_AS_REP_ENCPART, K._U_TGS_REQ_AUTH):
            ct = K.rc4_encrypt(key, usage, b"the-quick-brown-fox-jumps")
            self.assertEqual(K.rc4_decrypt(key, usage, ct), b"the-quick-brown-fox-jumps")

    def test_rc4_decrypt_rejects_tampering(self):
        key = nt_hash("x")
        ct = bytearray(K.rc4_encrypt(key, 3, b"secret"))
        ct[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            K.rc4_decrypt(key, 3, bytes(ct))

    @unittest.skipUnless(_HAVE_IMPACKET, "impacket (crypto oracle) not installed")
    def test_rc4_hmac_matches_impacket(self):
        key = nt_hash("password")
        oracle = Key(Enctype.RC4, key)
        for usage in (1, 3, 7, 8):
            conf = bytes([usage]) * 8
            self.assertEqual(K.rc4_encrypt(key, usage, b"payload", conf),
                             _RC4.encrypt(oracle, usage, b"payload", conf))

    @unittest.skipUnless(_HAVE_IMPACKET, "impacket (crypto oracle) not installed")
    def test_kerb_checksum_matches_impacket(self):
        key = nt_hash("password")
        oracle = Key(Enctype.RC4, key)
        for usage in (K._U_TGS_REQ_AUTH_CKSUM, K._U_TGS_REQ_AUTH):
            self.assertEqual(K.krb_checksum_hmacmd5(key, usage, b"req-body-bytes"),
                             _HMACMD5.checksum(oracle, usage, b"req-body-bytes"))


class KerberosMessageTest(unittest.TestCase):
    def test_as_req_preauth_is_well_formed(self):
        areq = K._build_as_req_preauth("svc_sql", "RECCE.LOCAL", nt_hash("pw"))
        self.assertEqual(areq[0], 0x6A)                        # [APPLICATION 10] AS-REQ
        _t, body, _ = K._read_tlv(areq, 0)
        _t2, seq, _ = K._read_tlv(body, 0)
        self.assertIsNotNone(K._find(seq, 0xA0 | 3))          # padata present
        self.assertIsNotNone(K._find(seq, 0xA0 | 4))          # req-body present

    def test_tgs_req_carries_the_tgt_and_a_hmacmd5_checksum(self):
        key = nt_hash("pw")
        sesskey = bytes(range(16))
        tkt = K._tlv(0x61, K._seq(
            K._ctx(0, K._int(5)), K._ctx(1, K._gstr("RECCE.LOCAL")),
            K._ctx(2, K._principal(2, ["krbtgt", "RECCE.LOCAL"])),
            K._ctx(3, K._encrypted_data(23, b"\x00" * 32))))
        tgs = K._build_tgs_req("RECCE.LOCAL", "svc_sql",
                               "MSSQLSvc/db.recce.local:1433", tkt, sesskey)
        self.assertEqual(tgs[0], 0x6C)                        # [APPLICATION 12] TGS-REQ
        # the embedded ticket bytes are carried verbatim inside the AP-REQ
        self.assertIn(tkt, tgs)

    def test_tgs_hash_format_is_hashcat_13100(self):
        cipher = bytes(range(48))
        h = K.tgs_hash("svc_sql", "RECCE.LOCAL", "MSSQLSvc/db:1433", 23, cipher)
        self.assertTrue(h.startswith("$krb5tgs$23$*svc_sql$RECCE.LOCAL$MSSQLSvc/db:1433*$"))
        self.assertEqual(h.rsplit("*$", 1)[1], cipher[:16].hex() + "$" + cipher[16:].hex())

    def test_kdc_error_code_extraction(self):
        # A minimal KRB-ERROR ([APPLICATION 30]) carrying error-code 7.
        err = K._tlv(0x7E, K._seq(K._ctx(6, K._int(7))))
        self.assertEqual(K._kdc_error_code(err), 7)
        self.assertIsNone(K._kdc_error_code(K._build_as_req_preauth("u", "R", nt_hash("p"))))


if __name__ == "__main__":
    unittest.main()
