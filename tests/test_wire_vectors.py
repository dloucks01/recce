"""Golden wire-vector tests: exact parsed output for real protocol messages.

The fuzz harness (test_fuzz_decoders.py) proves the decoders don't *crash* on
hostile bytes. These tests prove they *read the right fields* off a well-formed
message - the other half of "high fidelity". Each asserts the precise structure a
real server's bytes decode to, so a decoder that starts mis-reading a field (wrong
offset, endianness, sign) is caught even though it never raises.

Input comes from tests/wire_vectors.py, the same fixtures the fuzzer mutates, so a
golden failure and a fuzz failure refer to byte-for-byte the same "real" message.
"""
import struct
import unittest

from recce import snmp
from recce import mongodb
from recce import ldap
from recce import ntlm
from recce import smb
from tests import wire_vectors as W


class SnmpVectorTest(unittest.TestCase):

    def test_get_response_exact(self):
        err, varbinds = snmp.parse_response(W.snmp_get_response())
        self.assertEqual(err, 0)
        self.assertEqual(varbinds,
                         [("1.3.6.1.2.1.1.1.0", "Linux recce 6.1.0")])

    def test_request_id_echo(self):
        self.assertEqual(snmp._response_request_id(W.snmp_get_response()), 42)


class BsonVectorTest(unittest.TestCase):

    def test_hello_reply_exact(self):
        doc, idx = mongodb.bson_parse(W.mongodb_hello_doc(), 0)
        self.assertEqual(idx, len(W.mongodb_hello_doc()))
        self.assertEqual(doc, {
            "isWritablePrimary": True,
            "maxWireVersion": 17,
            "setName": "rs0",
            "ok": 1.0,
        })

    def test_listdbs_nested_array_exact(self):
        doc, _ = mongodb.bson_parse(W.mongodb_listdbs_doc(), 0)
        self.assertEqual([d["name"] for d in doc["databases"]], ["admin", "config"])
        self.assertEqual(doc["databases"][0]["sizeOnDisk"], 4096.0)
        self.assertEqual(doc["totalSize"], 12288.0)
        self.assertEqual(doc["ok"], 1.0)

    def test_int64_and_bool_types(self):
        blob = mongodb.bson_doc(
            b"\x12" + mongodb._cstr("big") + struct.pack("<q", 2 ** 40),
            b"\x08" + mongodb._cstr("flag") + b"\x00")
        doc, _ = mongodb.bson_parse(blob, 0)
        self.assertEqual(doc["big"], 2 ** 40)
        self.assertIs(doc["flag"], False)


class LdapVectorTest(unittest.TestCase):

    def test_search_entry_exact(self):
        obj, attrs = ldap.parse_search_entry(W.ldap_search_entry())
        self.assertEqual(obj, "CN=DC01,OU=Domain Controllers,DC=corp,DC=local")
        self.assertEqual(attrs, {"dnsHostName": ["dc01.corp.local", "dc01"]})

    def test_op_tag_identifies_search_entry(self):
        # protocolOp application tag 0x64 == searchResEntry.
        self.assertEqual(ldap._op_tag(W.ldap_search_entry()), 0x64)


class NtlmVectorTest(unittest.TestCase):

    def test_type2_challenge_and_target_info(self):
        parsed = ntlm.parse_type2(W.ntlm_type2())
        self.assertEqual(parsed["challenge"], bytes.fromhex("0123456789abcdef"))
        self.assertEqual(parsed["target_info"], W._NTLM_TARGET_INFO)
        self.assertEqual(parsed["flags"], ntlm._SEAL_FLAGS)

    def test_type2_unwraps_spnego_prefix(self):
        # A GSS/SPNEGO wrapper prepends bytes before the NTLMSSP signature; the
        # parser must locate the signature and still decode correctly.
        wrapped = b"\x60\x28\x06\x06\x2b\x06\x01\x05\x05\x02" + W.ntlm_type2()
        parsed = ntlm.parse_type2(wrapped)
        self.assertEqual(parsed["challenge"], bytes.fromhex("0123456789abcdef"))
        self.assertEqual(parsed["target_info"], W._NTLM_TARGET_INFO)


class SmbVectorTest(unittest.TestCase):

    def test_smb2_negotiate_exact(self):
        p = smb.parse_smb2_negotiate(W.smb2_negotiate_response())
        self.assertEqual(p["dialect"], 0x0311)
        self.assertEqual(p["dialect_name"], "SMB 3.1.1")
        self.assertTrue(p["signing_enabled"])
        self.assertFalse(p["signing_required"])

    def test_smb1_negotiate_exact(self):
        p = smb.parse_smb1_negotiate(W.smb1_negotiate_response())
        self.assertTrue(p["smbv1"])
        self.assertEqual(p["dialect_index"], 5)


if __name__ == "__main__":
    unittest.main()
