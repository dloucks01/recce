"""core.known_hostkeys: cross-service SSH-style hostkey fingerprint reader.

Fixtures below build SSH host-key blobs directly on the wire — RFC 4253
§6.6 string encoding (uint32 length + bytes) — and hash them with stdlib
`hashlib.sha256` to get a fingerprint identical to what `ssh-keygen -l -E
sha256` prints. Nothing here calls a recce encoder; only the reader.
"""
from __future__ import annotations

import base64
import hashlib
import struct

from recce.core.known_hostkeys import (hostkeys_for, known_hostkeys,
                                       record_hostkey)
from recce.core.models import Host, Port


# --- wire-derived fingerprint helpers --------------------------------------

def _ssh_string(b: bytes) -> bytes:
    """RFC 4253 §6.6: string = uint32 length + raw bytes."""
    return struct.pack(">I", len(b)) + b


def _ed25519_ks(pub32: bytes) -> bytes:
    """Wire-format K_S for an ssh-ed25519 host key (RFC 8709 §4)."""
    assert len(pub32) == 32
    return _ssh_string(b"ssh-ed25519") + _ssh_string(pub32)


def _rsa_ks(e: bytes, n: bytes) -> bytes:
    """Wire-format K_S for an ssh-rsa host key (RFC 4253 §6.6)."""
    return _ssh_string(b"ssh-rsa") + _ssh_string(e) + _ssh_string(n)


def _fp_of(blob: bytes) -> str:
    """The exact string `ssh-keygen -l -E sha256` prints."""
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


# Two distinct ed25519 hostkeys built from deterministic seeds so the
# fingerprints below are reproducible without a network.
_KEY_A = _ed25519_ks(hashlib.sha256(b"host-a-ed25519-seed").digest())
_KEY_B = _ed25519_ks(hashlib.sha256(b"host-b-ed25519-seed").digest())
_FP_A = _fp_of(_KEY_A)
_FP_B = _fp_of(_KEY_B)


# --- record_hostkey ---------------------------------------------------------

def test_record_hostkey_attaches_to_host_and_hostkeys_for_reads_back():
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    got = hostkeys_for(h)
    assert len(got) == 1
    assert got[0]["fp"] == _FP_A
    assert got[0]["ip"] == "10.0.0.10"
    assert got[0]["port"] == 22
    # key_type is normalised lower-case (RFC 4250 §4.11 algorithm names)
    assert got[0]["key_type"] == "ssh-ed25519"
    assert got[0]["source"] == "ssh"


def test_record_hostkey_is_idempotent_on_same_fingerprint_and_port():
    """Re-running the SSH probe on the same endpoint must not duplicate."""
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    assert len(hostkeys_for(h)) == 1


def test_record_hostkey_records_second_endpoint_on_different_port():
    """22 and 2222 may both be an sshd on the same host — record both."""
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(h, "10.0.0.10", 2222, _FP_A, "ssh-ed25519", "ssh")
    ports = sorted(e["port"] for e in hostkeys_for(h))
    assert ports == [22, 2222]


def test_record_hostkey_silently_drops_empty_fingerprint():
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, "", "ssh-ed25519", "ssh")
    record_hostkey(h, "10.0.0.10", 22, "   ", "ssh-ed25519", "ssh")
    assert hostkeys_for(h) == []


def test_record_hostkey_preserves_fingerprint_case_verbatim():
    """SHA256 fingerprints are base64: `Abc` and `abc` are distinct
    bytes. The reader must NOT lower-case them."""
    fp_mixed = "SHA256:AbCdEf0123ghIJKlmNOPqrstUVwxYZ"
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, fp_mixed, "ssh-ed25519", "ssh")
    assert hostkeys_for(h)[0]["fp"] == fp_mixed


# --- known_hostkeys engagement-wide correlation ----------------------------

def test_known_hostkeys_unions_across_hosts_by_fingerprint():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_hostkey(a, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(b, "10.0.0.20", 22, _FP_B, "ssh-ed25519", "ssh")
    got = known_hostkeys([a, b])
    assert set(got["by_fingerprint"][_FP_A]) == {"10.0.0.10:22"}
    assert set(got["by_fingerprint"][_FP_B]) == {"10.0.0.20:22"}
    # Not reused: each fp on exactly one IP.
    assert got["reused"] == []


def test_known_hostkeys_reused_flags_same_fingerprint_on_multiple_ips():
    """Two hosts with the same SSH hostkey = golden-image clone / VM
    template stamp. This is exactly what the reader exists to surface."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_hostkey(a, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(b, "10.0.0.20", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(c, "10.0.0.30", 22, _FP_B, "ssh-ed25519", "ssh")
    got = known_hostkeys([a, b, c])
    reused = got["reused"]
    assert len(reused) == 1
    assert reused[0]["fingerprint"] == _FP_A
    assert set(reused[0]["ips"]) == {"10.0.0.10", "10.0.0.20"}
    assert set(reused[0]["endpoints"]) == {"10.0.0.10:22", "10.0.0.20:22"}
    assert reused[0]["key_type"] == "ssh-ed25519"


def test_known_hostkeys_same_key_on_two_ports_of_one_host_is_not_reuse():
    """22 and 2222 on the same box share the key by construction — not
    a reuse finding. Reuse requires >=2 DISTINCT IPs."""
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(h, "10.0.0.10", 2222, _FP_A, "ssh-ed25519", "ssh")
    got = known_hostkeys([h])
    assert got["reused"] == []
    assert set(got["by_fingerprint"][_FP_A]) == {"10.0.0.10:22",
                                                  "10.0.0.10:2222"}


def test_known_hostkeys_by_ip_lists_all_algorithms_seen_on_a_host():
    """A host offering both ssh-rsa AND ssh-ed25519 keys yields two
    entries in by_ip — a dual-hostkey server is a normal shape."""
    e = struct.pack(">I", 65537)[1:]  # 0x010001, RSA e
    n = hashlib.sha256(b"rsa-modulus-seed").digest() * 16  # ~4096 bits
    rsa_blob = _rsa_ks(e, n)
    fp_rsa = _fp_of(rsa_blob)
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    record_hostkey(h, "10.0.0.10", 22, fp_rsa, "ssh-rsa", "ssh")
    got = known_hostkeys([h])
    pairs = got["by_ip"]["10.0.0.10"]
    assert (_FP_A, "ssh-ed25519") in pairs
    assert (fp_rsa, "ssh-rsa") in pairs


def test_known_hostkeys_ignores_hosts_with_no_recorded_keys():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_hostkey(a, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    got = known_hostkeys([a, b])
    assert "10.0.0.20" not in got["by_ip"]
    assert got["by_fingerprint"] == {_FP_A: ["10.0.0.10:22"]}


def test_hostkeys_for_returns_copies_so_consumer_cannot_corrupt_store():
    h = Host(ip="10.0.0.10")
    record_hostkey(h, "10.0.0.10", 22, _FP_A, "ssh-ed25519", "ssh")
    got = hostkeys_for(h)
    got[0]["fp"] = "SHA256:tampered"
    # Original store unaffected
    assert hostkeys_for(h)[0]["fp"] == _FP_A


# --- producer wire: ssh.analyze() -> record_hostkey ------------------------

def test_ssh_analyze_wires_hostkey_capture_into_known_hostkeys(monkeypatch):
    """Integration: ssh.analyze() feeds the reader from its per-probe
    hostkey_capture, and known_hostkeys() then sees it.

    We stub the network probe so the test stays offline: return a
    hostkey_capture matching what a real DH group14 KEX would yield.
    """
    from recce.services import ssh, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=22, protocol="tcp", state="open", service="ssh")]

    fake_pr = {
        "reachable": True, "banner": "SSH-2.0-fake", "ident": "SSH-2.0-fake",
        "softversion": "fake", "comment": "", "protocol_version": "2.0",
        "product": "openssh", "version": "9.6",
        "kex": ["curve25519-sha256"], "hostkey": ["ssh-ed25519"],
        "cipher_cs": ["aes128-ctr"], "cipher_sc": ["aes128-ctr"],
        "mac_cs": ["hmac-sha2-256"], "mac_sc": ["hmac-sha2-256"],
        "comp_cs": ["none"], "comp_sc": ["none"],
        "hostkey_capture": {"key_type": "ssh-ed25519",
                            "fp_sha256": _FP_A,
                            "fp_md5": "MD5:aa:bb"},
    }

    # svcprobe.iter_probe yields (target, probe_result) tuples.
    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    # auth_methods shells out; short-circuit it.
    monkeypatch.setattr(ssh, "auth_methods", lambda ip, port, user="root":
                        {"reachable": False, "methods": []})

    ssh.analyze([h], active=True)

    # The host now carries the fingerprint …
    keys = hostkeys_for(h)
    assert [k["fp"] for k in keys] == [_FP_A]
    assert keys[0]["source"] == "ssh"
    # … and the engagement-wide reader sees it.
    got = known_hostkeys([h])
    assert got["by_fingerprint"][_FP_A] == ["10.0.0.10:22"]
