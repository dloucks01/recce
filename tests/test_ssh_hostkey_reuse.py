"""ssh.findings() consumer for cross-host SSH host key reuse.

Fixtures build wire-format K_S blobs directly (RFC 4253 §6.6: uint32
length + bytes) and hash them with stdlib `hashlib.sha256` to produce
fingerprints byte-identical to `ssh-keygen -l -E sha256`. No recce
encoder is called from the fixtures - only the reader / consumer under
test.

The 'network' here is the shared in-memory host store the SSH probe
already writes into via `record_hostkey`. Nothing socket-facing runs;
these tests exercise only the correlation consumer inside
`ssh.findings()`.
"""
from __future__ import annotations

import base64
import hashlib
import struct

from recce.core.known_hostkeys import record_hostkey
from recce.core.models import Host, Port
from recce.services import ssh


# --- wire-derived fingerprint helpers --------------------------------------

def _ssh_string(b: bytes) -> bytes:
    """RFC 4253 §6.6: string = uint32 length + raw bytes."""
    return struct.pack(">I", len(b)) + b


def _ed25519_ks(pub32: bytes) -> bytes:
    """Wire-format K_S for an ssh-ed25519 host key (RFC 8709 §4)."""
    assert len(pub32) == 32
    return _ssh_string(b"ssh-ed25519") + _ssh_string(pub32)


def _fp_of(blob: bytes) -> str:
    """The exact string `ssh-keygen -l -E sha256` prints."""
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


# Two deterministic host keys - one shared across hosts (the reuse
# signal), one unique per host (baseline for the negative case).
_KEY_SHARED = _ed25519_ks(hashlib.sha256(b"golden-image-ed25519").digest())
_KEY_UNIQUE_A = _ed25519_ks(hashlib.sha256(b"host-a-unique-ed25519").digest())
_KEY_UNIQUE_B = _ed25519_ks(hashlib.sha256(b"host-b-unique-ed25519").digest())

_FP_SHARED = _fp_of(_KEY_SHARED)
_FP_UNIQUE_A = _fp_of(_KEY_UNIQUE_A)
_FP_UNIQUE_B = _fp_of(_KEY_UNIQUE_B)


# --- fixture builders -------------------------------------------------------

def _mkhost(ip: str, ports=(22,)) -> Host:
    h = Host(ip=ip)
    for p in ports:
        h.ports.append(Port(portid=p, state="open", service="ssh",
                            product="OpenSSH", version="9.6p1"))
    return h


def _reachable_probe(fp: str, key_type: str = "ssh-ed25519") -> dict:
    """Minimum probe dict shape ssh.findings() reads: a reachable server
    that returned KEXINIT + a captured hostkey. Empty algo lists keep the
    posture branches quiet so only the reuse consumer emits."""
    return {"reachable": True, "banner": "SSH-2.0-OpenSSH_9.6p1",
            "ident": "SSH-2.0-OpenSSH_9.6p1",
            "softversion": "OpenSSH_9.6p1", "comment": "",
            "protocol_version": "2.0", "product": "", "version": "",
            "kex": [], "hostkey": [],
            "cipher_cs": [], "cipher_sc": [],
            "mac_cs": [], "mac_sc": [],
            "comp_cs": [], "comp_sc": [],
            "hostkey_capture": {"key_type": key_type,
                                "fp_md5": "MD5:00:11",
                                "fp_sha256": fp}}


# --- (a) vulnerable target: one fingerprint on >=2 IPs -> finding ----------

def test_shared_fingerprint_across_two_hosts_emits_reuse_finding():
    a = _mkhost("10.0.0.10")
    b = _mkhost("10.0.0.11")
    record_hostkey(a, "10.0.0.10", 22, _FP_SHARED, "ssh-ed25519", "ssh")
    record_hostkey(b, "10.0.0.11", 22, _FP_SHARED, "ssh-ed25519", "ssh")
    probes = {("10.0.0.10", 22): _reachable_probe(_FP_SHARED),
              ("10.0.0.11", 22): _reachable_probe(_FP_SHARED)}

    fs = ssh.findings([a, b], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]

    # One finding per endpoint sharing the fp, so both hosts surface it.
    assert len(reuse) == 2
    targets = sorted(f["target"] for f in reuse)
    assert targets == ["10.0.0.10:22", "10.0.0.11:22"]
    for f in reuse:
        assert f["severity"] == "info"
        assert f["depth_tier"] == "t4"
        assert _FP_SHARED in f["title"]
        assert "10.0.0.10" in f["detail"] and "10.0.0.11" in f["detail"]
        assert f["narrative"]                              # populated
        assert "CWE-262" in f["cwes"]                      # weak/shared secret


def test_shared_fingerprint_across_three_hosts_lists_all_peers():
    a = _mkhost("10.0.0.10")
    b = _mkhost("10.0.0.11")
    c = _mkhost("10.0.0.12")
    for h in (a, b, c):
        record_hostkey(h, h.ip, 22, _FP_SHARED, "ssh-ed25519", "ssh")
    probes = {(h.ip, 22): _reachable_probe(_FP_SHARED) for h in (a, b, c)}

    fs = ssh.findings([a, b, c], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]

    assert len(reuse) == 3
    for f in reuse:
        assert "3 IPs" in f["title"]
        for ip in ("10.0.0.10", "10.0.0.11", "10.0.0.12"):
            assert ip in f["detail"]


def test_shared_fingerprint_across_alt_port_still_counts_as_reuse():
    # Same fp on distinct IPs but different ports still trips the
    # correlator - reuse is over IPs, not (ip,port) pairs.
    a = _mkhost("10.0.0.10", ports=(22,))
    b = _mkhost("10.0.0.11", ports=(2222,))
    record_hostkey(a, "10.0.0.10", 22, _FP_SHARED, "ssh-ed25519", "ssh")
    record_hostkey(b, "10.0.0.11", 2222, _FP_SHARED, "ssh-ed25519", "ssh")
    probes = {("10.0.0.10", 22): _reachable_probe(_FP_SHARED),
              ("10.0.0.11", 2222): _reachable_probe(_FP_SHARED)}

    fs = ssh.findings([a, b], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]
    assert {f["target"] for f in reuse} == {"10.0.0.10:22", "10.0.0.11:2222"}


# --- (b) patched / absent: unique fingerprints per host -> no finding ------

def test_unique_fingerprints_per_host_emits_no_reuse_finding():
    a = _mkhost("10.0.0.10")
    b = _mkhost("10.0.0.11")
    record_hostkey(a, "10.0.0.10", 22, _FP_UNIQUE_A, "ssh-ed25519", "ssh")
    record_hostkey(b, "10.0.0.11", 22, _FP_UNIQUE_B, "ssh-ed25519", "ssh")
    probes = {("10.0.0.10", 22): _reachable_probe(_FP_UNIQUE_A),
              ("10.0.0.11", 22): _reachable_probe(_FP_UNIQUE_B)}

    fs = ssh.findings([a, b], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]
    assert reuse == []


def test_same_fp_on_two_ports_of_one_host_is_not_reuse():
    # A single host presenting the same key on 22 and 2222 is expected
    # (one sshd, two listens) - NOT a reuse finding, per known_hostkeys
    # which groups by DISTINCT IPs.
    a = _mkhost("10.0.0.10", ports=(22, 2222))
    record_hostkey(a, "10.0.0.10", 22, _FP_SHARED, "ssh-ed25519", "ssh")
    record_hostkey(a, "10.0.0.10", 2222, _FP_SHARED, "ssh-ed25519", "ssh")
    probes = {("10.0.0.10", 22): _reachable_probe(_FP_SHARED),
              ("10.0.0.10", 2222): _reachable_probe(_FP_SHARED)}

    fs = ssh.findings([a], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]
    assert reuse == []


def test_no_fingerprints_recorded_emits_no_reuse_finding():
    # Probe reachable but hostkey capture never landed (older probe, or
    # non-DH-group14 negotiation). Nothing to correlate.
    a = _mkhost("10.0.0.10")
    b = _mkhost("10.0.0.11")
    probes = {("10.0.0.10", 22): _reachable_probe(_FP_UNIQUE_A),
              ("10.0.0.11", 22): _reachable_probe(_FP_UNIQUE_B)}
    # Note: no record_hostkey() calls - fingerprint store is empty.
    fs = ssh.findings([a, b], probes)
    reuse = [f for f in fs if f.get("kind") == "ssh_hostkey_reused"]
    assert reuse == []
