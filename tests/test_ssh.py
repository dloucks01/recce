"""Tests for recce.services.ssh - the SSH KEXINIT + hostkey probe.

Fixtures are hand-assembled to the RFC 4253 §6/§7.1 wire layout with
algorithm strings taken from real OpenSSH captures. NEVER built by
calling ssh.py's own encoders (that would be circular).

The fake server binds a loopback TCP socket and replays a pre-canned
identification line + SSH_MSG_KEXINIT packet after the client sends its
own KEXINIT. probe() reads them just like it would a real sshd.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import ssh


# --- wire fixtures -------------------------------------------------------------

# Server identification string (RFC 4253 §4.2). CRLF-terminated. Real
# OpenSSH 8.9p1 on Ubuntu 22.04 sends exactly this shape.
_IDENT_OPENSSH89_UBUNTU = (
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n"
)
_IDENT_DROPBEAR = b"SSH-2.0-dropbear_2020.81\r\n"
_IDENT_LEGACY_199 = b"SSH-1.99-OpenSSH_3.6.1p2\r\n"
_IDENT_REGRESSHION = b"SSH-2.0-OpenSSH_9.6p1 Debian-3ubuntu13.5\r\n"


def _uint32(n: int) -> bytes:
    return struct.pack(">I", n)


def _string(b: bytes) -> bytes:
    return _uint32(len(b)) + b


def _namelist(csv: str) -> bytes:
    return _string(csv.encode("ascii"))


def _kexinit_payload(kex: str, hostkey: str, cipher: str, mac: str,
                     comp: str = "none") -> bytes:
    """Hand-assembled SSH_MSG_KEXINIT payload matching RFC 4253 §7.1 exactly:
      byte      SSH_MSG_KEXINIT (0x14)
      byte[16]  cookie
      name-list kex_algorithms
      name-list server_host_key_algorithms
      name-list encryption_algorithms_c2s
      name-list encryption_algorithms_s2c
      name-list mac_algorithms_c2s
      name-list mac_algorithms_s2c
      name-list compression_algorithms_c2s
      name-list compression_algorithms_s2c
      name-list languages_c2s
      name-list languages_s2c
      boolean   first_kex_packet_follows
      uint32    0
    """
    return (
        bytes([0x14])
        + bytes(16)                                # cookie (zeroed - fine for test)
        + _namelist(kex)
        + _namelist(hostkey)
        + _namelist(cipher) + _namelist(cipher)
        + _namelist(mac) + _namelist(mac)
        + _namelist(comp) + _namelist(comp)
        + _namelist("") + _namelist("")
        + bytes([0])
        + _uint32(0)
    )


def _wrap_binary(payload: bytes) -> bytes:
    """RFC 4253 §6 packet framing, no MAC (pre-NEWKEYS). Hand-assembled to
    match the spec (packet_length + padding_length + payload + padding)."""
    n = 5 + len(payload)
    pad = 8 - (n % 8)
    if pad < 4:
        pad += 8
    pkt_len = 1 + len(payload) + pad
    return _uint32(pkt_len) + bytes([pad]) + payload + b"\x00" * pad


# --- fake ssh server -----------------------------------------------------------

class _FakeSSHServer:
    """Sends `ident` + optionally a KEXINIT packet after the client speaks."""

    def __init__(self, ident: bytes, kexinit_payload: bytes | None = None,
                 send_kexinit_immediately: bool = True):
        self._ident = ident
        self._kexinit = _wrap_binary(kexinit_payload) if kexinit_payload else None
        self._eager = send_kexinit_immediately
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self._srv.settimeout(4.0)
        self.host, self.port = self._srv.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except (socket.timeout, OSError):
            return
        try:
            conn.settimeout(4.0)
            # Send ident (+ optional KEXINIT eagerly, matching real OpenSSH).
            conn.sendall(self._ident)
            if self._eager and self._kexinit:
                conn.sendall(self._kexinit)
            # Read whatever the client sends (its ident + its KEXINIT); we
            # do not need to parse it for the KEXINIT posture tests.
            try:
                _ = conn.recv(8192)
            except (socket.timeout, OSError):
                pass
            if not self._eager and self._kexinit:
                conn.sendall(self._kexinit)
            # Keep the socket open briefly then close.
            try:
                conn.settimeout(0.3)
                _ = conn.recv(4096)
            except (socket.timeout, OSError):
                pass
        finally:
            try: conn.close()
            except OSError: pass

    def close(self):
        try: self._srv.close()
        except OSError: pass


# --- tests --------------------------------------------------------------------

class BannerParseTest(unittest.TestCase):
    def test_openssh_ubuntu_banner_extracts_softversion_and_distro_tag(self):
        # Serve only the ident + a hardened modern KEXINIT (no fingerprint
        # capture since we won't get a KEXDH_REPLY).
        kexinit = _kexinit_payload(
            "curve25519-sha256,kex-strict-s-v00@openssh.com",
            "rsa-sha2-256,ssh-ed25519",
            "aes128-ctr,aes256-gcm@openssh.com",
            "hmac-sha2-256")
        srv = _FakeSSHServer(_IDENT_OPENSSH89_UBUNTU, kexinit)
        try:
            pr = ssh.probe(srv.host, srv.port, timeout=2, capture_hostkey=False)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["protocol_version"], "2.0")
        self.assertEqual(pr["softversion"], "OpenSSH_8.9p1")
        self.assertEqual(pr["comment"], "Ubuntu-3ubuntu0.10")
        self.assertEqual(pr["product"], "OpenSSH")
        self.assertTrue(pr["version"].startswith("8.9"))

    def test_dropbear_banner_parsed(self):
        kexinit = _kexinit_payload("curve25519-sha256", "ssh-ed25519",
                                   "aes128-ctr", "hmac-sha2-256")
        srv = _FakeSSHServer(_IDENT_DROPBEAR, kexinit)
        try:
            pr = ssh.probe(srv.host, srv.port, timeout=2, capture_hostkey=False)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["softversion"], "dropbear_2020.81")
        self.assertEqual(pr["product"], "dropbear")

    def test_dead_port_returns_none(self):
        pr = ssh.probe("127.0.0.1", 1, timeout=1)
        self.assertIsNone(pr)


class KexinitParseTest(unittest.TestCase):
    def test_kex_lists_populated(self):
        kex = ("diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
               "curve25519-sha256")
        cipher = "aes128-cbc,3des-cbc,aes128-ctr"
        mac = "hmac-md5,hmac-sha1-96,hmac-sha2-256"
        kexinit = _kexinit_payload(kex, "ssh-rsa,ssh-dss,ssh-ed25519",
                                   cipher, mac)
        srv = _FakeSSHServer(_IDENT_OPENSSH89_UBUNTU, kexinit)
        try:
            pr = ssh.probe(srv.host, srv.port, timeout=2, capture_hostkey=False)
        finally:
            srv.close()
        self.assertIn("diffie-hellman-group1-sha1", pr["kex"])
        self.assertIn("ssh-rsa", pr["hostkey"])
        self.assertIn("ssh-dss", pr["hostkey"])
        self.assertIn("aes128-cbc", pr["cipher_sc"])
        self.assertIn("hmac-md5", pr["mac_sc"])


class KexinitDeferredTest(unittest.TestCase):
    """Server that sends the KEXINIT AFTER receiving the client's ident +
    KEXINIT - the RFC-allowed lazy path."""

    def test_deferred_kexinit_still_parsed(self):
        kexinit = _kexinit_payload("curve25519-sha256", "ssh-ed25519",
                                   "aes128-ctr", "hmac-sha2-256")
        srv = _FakeSSHServer(_IDENT_OPENSSH89_UBUNTU, kexinit,
                             send_kexinit_immediately=False)
        try:
            pr = ssh.probe(srv.host, srv.port, timeout=2, capture_hostkey=False)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertIn("curve25519-sha256", pr["kex"])


# --- posture / findings tests --------------------------------------------------

def _make_probe(ident_softver: str = "OpenSSH_8.9p1",
                comment: str = "Ubuntu-3ubuntu0.10",
                proto: str = "2.0",
                kex: list[str] | None = None,
                hostkey: list[str] | None = None,
                cipher_sc: list[str] | None = None,
                mac_sc: list[str] | None = None,
                hostkey_capture: dict | None = None) -> dict:
    """Synthesize a probe result dict for findings() tests. Only exercises
    the finding-generation path, not the wire parser (which the tests
    above exercise via the fake server + hand-crafted bytes)."""
    return {
        "reachable": True,
        "ident": f"SSH-{proto}-{ident_softver} {comment}".strip(),
        "banner": f"SSH-{proto}-{ident_softver} {comment}".strip(),
        "protocol_version": proto,
        "softversion": ident_softver,
        "comment": comment,
        "product": "OpenSSH" if "OpenSSH" in ident_softver else "",
        "version": "",
        "kex": kex or ["curve25519-sha256"],
        "hostkey": hostkey or ["ssh-ed25519"],
        "cipher_cs": cipher_sc or ["aes128-ctr"],
        "cipher_sc": cipher_sc or ["aes128-ctr"],
        "mac_cs": mac_sc or ["hmac-sha2-256"],
        "mac_sc": mac_sc or ["hmac-sha2-256"],
        "comp_cs": ["none"], "comp_sc": ["none"],
        "hostkey_capture": hostkey_capture,
    }


def _fake_host_with_port(portid: int = 22):
    from recce.core.models import Host, Port
    return Host(ip="10.0.0.5", ports=[Port(portid=portid, service="ssh",
                                           state="open")])


class WeakKexFindingTest(unittest.TestCase):
    def test_group1_sha1_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(kex=["diffie-hellman-group1-sha1", "curve25519-sha256"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        titles = [f["title"] for f in fs]
        self.assertTrue(any("weak key exchange" in t.lower() for t in titles))
        self.assertTrue(any(f["kind"] == "ssh_weak_kex" for f in fs))

    def test_hardened_kex_produces_no_weak_kex_finding(self):
        h = _fake_host_with_port()
        pr = _make_probe(kex=["curve25519-sha256",
                              "diffie-hellman-group16-sha512"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertFalse(any(f["kind"] == "ssh_weak_kex" for f in fs))


class WeakCipherMacFindingTest(unittest.TestCase):
    def test_cbc_and_md5_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(cipher_sc=["aes128-cbc", "3des-cbc", "aes128-ctr"],
                         mac_sc=["hmac-md5", "hmac-sha1-96", "hmac-sha2-256"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("ssh_weak_cipher", kinds)
        self.assertIn("ssh_weak_mac", kinds)


class HostkeyPostureFindingTest(unittest.TestCase):
    def test_ssh_rsa_and_dss_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(hostkey=["ssh-rsa", "ssh-dss", "ssh-ed25519"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        hits = [f for f in fs if f["kind"] == "ssh_hostkey_posture"]
        self.assertTrue(hits)
        self.assertIn("ssh-rsa", hits[0]["title"])


class TerrapinFindingTest(unittest.TestCase):
    def test_chacha20_without_kex_strict_flags_terrapin(self):
        h = _fake_host_with_port()
        pr = _make_probe(
            kex=["curve25519-sha256"],
            cipher_sc=["chacha20-poly1305@openssh.com", "aes128-ctr"],
            mac_sc=["hmac-sha2-256"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertTrue(any(f["kind"] == "ssh_terrapin" for f in fs))

    def test_kex_strict_suppresses_terrapin(self):
        h = _fake_host_with_port()
        pr = _make_probe(
            kex=["curve25519-sha256", "kex-strict-s-v00@openssh.com"],
            cipher_sc=["chacha20-poly1305@openssh.com"],
            mac_sc=["hmac-sha2-256"])
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertFalse(any(f["kind"] == "ssh_terrapin" for f in fs))


class LegacyProtoFindingTest(unittest.TestCase):
    def test_ssh_199_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(proto="1.99", ident_softver="OpenSSH_3.6.1p2",
                         comment="")
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertTrue(any(f["kind"] == "ssh_legacy_proto" for f in fs))


class KnownBadBuildFindingTest(unittest.TestCase):
    def test_regresshion_version_range_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(ident_softver="OpenSSH_9.6p1",
                         comment="Debian-3ubuntu13.5")
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertTrue(any(f["kind"] == "ssh_known_bad_build"
                            and "CVE-2024-6387" in f["title"] for f in fs))

    def test_recent_openssh_not_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(ident_softver="OpenSSH_9.8p1", comment="")
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertFalse(any(f["kind"] == "ssh_known_bad_build" for f in fs))


class BannerLeakFindingTest(unittest.TestCase):
    def test_ubuntu_tag_flagged(self):
        h = _fake_host_with_port()
        pr = _make_probe(comment="Ubuntu-3ubuntu0.10")
        fs = ssh.findings([h], {(h.ip, 22): pr})
        self.assertTrue(any(f["kind"] == "ssh_banner" for f in fs))


class HostkeyCaptureFindingTest(unittest.TestCase):
    def test_fingerprint_captured_becomes_info_finding(self):
        h = _fake_host_with_port()
        pr = _make_probe(hostkey_capture={
            "key_type": "ssh-ed25519",
            "fp_sha256": "SHA256:AAAA1234deadbeefbase64",
            "fp_md5": "MD5:aa:bb:cc:dd",
        })
        fs = ssh.findings([h], {(h.ip, 22): pr})
        hits = [f for f in fs if f["kind"] == "ssh_hostkey_fingerprint"]
        self.assertTrue(hits)
        self.assertIn("SHA256:", hits[0]["detail"])


class AuthMethodsFindingTest(unittest.TestCase):
    def test_password_and_root_findings_from_auth_methods(self):
        h = _fake_host_with_port()
        pr = _make_probe()
        auth = {(h.ip, 22): {"root": {
            "reachable": True, "user": "root",
            "methods": ["publickey", "password"], "stderr": ""}}}
        fs = ssh.findings([h], {(h.ip, 22): pr}, auth)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ssh_auth_methods", kinds)
        self.assertIn("ssh_password_auth", kinds)
        self.assertIn("ssh_root_login", kinds)


class AuthMethodsShellOutTest(unittest.TestCase):
    """auth_methods() shell-outs to `ssh`; monkeypatch subprocess.run so we
    do not actually spawn or hit the network."""

    def test_permission_denied_stderr_parsed(self, ):
        import subprocess

        class FakeCompleted:
            def __init__(self, stderr):
                self.stderr = stderr
                self.stdout = ""
                self.returncode = 255

        def fake_run(*a, **kw):
            return FakeCompleted(
                "root@127.0.0.1: Permission denied "
                "(publickey,password,keyboard-interactive).\n")

        # Monkeypatch subprocess.run + shutil.which used inside auth_methods.
        import shutil
        orig_run = subprocess.run
        orig_which = shutil.which
        subprocess.run = fake_run
        shutil.which = lambda name: "/usr/bin/ssh"
        try:
            r = ssh.auth_methods("127.0.0.1", 22, user="root", timeout=2)
        finally:
            subprocess.run = orig_run
            shutil.which = orig_which
        self.assertTrue(r["reachable"])
        self.assertIn("publickey", r["methods"])
        self.assertIn("password", r["methods"])
        self.assertIn("keyboard-interactive", r["methods"])

    def test_missing_ssh_binary_returns_empty(self):
        import shutil
        orig_which = shutil.which
        shutil.which = lambda name: None
        try:
            r = ssh.auth_methods("127.0.0.1", 22)
        finally:
            shutil.which = orig_which
        self.assertFalse(r["reachable"])
        self.assertEqual(r["methods"], [])


class DetectionTest(unittest.TestCase):
    def test_is_ssh_port_and_service(self):
        from recce.core.models import Port
        self.assertTrue(ssh.is_ssh(Port(portid=22, service="ssh", state="open")))
        self.assertTrue(ssh.is_ssh(Port(portid=2222, service="", state="open")))
        self.assertTrue(ssh.is_ssh(Port(portid=830, service="", state="open")))
        self.assertTrue(ssh.is_ssh(Port(portid=9999, service="ssh", state="open")))
        self.assertFalse(ssh.is_ssh(Port(portid=80, service="http", state="open")))
        self.assertFalse(ssh.is_ssh(Port(portid=22, service="ssh", state="closed")))


class WeakKexPacketRoundtripTest(unittest.TestCase):
    """End-to-end: fake server offers a bunch of weak algos, probe() reads
    them, findings() emits the expected posture findings."""

    def test_weak_bundle_produces_all_posture_findings(self):
        kexinit = _kexinit_payload(
            "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,"
            "curve25519-sha256",
            "ssh-rsa,ssh-dss,ssh-ed25519",
            "arcfour,3des-cbc,aes128-cbc,chacha20-poly1305@openssh.com,aes128-ctr",
            "hmac-md5,hmac-sha1-96,hmac-sha2-256")
        srv = _FakeSSHServer(_IDENT_LEGACY_199, kexinit)
        try:
            pr = ssh.probe(srv.host, srv.port, timeout=2, capture_hostkey=False)
        finally:
            srv.close()
        h = _fake_host_with_port(srv.port)
        h.ip = srv.host
        fs = ssh.findings([h], {(srv.host, srv.port): pr})
        kinds = {f["kind"] for f in fs}
        for expected in ("ssh_legacy_proto", "ssh_weak_kex", "ssh_weak_cipher",
                         "ssh_weak_mac", "ssh_hostkey_posture",
                         "ssh_terrapin", "ssh_algo_inventory"):
            self.assertIn(expected, kinds, f"missing {expected} in {kinds}")


if __name__ == "__main__":
    unittest.main()
