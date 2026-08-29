"""Tests for recce.services.nisyp — NIS/YP over ONC RPC.

Wire fixtures are byte-assembled from the RFC/spec layout rather than by
calling nisyp's own encoders, so a shifted offset in probe() or the parser
still fails these tests. Socket I/O is faked by monkeypatching
socket.socket / socket.create_connection so nothing touches the network.
"""
from __future__ import annotations

import socket
import struct

import pytest

from recce.core.models import Host, Port
from recce.services import nisyp


# --- helpers to build RPC wire ------------------------------------------------

def _rpc_reply(xid: int, payload: bytes,
               accept_stat: int = 0, reply_stat: int = 0) -> bytes:
    """Build a MSG_ACCEPTED / SUCCESS reply. verifier is AUTH_NULL/0."""
    return struct.pack(">III", xid, 1, reply_stat) \
        + struct.pack(">II", 0, 0) \
        + struct.pack(">I", accept_stat) \
        + payload


def _xdr_str(s: str) -> bytes:
    b = s.encode("utf-8")
    pad = (-len(b)) % 4
    return struct.pack(">I", len(b)) + b + b"\x00" * pad


# --- unit-level parsers -------------------------------------------------------

def test_is_nis_predicate():
    assert nisyp.is_nis(Port(portid=111, state="open", service="rpcbind"))
    assert nisyp.is_nis(Port(portid=714, state="open", service=""))
    assert nisyp.is_nis(Port(portid=32771, state="open", service="ypserv"))
    assert not nisyp.is_nis(Port(portid=22, state="open", service="ssh"))


def test_hash_format_classification():
    # 13-char DES crypt (Solaris ≤ 9 territory)
    assert nisyp._hash_format("Xr4ilOzQ4PCOq") == "des"
    # modular crypt schemes
    assert nisyp._hash_format("$1$abcd$hashhash") == "md5"
    assert nisyp._hash_format("$5$abcd$hashhash") == "sha256"
    assert nisyp._hash_format("$6$abcd$hashhash") == "sha512"
    assert nisyp._hash_format("$2a$10$xxx") == "blowfish"
    assert nisyp._hash_format("$y$j9T$xxx") == "yescrypt"
    # locked / shadowed / empty must NOT be reported as a live hash
    for locked in ("", "x", "*", "!", "!!", "NP"):
        assert nisyp._hash_format(locked) == "", locked
    # unknown but non-empty is surfaced as such
    assert nisyp._hash_format("nonsense") == "unknown"


def test_parse_pw_line_getpwent_shape():
    row = nisyp._parse_pw_line("alice:$6$abcd$xx:1001:1001:Alice:/home/alice:/bin/bash")
    assert row["user"] == "alice"
    assert row["hash_format"] == "sha512"
    assert row["uid"] == "1001" and row["shell"] == "/bin/bash"
    # a comment / blank line should be ignored
    assert nisyp._parse_pw_line("# a comment") is None
    # too few fields — not a getpwent line
    assert nisyp._parse_pw_line("nope:only:two") is None


def test_domain_candidates_ordering_and_dedup():
    h = Host(ip="10.0.0.5", hostnames=["ns1.corp.example.com"])
    cands = nisyp.nis_domain_candidates(h, extra=["CORP.EXAMPLE.COM", "corp"])
    # extras come first, deduped case-insensitively, hostname suffix + short
    # name next, defaults last
    assert cands[0] == "corp.example.com"
    assert cands[1] == "corp"
    assert "ns1" in cands
    assert "nis" in cands and "yp" in cands
    # cap honoured
    assert len(cands) <= 16


# --- XDR / RPC parsing off the wire ------------------------------------------

def test_parse_reply_accepts_matched_xid_and_success():
    pkt = _rpc_reply(0xdead, b"\x00\x00\x00\x01")
    assert nisyp._parse_reply(pkt, 0xdead) == b"\x00\x00\x00\x01"


def test_parse_reply_rejects_wrong_xid():
    pkt = _rpc_reply(0xdead, b"")
    assert nisyp._parse_reply(pkt, 0xbeef) is None


def test_parse_reply_rejects_non_success():
    # accept_stat != 0 -> None
    pkt = _rpc_reply(0xdead, b"\x00" * 4, accept_stat=1)
    assert nisyp._parse_reply(pkt, 0xdead) is None


def test_cursor_reads_string_and_opaque():
    body = _xdr_str("hello") + struct.pack(">I", 3) + b"\x01\x02\x03\x00"
    cur = nisyp._Cur(body)
    assert cur.string() == "hello"
    assert cur.opaque() == b"\x01\x02\x03"


def test_cursor_rejects_oversized_opaque():
    """A length header larger than the buffer must raise, not read past end."""
    body = struct.pack(">I", 999) + b"AB"
    cur = nisyp._Cur(body)
    with pytest.raises(ValueError):
        cur.opaque()


# --- portmap DUMP / GETPORT parsing (fake UDP socket) ------------------------

class _FakeUDP:
    """A minimal `socket.socket(SOCK_DGRAM)` stand-in that returns a canned
    payload from recvfrom, capturing what was sent for assertion."""

    def __init__(self, reply: bytes):
        self._reply = reply
        self.sent: list[tuple[bytes, tuple]] = []

    def settimeout(self, t): pass
    def sendto(self, data, addr): self.sent.append((data, addr))
    def recvfrom(self, n):
        return self._reply, ("127.0.0.1", 111)
    def close(self): pass


def _install_fake_udp(monkeypatch, reply: bytes) -> _FakeUDP:
    fake = _FakeUDP(reply)
    def _factory(family, type_):
        assert type_ == socket.SOCK_DGRAM
        return fake
    monkeypatch.setattr(nisyp.socket, "socket", _factory)
    return fake


def _portmap_dump_payload(entries: list[tuple[int, int, int, int]]) -> bytes:
    """Build a portmap DUMP payload: a linked list of (prog, vers, prot, port)
    prefixed by a value-follows bool. Terminated by a FALSE bool."""
    body = b""
    for prog, vers, prot, port in entries:
        body += struct.pack(">IIIII", 1, prog, vers, prot, port)
    body += struct.pack(">I", 0)
    return body


def test_portmap_dump_recognises_nis_programs(monkeypatch):
    # A realistic portmap DUMP: portmap self, ypserv v2/tcp+udp, ypbind,
    # yppasswdd, ypupdated, plus an unrelated program.
    entries = [
        (100000, 2, 6, 111),                    # portmap tcp
        (100000, 2, 17, 111),                   # portmap udp
        (100004, 2, 17, 714),                   # ypserv v2 udp
        (100004, 2, 6,  717),                   # ypserv v2 tcp
        (100007, 2, 17, 715),                   # ypbind v2 udp
        (100009, 1, 17, 716),                   # yppasswdd
        (100028, 1, 17, 718),                   # ypupdated
        (100005, 3, 17, 892),                   # mountd (control)
    ]
    reply = _rpc_reply(0x2001, _portmap_dump_payload(entries))
    _install_fake_udp(monkeypatch, reply)
    got = nisyp.portmap_dump("10.0.0.9", timeout=1.0)
    # every entry survives
    assert len(got) == len(entries)
    # is_nis and classify_program reach the right names
    named = {nisyp._classify_program(p["prog"]) for p in got}
    assert {"ypserv", "ypbind", "yppasswdd", "ypupdated"} <= named


def test_getport_reads_the_u32(monkeypatch):
    reply = _rpc_reply(0x2002, struct.pack(">I", 714))
    _install_fake_udp(monkeypatch, reply)
    assert nisyp.getport("10.0.0.9", 100004, 2, 17, timeout=1.0) == 714


def test_getport_returns_zero_on_short_reply(monkeypatch):
    _install_fake_udp(monkeypatch, _rpc_reply(0x2002, b"\x00"))
    assert nisyp.getport("10.0.0.9", 100004, 2, 17, timeout=1.0) == 0


# --- YPPROC_DOMAIN + YPPROC_MAPLIST over UDP ---------------------------------

def test_yp_domain_true_and_false(monkeypatch):
    # TRUE (1) — domain served.
    _install_fake_udp(monkeypatch, _rpc_reply(0x3001, struct.pack(">I", 1)))
    assert nisyp.yp_domain("10.0.0.9", 714, "corp", timeout=1.0) is True
    # FALSE (0) — not served.
    _install_fake_udp(monkeypatch, _rpc_reply(0x3001, struct.pack(">I", 0)))
    assert nisyp.yp_domain("10.0.0.9", 714, "wrong", timeout=1.0) is False


def test_yp_maplist_parses_linked_string_list(monkeypatch):
    # ypresp_maplist: ypstat (YP_TRUE=1) + linked list of strings
    body = struct.pack(">I", nisyp._YP_TRUE)
    for name in ("passwd.byname", "passwd.byuid", "group.byname",
                 "netgroup", "hosts.byname", "ypservers"):
        body += struct.pack(">I", 1) + _xdr_str(name)
    body += struct.pack(">I", 0)                       # end of list
    _install_fake_udp(monkeypatch, _rpc_reply(0x3002, body))
    maps = nisyp.yp_maplist("10.0.0.9", 714, "corp", timeout=1.0)
    assert "passwd.byname" in maps and "netgroup" in maps
    assert len(maps) == 6


def test_yp_maplist_empty_on_ypstat_nomap(monkeypatch):
    # ypstat != YP_TRUE means "no such map / no domain" — no entries follow.
    _install_fake_udp(monkeypatch,
                      _rpc_reply(0x3002, struct.pack(">I", nisyp._YP_NOMORE)))
    assert nisyp.yp_maplist("10.0.0.9", 714, "corp", timeout=1.0) == []


# --- YPPROC_ALL streaming over TCP -------------------------------------------

class _FakeTCP:
    """A `socket.create_connection` stand-in that returns a canned byte stream.
    recv walks the buffer; sendall is captured for assertion."""

    def __init__(self, stream: bytes):
        self._buf = stream
        self.sent = b""

    def settimeout(self, t): pass
    def sendall(self, data): self.sent += data
    def recv(self, n):
        if not self._buf:
            return b""
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk
    def close(self): pass


def _record(bytes_: bytes, last: bool = True) -> bytes:
    """Wrap a byte string as one RPC record-marking fragment."""
    marker = (0x80000000 if last else 0) | len(bytes_)
    return struct.pack(">I", marker) + bytes_


def _yp_all_stream(pairs: list[tuple[str, str]], stop_stat: int | None = None) -> bytes:
    """Assemble a series of YPPROC_ALL response records.

    Each pair is one record carrying ypresp_all (more=TRUE + ypstat=YP_TRUE +
    key + val). A final record with more=FALSE ends the stream. When
    `stop_stat` is set, the last record uses more=TRUE + that ypstat (>YP_TRUE)
    to signal end-of-map the way real ypserv sometimes does."""
    out = b""
    for k, v in pairs:
        payload = (struct.pack(">II", 1, nisyp._YP_TRUE)
                   + _xdr_str(k) + _xdr_str(v))
        out += _record(_rpc_reply(0x3003, payload))
    if stop_stat is not None:
        end = struct.pack(">II", 1, stop_stat) + _xdr_str("") + _xdr_str("")
    else:
        end = struct.pack(">I", 0)                    # more == FALSE
    out += _record(_rpc_reply(0x3003, end))
    return out


def test_yp_all_streams_pairs_until_more_false(monkeypatch):
    pairs = [("alice", "alice:$6$aa$hash1:1001:1001:Alice:/home/alice:/bin/bash"),
             ("bob",   "bob:$1$bb$hash2:1002:1002:Bob:/home/bob:/bin/sh")]
    fake = _FakeTCP(_yp_all_stream(pairs))

    def _create_connection(addr, timeout=None):
        return fake
    monkeypatch.setattr(nisyp.socket, "create_connection", _create_connection)

    got = nisyp.yp_all("10.0.0.9", 714, "corp", "passwd.byname",
                      timeout=1.0)
    assert got == pairs
    # The sent buffer must carry both XDR strings (domain, map) in order.
    assert b"corp" in fake.sent and b"passwd.byname" in fake.sent


def test_yp_all_stops_on_ypstat_nomore(monkeypatch):
    pairs = [("alice", "alice:x:1001:1001::/home/alice:/bin/bash")]
    fake = _FakeTCP(_yp_all_stream(pairs, stop_stat=nisyp._YP_NOMORE))

    def _create_connection(addr, timeout=None):
        return fake
    monkeypatch.setattr(nisyp.socket, "create_connection", _create_connection)

    got = nisyp.yp_all("10.0.0.9", 714, "corp", "passwd.byname",
                      timeout=1.0)
    assert got == pairs


# --- findings — the finding shape and severity for each capability -----------

def _host(ip="10.0.0.9"):
    return Host(ip=ip, hostnames=["nis1.corp.example.com"],
                ports=[Port(portid=111, state="open", service="rpcbind")])


def _probe_base(**kw):
    base = {
        "reachable": True, "programs": [], "nis_programs": {}, "domain": "",
        "maps": [], "records": {}, "passwd_hashes": [], "securenets": False,
        "ypserv_port": 714,
    }
    base.update(kw)
    return base


def test_findings_ypupdated_is_high_and_cites_cve_class():
    pr = _probe_base(nis_programs={"ypupdated": [{"prog": 100028}]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    f = next(x for x in fs if x["kind"] == "nis_ypupdated")
    assert f["severity"] == "high"
    assert "CVE-1999-0208" in f["detail"] or "CVE-1999-0208" in f.get("narrative", "")


def test_findings_yppasswdd_is_medium_named():
    pr = _probe_base(nis_programs={"yppasswdd": [{"prog": 100009}]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    assert any(f["kind"] == "nis_yppasswdd" and f["severity"] == "medium"
               for f in fs)


def test_findings_rpc_names_low_when_only_ypserv_named():
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    assert any(f["kind"] == "nis_rpc_names" and f["severity"] == "low"
               for f in fs)


def test_findings_passwd_hashes_critical_and_cwe_522():
    hashes = [
        {"user": "alice", "hash": "Xr4ilOzQ4PCOq", "uid": "1001", "gid": "1001",
         "gecos": "Alice", "home": "/home/alice", "shell": "/bin/bash",
         "hash_format": "des"},
        {"user": "bob", "hash": "$6$aa$hashx", "uid": "1002", "gid": "1002",
         "gecos": "", "home": "/home/bob", "shell": "/bin/sh",
         "hash_format": "sha512"},
    ]
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["passwd.byname"],
                     passwd_hashes=hashes)
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    f = next(x for x in fs if x["kind"] == "nis_passwd_hashes")
    assert f["severity"] == "critical"
    assert "CWE-522" in f["cwes"]
    assert "alice" in f["detail"] and "corp" in f["detail"]
    # DES presence triggers the EOL companion finding
    assert any(x["kind"] == "nis_hash_age" for x in fs)


def test_findings_netgroup_root_trust_is_high():
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["netgroup"],
                     records={"netgroup": [
                         ("wheel-hosts", "(-,root,) (dbserver,root,)")]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    f = next(x for x in fs if x["kind"] == "nis_netgroup_trust")
    assert f["severity"] == "high"


def test_findings_group_map_privileged_is_high():
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["group.byname"],
                     records={"group.byname": [
                         ("wheel", "wheel:*:0:root,alice"),
                         ("users", "users:*:100:")]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    f = next(x for x in fs if x["kind"] == "nis_group_hashes")
    assert f["severity"] == "high"


def test_findings_topology_leak_when_hosts_or_ypservers():
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["hosts.byname", "ypservers"],
                     records={"hosts.byname": [("db1", "10.0.0.11 db1")],
                              "ypservers": [("ypmaster", "10.0.0.9")]})
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    assert any(f["kind"] == "nis_topology_leak" for f in fs)


def test_findings_securenets_partial_hardening_medium():
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["passwd.byname"],
                     passwd_hashes=[], securenets=True)
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    f = next(x for x in fs if x["kind"] == "nis_domain_leak")
    assert f["severity"] == "medium"


def test_findings_unreachable_produces_none():
    assert nisyp.findings([_host()], {"10.0.0.9": {"reachable": False}}) == []


def test_findings_to_vulns_on_port_111_with_nisyp_source():
    hashes = [{"user": "u", "hash": "$1$s$h", "uid": "1", "gid": "1",
               "gecos": "", "home": "", "shell": "/bin/sh",
               "hash_format": "md5"}]
    pr = _probe_base(nis_programs={"ypserv": [{"prog": 100004}]},
                     domain="corp", maps=["passwd.byname"],
                     passwd_hashes=hashes)
    fs = nisyp.findings([_host()], {"10.0.0.9": pr})
    v = nisyp.findings_to_vulns([f for f in fs
                                 if f["kind"] == "nis_passwd_hashes"])
    vuln = v["10.0.0.9"][0]
    assert vuln.source == "nisyp"
    assert vuln.port == 111
    assert vuln.severity == "critical"


def test_analyze_shape_and_credential_handoff():
    """analyze() with active=False just returns the target skeleton — but the
    credential-handoff hook stores hashes into the creds dict when probes
    exist."""
    hosts = [_host()]
    hashes = [{"user": "alice", "hash": "Xr4ilOzQ4PCOq", "uid": "1001",
               "gid": "1001", "gecos": "", "home": "/home/alice",
               "shell": "/bin/bash", "hash_format": "des"}]
    creds: dict = {}
    added = nisyp._handoff_hashes(
        hosts,
        {"10.0.0.9": _probe_base(domain="corp", passwd_hashes=hashes)},
        creds)
    assert added == 1
    cred = creds["credentials"][0]
    assert cred.username == "alice"
    assert cred.source == "nisyp"
    assert cred.kind == "crypt-des"

    res = nisyp.analyze(hosts, active=False)
    assert set(res) >= {"targets", "findings", "runbooks", "probes", "stats"}
    assert res["stats"]["targets"] == 1
