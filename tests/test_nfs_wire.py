"""Wire-derived tests for the NFS module additions: MOUNTPROC_DUMP (proc 2 /
showmount -a) and MOUNTPROC_MNT (proc 1 / filehandle capture). Fixtures follow
RFC 1813 sec 5.2.1 / 5.2.2 (mountd v3) - length-prefixed dirpath, MNT3_OK reply
= status u32 + nfs_fh3 (opaque) + auth_flavors<>.
"""
from __future__ import annotations

import socketserver
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import nfs as N


# --- one-shot mock mountd on 127.0.0.1 ------------------------------------------

def _xstr(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">I", len(b)) + b + b"\x00" * ((-len(b)) & 3)


def _reply(xid: int, results: bytes) -> bytes:
    body = (struct.pack(">III", xid, 1, 0)                 # xid, REPLY, MSG_ACCEPTED
            + struct.pack(">II", 0, 0)                     # verf AUTH_NULL
            + struct.pack(">I", 0)                         # accept_stat SUCCESS
            + results)
    return struct.pack(">I", 0x80000000 | len(body)) + body


def _make_handler(exports, clients, mnt_fh):
    """A mountd handler dispatching one RPC per connection over record marking.
    - DUMP (proc 4 on PMAP): advertises mountd on this port.
    - EXPORT (proc 5 on MOUNT): the supplied exports.
    - MNT (proc 1): returns MNT3_OK + fh (if `mnt_fh` set) else MNT3ERR_ACCES=13.
    - DUMP (proc 2 on MOUNT): the supplied client list.
    """
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(3.0)
            rec = N._recv_record(sock, 3.0)
            if rec is None:
                return
            xid, _mt, _rv, prog, _ve, proc = struct.unpack_from(">IIIIII", rec, 0)
            myport = self.server.server_address[1]
            if prog == N._PMAP_PROG and proc == 4:            # portmap DUMP
                res = b""
                for pr, ve, po in ((N._MOUNT_PROG, 3, myport),
                                   (N._NFS_PROG, 3, 2049)):
                    res += struct.pack(">IIIII", 1, pr, ve, N._IPPROTO_TCP, po)
                res += struct.pack(">I", 0)
                sock.sendall(_reply(xid, res))
            elif prog == N._MOUNT_PROG and proc == 5:         # mountd EXPORT
                res = b""
                for dirp, groups in exports:
                    res += struct.pack(">I", 1) + _xstr(dirp)
                    for g in groups:
                        res += struct.pack(">I", 1) + _xstr(g)
                    res += struct.pack(">I", 0)               # end of group list
                res += struct.pack(">I", 0)                   # end of export list
                sock.sendall(_reply(xid, res))
            elif prog == N._MOUNT_PROG and proc == 2:         # mountd DUMP (clients)
                res = b""
                for hostname, dirp in clients:
                    res += struct.pack(">I", 1) + _xstr(hostname) + _xstr(dirp)
                res += struct.pack(">I", 0)
                sock.sendall(_reply(xid, res))
            elif prog == N._MOUNT_PROG and proc == 1:         # mountd MNT
                if mnt_fh:
                    # MNT3_OK (0) + nfs_fh3 (opaque, length-prefixed) + auth_flavors<>
                    fh = struct.pack(">I", len(mnt_fh)) + mnt_fh \
                        + b"\x00" * ((-len(mnt_fh)) & 3)
                    flavors = struct.pack(">II", 1, 1)        # AUTH_SYS
                    sock.sendall(_reply(xid, struct.pack(">I", 0) + fh + flavors))
                else:
                    sock.sendall(_reply(xid, struct.pack(">I", 13)))  # MNT3ERR_ACCES
            else:
                sock.sendall(_reply(xid, b""))

    return Handler


class _MockMountd:
    def __init__(self, exports, clients, mnt_fh):
        self.srv = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), _make_handler(exports, clients, mnt_fh))
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


# --- tests ----------------------------------------------------------------------

# A representative NFSv3 filehandle - opaque bytes; recce should never inspect
# the contents, only capture the length and treat the reply as "MNT_OK".
_FIXED_FH = bytes.fromhex("01000602000000000000000000000000") \
    + bytes.fromhex("0000000000000000000000000000000000000000")


class NfsMountDumpAndMntWireTest(unittest.TestCase):
    """RFC 1813 sec 5.2.1 / 5.2.2 wire test: DUMP hands back the client list;
    MNT3_OK hands back a root filehandle + auth flavors."""

    def test_mount_dump_parses_client_list(self):
        exports = [("/srv/backups", ["*"])]
        clients = [("host-a.example", "/srv/backups"),
                   ("10.0.0.7", "/srv/backups")]
        with _MockMountd(exports, clients, _FIXED_FH) as m:
            got = N.mount_dump("127.0.0.1", m.port, 3, timeout=3.0)
        self.assertEqual(got, [
            {"hostname": "host-a.example", "dir": "/srv/backups"},
            {"hostname": "10.0.0.7", "dir": "/srv/backups"},
        ])

    def test_mount_dump_empty_list_is_empty(self):
        with _MockMountd([], [], b"") as m:
            got = N.mount_dump("127.0.0.1", m.port, 3, timeout=3.0)
        self.assertEqual(got, [])

    def test_mount_mnt_captures_filehandle_and_flavors(self):
        exports = [("/srv/backups", ["*"])]
        with _MockMountd(exports, [], _FIXED_FH) as m:
            r = N.mount_mnt("127.0.0.1", m.port, "/srv/backups", 3, timeout=3.0)
        self.assertIsNotNone(r)
        self.assertEqual(r["status"], 0)
        self.assertEqual(r["fh"], _FIXED_FH)
        self.assertEqual(r["auth_flavors"], [1])              # AUTH_SYS

    def test_mount_mnt_reports_server_denial_without_fh(self):
        exports = [("/srv/backups", ["*"])]
        # mnt_fh empty -> mock returns MNT3ERR_ACCES (13).
        with _MockMountd(exports, [], b"") as m:
            r = N.mount_mnt("127.0.0.1", m.port, "/srv/backups", 3, timeout=3.0)
        self.assertIsNotNone(r)
        self.assertEqual(r["status"], 13)
        self.assertEqual(r["fh"], b"")
        self.assertEqual(r["auth_flavors"], [])

    def test_probe_captures_mounts_and_clients(self):
        exports = [("/srv/backups", ["*"]),
                   ("/home", ["10.0.0.0/24"])]
        clients = [("host-a", "/srv/backups")]
        with _MockMountd(exports, clients, _FIXED_FH) as m:
            pr = N.probe("127.0.0.1", timeout=3.0, pmport=m.port)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["mount_clients"],
                         [{"hostname": "host-a", "dir": "/srv/backups"}])
        # MNT was attempted per export - both should be present, both MNT3_OK.
        self.assertEqual({m["dir"] for m in pr["mounts"]},
                         {"/srv/backups", "/home"})
        for m in pr["mounts"]:
            self.assertEqual(m["status"], 0)
            self.assertEqual(m["fh_len"], len(_FIXED_FH))

    def test_probe_mount_probe_gate_disables_mnt(self):
        exports = [("/srv/backups", ["*"])]
        with _MockMountd(exports, [], _FIXED_FH) as m:
            pr = N.probe("127.0.0.1", timeout=3.0, pmport=m.port,
                         mount_probe=False)
        self.assertEqual(pr["mounts"], [])

    def test_findings_emit_nfs_mnt_open_and_mount_clients(self):
        exports = [("/srv/backups", ["*"])]
        clients = [("host-a", "/srv/backups")]
        with _MockMountd(exports, clients, _FIXED_FH) as m:
            pr = {"10.0.8.9": N.probe("127.0.0.1", timeout=3.0, pmport=m.port)}
        host = Host(ip="10.0.8.9", ports=[
            Port(portid=2049, service="nfs", state="open"),
            Port(portid=111, service="rpcbind", state="open")])
        fs = N.findings([host], pr)
        kinds = {f["kind"] for f in fs}
        self.assertIn("nfs_mnt_open", kinds)
        self.assertIn("nfs_mount_clients", kinds)
        # nfs_mnt_open must be high (mountability proven from recce's IP).
        mnt = next(f for f in fs if f["kind"] == "nfs_mnt_open")
        self.assertEqual(mnt["severity"], "high")
        self.assertIn("/srv/backups", mnt["detail"])
        # nfs_mount_clients must be medium (info-leak, not immediate write).
        cl = next(f for f in fs if f["kind"] == "nfs_mount_clients")
        self.assertEqual(cl["severity"], "medium")
        self.assertIn("host-a", cl["detail"])

    def test_findings_no_mnt_or_clients_when_absent(self):
        # Server exports the world share but denies MNT and hides rmtab.
        exports = [("/srv/backups", ["*"])]
        with _MockMountd(exports, [], b"") as m:                  # mnt_fh empty
            pr = {"10.0.8.9": N.probe("127.0.0.1", timeout=3.0, pmport=m.port)}
        host = Host(ip="10.0.8.9", ports=[
            Port(portid=2049, service="nfs", state="open")])
        fs = N.findings([host], pr)
        kinds = {f["kind"] for f in fs}
        self.assertIn("nfs_world", kinds)                          # existing
        self.assertNotIn("nfs_mnt_open", kinds)                    # denied
        self.assertNotIn("nfs_mount_clients", kinds)               # empty

    def test_mount_dump_bounded_on_transport_error(self):
        # No server - a straight connection refusal returns [] (no exception).
        self.assertEqual(N.mount_dump("127.0.0.1", 1, 3, timeout=0.5), [])
        self.assertIsNone(N.mount_mnt("127.0.0.1", 1, "/x", 3, timeout=0.5))


if __name__ == "__main__":
    unittest.main()
