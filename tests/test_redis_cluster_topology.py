"""Redis cluster/replication topology disclosure capability.

Once an unauthenticated Redis is confirmed, the deep probe issues two additional
metadata-only reads: `INFO replication` (whose `slave{N}:` entries list every
replica endpoint), and `CLUSTER NODES` (whose bulk reply lists every peer the
cluster knows about, with node IDs and roles). recce never writes a key, changes
a config, or attempts auth. This suite drives the parsers with RFC/wire-derived
fixtures, exercises the probe against a monkeypatched socket, and confirms the
finding fires vulnerable / stays quiet patched / stays quiet absent.
"""
import unittest

from recce.core.models import Host, Port
from recce.services.db import redis as R


# --- RFC / wire-derived fixtures ------------------------------------------------

_INFO_REPLICATION_MASTER = (
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:2\r\n"
    "slave0:ip=10.0.0.11,port=6379,state=online,offset=15234,lag=0\r\n"
    "slave1:ip=10.0.0.12,port=6379,state=online,offset=15234,lag=1\r\n"
    "master_replid:8371b3f0deadbeefcafebabe0000000000000001\r\n"
    "master_repl_offset:15234\r\n"
)

_INFO_REPLICATION_STANDALONE = (
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:0\r\n"
    "master_replid:1111111111111111111111111111111111111111\r\n"
    "master_repl_offset:0\r\n"
)

# CLUSTER NODES reply from a live 3-master / 3-replica cluster (bytes are the
# exact framing Redis emits: node id, ip:port@cport, flags, master ref, ping,
# pong, epoch, link-state, then any slot ranges).
_CLUSTER_NODES = (
    "07c37dfeb235213a872192d90877d0cd55635b91 127.0.0.1:30004@31004 "
    "slave e7d1eecce10fd6bb5eb35b9f99a514335d9ba9ca 0 1426238317239 4 "
    "connected\n"
    "67ed2db8d677e59ec4a4cefb06858cf2a1a89fa1 127.0.0.1:30002@31002 "
    "master - 0 1426238316232 2 connected 5461-10922\n"
    "292f8b365bb7edb5e285caf0b7e6ddc7265d2f4f 127.0.0.1:30003@31003 "
    "master - 0 1426238318243 3 connected 10923-16383\n"
    "6ec23923021cf3ffec47632106199cb7f496ce01 127.0.0.1:30005@31005 "
    "slave 67ed2db8d677e59ec4a4cefb06858cf2a1a89fa1 0 1426238316232 5 "
    "connected\n"
    "824fe116063bc5fcf9f4ffd895bc17aee7731ac3 127.0.0.1:30006@31006 "
    "slave 292f8b365bb7edb5e285caf0b7e6ddc7265d2f4f 0 1426238317741 6 "
    "connected\n"
    "e7d1eecce10fd6bb5eb35b9f99a514335d9ba9ca 127.0.0.1:30001@31001 "
    "myself,master - 0 0 1 connected 0-5460\n"
)


# --- parser tests ---------------------------------------------------------------

class ReplicationSlavesParseTest(unittest.TestCase):
    def test_master_yields_slave_endpoints(self):
        d = R._info_dict(_INFO_REPLICATION_MASTER)
        slaves = R._replication_slaves(d)
        self.assertEqual(len(slaves), 2)
        self.assertEqual(slaves[0]["host"], "10.0.0.11")
        self.assertEqual(slaves[0]["port"], "6379")
        self.assertEqual(slaves[0]["state"], "online")
        self.assertEqual(slaves[1]["host"], "10.0.0.12")

    def test_standalone_yields_no_slaves(self):
        d = R._info_dict(_INFO_REPLICATION_STANDALONE)
        self.assertEqual(R._replication_slaves(d), [])

    def test_bogus_lines_are_ignored(self):
        # `slave` (no digits) and `slaveof` are NOT slave endpoint entries.
        d = {"slave": "not a number suffix",
             "slaveof": "some-legacy-key",
             "slave2": "ip=192.0.2.9,port=6379,state=online"}
        slaves = R._replication_slaves(d)
        self.assertEqual([s["host"] for s in slaves], ["192.0.2.9"])


class ClusterNodesParseTest(unittest.TestCase):
    def test_parses_full_cluster_reply(self):
        nodes = R._parse_cluster_nodes(_CLUSTER_NODES)
        self.assertEqual(len(nodes), 6)
        by_id = {n["id"]: n for n in nodes}
        me = by_id["e7d1eecce10fd6bb5eb35b9f99a514335d9ba9ca"]
        self.assertEqual(me["role"], "master")
        self.assertEqual(me["host"], "127.0.0.1")
        self.assertEqual(me["port"], "30001")
        self.assertEqual(me["cport"], "31001")
        self.assertIn("myself", me["flags"])
        replica = by_id["07c37dfeb235213a872192d90877d0cd55635b91"]
        self.assertEqual(replica["role"], "slave")
        self.assertEqual(replica["master"],
                         "e7d1eecce10fd6bb5eb35b9f99a514335d9ba9ca")
        # role tallies
        roles = [n["role"] for n in nodes]
        self.assertEqual(roles.count("master"), 3)
        self.assertEqual(roles.count("slave"), 3)

    def test_empty_or_short_lines_are_skipped(self):
        self.assertEqual(R._parse_cluster_nodes(""), [])
        self.assertEqual(R._parse_cluster_nodes("id 1.2.3.4:6379"), [])

    def test_ipv6_endpoint_keeps_ipv6_host(self):
        # Redis emits IPv6 endpoints inline; splitting must use the LAST colon.
        line = ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "
                "fe80::1:6379@16379 master - 0 0 1 connected 0-16383")
        nodes = R._parse_cluster_nodes(line)
        self.assertEqual(nodes[0]["host"], "fe80::1")
        self.assertEqual(nodes[0]["port"], "6379")


# --- probe integration (monkeypatched socket) -----------------------------------

class _FakeSock:
    """Scripted RESP peer. Every _command(...) call sends bytes we ignore; every
    _read_reply(...) call pops the next reply we were seeded with. Nothing hits
    the network."""

    def __init__(self, replies):
        self._replies = list(replies)

    def sendall(self, _data):
        return None

    def settimeout(self, _t):
        return None

    def recv(self, _n):
        return b""

    def close(self):
        return None


def _encode_bulk(s: str) -> bytes:
    b = s.encode()
    return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"


class ProbeTopologyTest(unittest.TestCase):
    def setUp(self):
        # Reset any monkeypatching between tests.
        self._orig_command = R._command
        self._orig_read = R._read_reply
        self._orig_conn = R.socket.create_connection

    def tearDown(self):
        R._command = self._orig_command
        R._read_reply = self._orig_read
        R.socket.create_connection = self._orig_conn

    def _install(self, replies):
        """Wire recce's RESP layer to consume the given queue of parsed replies."""
        queue = list(replies)

        def _fake_conn(_addr, timeout=None):
            return _FakeSock(queue)

        def _fake_command(sock, *args):
            return b""

        def _fake_read(sock, timeout=R._TIMEOUT):
            if not queue:
                return None
            return queue.pop(0)

        R.socket.create_connection = _fake_conn
        R._command = _fake_command
        R._read_reply = _fake_read

    def _base_replies(self):
        """The replies the existing (already-shipped) probe consumes before the
        new topology calls: PING, INFO, six CONFIG GETs, MODULE LIST, ACL
        WHOAMI, ACL LIST, ACL USERS, EVAL, then INFO replication + CLUSTER
        NODES for the topology capability."""
        info_body = (
            "# Server\r\nredis_version:7.2.0\r\nos:Linux 6.1 x86_64\r\n"
            "redis_mode:standalone\r\n# Replication\r\nrole:master\r\n"
            "# Keyspace\r\ndb0:keys=1,expires=0\r\n")
        return [
            "PONG",                                    # PING
            info_body,                                 # INFO (bulk string)
            ["dir", "/data"],                          # CONFIG GET dir
            ["dbfilename", "dump.rdb"],                # CONFIG GET dbfilename
            ["requirepass", ""],                       # CONFIG GET requirepass
            ["protected-mode", "no"],                  # CONFIG GET protected-mode
            ["save", ""],                              # CONFIG GET save
            ["appendonly", "no"],                      # CONFIG GET appendonly
            # _deep starts here:
            R._Err("ERR MODULE not supported"),        # MODULE LIST -> error
            "default",                                 # ACL WHOAMI
            R._Err("ERR ACL"),                         # ACL LIST -> error
            R._Err("ERR ACL"),                         # ACL USERS -> error
            0,                                         # EVAL loadlib probe
        ]

    def test_vulnerable_topology_yields_finding(self):
        replies = self._base_replies() + [
            _INFO_REPLICATION_MASTER,                  # INFO replication
            _CLUSTER_NODES,                            # CLUSTER NODES
        ]
        self._install(replies)
        pr = R.probe("10.0.0.10", 6379, timeout=1.0)
        self.assertTrue(pr.get("unauth"))
        self.assertEqual(len(pr.get("replication_slaves") or []), 2)
        self.assertEqual(len(pr.get("cluster_nodes") or []), 6)
        host = Host(ip="10.0.0.10",
                    ports=[Port(portid=6379, service="redis", state="open")])
        fs = R.findings([host], {("10.0.0.10", 6379): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("redis_cluster_topology", kinds)
        f = next(f for f in fs if f["kind"] == "redis_cluster_topology")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertIn("CWE-200", f["cwes"])
        self.assertIn("CLUSTER NODES", f["detail"])
        self.assertIn("10.0.0.11", f["detail"])       # a slave IP made it in
        self.assertIn("127.0.0.1", f["detail"])       # a cluster node IP made it in

    def test_patched_topology_no_finding(self):
        """CLUSTER disabled + no replicas: peer answers ERR to both topology
        calls, so the probe records nothing and findings() stays quiet."""
        replies = self._base_replies() + [
            R._Err("ERR unknown subcommand"),          # INFO replication -> err
            R._Err("ERR This instance has cluster support disabled"),
        ]
        self._install(replies)
        pr = R.probe("10.0.0.10", 6379, timeout=1.0)
        self.assertTrue(pr.get("unauth"))
        self.assertNotIn("replication_slaves", pr)
        self.assertNotIn("cluster_nodes", pr)
        host = Host(ip="10.0.0.10",
                    ports=[Port(portid=6379, service="redis", state="open")])
        fs = R.findings([host], {("10.0.0.10", 6379): pr})
        self.assertNotIn("redis_cluster_topology", [f["kind"] for f in fs])

    def test_absent_when_not_unauth(self):
        """A locked instance (auth_required) never runs the deep probe - and
        even a hand-supplied topology on a non-unauth pr must NOT flag."""
        pr = {"reachable": True, "unauth": False, "auth_required": True,
              "cluster_nodes": [{"id": "x", "host": "1.2.3.4", "port": "6379",
                                 "cport": "16379", "flags": ["master"],
                                 "master": "", "role": "master"}]}
        host = Host(ip="10.0.0.10",
                    ports=[Port(portid=6379, service="redis", state="open")])
        fs = R.findings([host], {("10.0.0.10", 6379): pr})
        self.assertNotIn("redis_cluster_topology", [f["kind"] for f in fs])


if __name__ == "__main__":
    unittest.main()
