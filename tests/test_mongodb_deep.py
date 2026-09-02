"""Tests for the MongoDB deep-enum additions: hostInfo, getLog startupWarnings,
and local.system.keys cluster-keyfile extraction. Uses an in-process fake mongod
speaking real OP_MSG / BSON so the wire path is exercised end to end."""
import socket
import struct
import threading
import unittest

from recce.services.db import mongodb as M
from recce.core.models import Host, Port


def _host(port, service="mongodb"):
    return Host(ip="127.0.0.1", ports=[Port(portid=port, service=service, state="open")])


def _tcp_once(handler):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    handler(conn)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return port


# --- BSON helpers (mirror MongoDeepLoot's local ones so this file is self-contained)

def _e_double(n, v):
    return b"\x01" + M._cstr(n) + struct.pack("<d", v)


def _e_bool(n, v):
    return b"\x08" + M._cstr(n) + bytes([1 if v else 0])


def _e_doc(n, d):
    return b"\x03" + M._cstr(n) + d


def _e_array(n, docs):
    inner = M.bson_doc(*[_e_doc(str(i), d) for i, d in enumerate(docs)])
    return b"\x04" + M._cstr(n) + inner


def _e_int64(n, v):
    return b"\x12" + M._cstr(n) + struct.pack("<q", v)


def _e_binary_gen(n, data, subtype=0):
    return (b"\x05" + M._cstr(n) + struct.pack("<i", len(data))
            + bytes([subtype]) + data)


def _serve(replies_by_cmd):
    """Fake mongod handling OP_MSG. `replies_by_cmd` maps first-key -> bytes BSON doc."""
    unknown = M.bson_doc(M._e_str("errmsg", "no such command"), _e_double("ok", 0.0))

    def handle(conn):
        while True:
            hdr = M._recvn(conn, 16)
            if len(hdr) < 16:
                return
            length = struct.unpack("<i", hdr[:4])[0]
            rid = struct.unpack("<i", hdr[4:8])[0]
            body = M._recvn(conn, length - 16)
            doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
            cmd = next(iter(doc), "")
            conn.sendall(M.op_msg(rid, replies_by_cmd.get(cmd, unknown)))
    return _tcp_once(handle)


def _base_replies():
    hello = M.bson_doc(_e_bool("isWritablePrimary", True),
                       M._e_int32("maxWireVersion", 17),
                       _e_double("ok", 1.0))
    build = M.bson_doc(M._e_str("version", "6.0.1"),
                       M._e_str("javascriptEngine", "mozjs"),
                       _e_double("ok", 1.0))
    listdbs = M.bson_doc(
        _e_array("databases", [M.bson_doc(M._e_str("name", "prod"),
                                          _e_double("sizeOnDisk", 100.0))]),
        _e_double("totalSize", 100.0), _e_double("ok", 1.0))
    return {"hello": hello, "buildInfo": build, "listDatabases": listdbs}


class MongoHostInfoDisclosure(unittest.TestCase):
    """hostInfo -> OS/hostname fingerprint captured and surfaced as a finding."""

    def setUp(self):
        replies = _base_replies()
        replies["hostInfo"] = M.bson_doc(
            _e_doc("system", M.bson_doc(
                M._e_str("hostname", "prod-db-01.internal.example"),
                M._e_int32("cpuAddrSize", 64))),
            _e_doc("os", M.bson_doc(
                M._e_str("type", "Linux"),
                M._e_str("name", "Ubuntu"),
                M._e_str("version", "22.04"))),
            _e_double("ok", 1.0))
        self.port = _serve(replies)

    def test_probe_captures_host_info(self):
        pr = M.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["host_info"]["hostname"], "prod-db-01.internal.example")
        self.assertEqual(pr["host_info"]["os_type"], "Linux")
        self.assertEqual(pr["host_info"]["os_name"], "Ubuntu")
        self.assertEqual(pr["host_info"]["os_version"], "22.04")

    def test_finding_emitted(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("mongo_hostinfo", kinds)
        hf = [f for f in fs if f["kind"] == "mongo_hostinfo"][0]
        self.assertIn("prod-db-01.internal.example", hf["detail"])
        self.assertIn("Linux", hf["detail"])
        self.assertEqual(hf["severity"], "medium")


class MongoHostInfoT2Corroboration(unittest.TestCase):
    """T2 SAFE proof-of-exploit: a second controlled read (serverStatus)
    returns live process state that ties the hostInfo fingerprint to a live
    mongod on this socket. Promotes depth_tier T1 -> T2."""

    def setUp(self):
        replies = _base_replies()
        replies["hostInfo"] = M.bson_doc(
            _e_doc("system", M.bson_doc(
                M._e_str("hostname", "prod-db-01.internal.example"),
                M._e_int32("cpuAddrSize", 64))),
            _e_doc("os", M.bson_doc(
                M._e_str("type", "Linux"),
                M._e_str("name", "Ubuntu"),
                M._e_str("version", "22.04"))),
            _e_double("ok", 1.0))
        # serverStatus reply mirrors what a real mongod 6.x returns for the
        # slim projection: identity + version + pid + uptime + localTime, all
        # top-level keys. Values are wire-realistic — FQDN:port host, positive
        # pid/uptime, ISO-ish localTime string.
        replies["serverStatus"] = M.bson_doc(
            M._e_str("host", "prod-db-01.internal.example:27017"),
            M._e_str("version", "6.0.1"),
            M._e_str("process", "mongod"),
            _e_int64("pid", 4271),
            M._e_int32("uptime", 8642),
            M._e_str("localTime", "2026-08-30T14:22:07Z"),
            _e_double("ok", 1.0))
        self.port = _serve(replies)

    def test_probe_captures_server_status(self):
        pr = M.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        ss = pr["host_info"].get("server_status")
        self.assertIsInstance(ss, dict)
        self.assertEqual(ss["host"], "prod-db-01.internal.example:27017")
        self.assertEqual(ss["process"], "mongod")
        self.assertEqual(ss["pid"], 4271)
        self.assertEqual(ss["uptime"], 8642)
        self.assertEqual(ss["version"], "6.0.1")
        self.assertEqual(ss["localTime"], "2026-08-30T14:22:07Z")

    def test_finding_promoted_to_t2_with_evidence_in_detail(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        hf = [f for f in fs if f["kind"] == "mongo_hostinfo"]
        self.assertTrue(hf, "hostinfo finding should still emit")
        f = hf[0]
        self.assertEqual(f["depth_tier"], "t2")
        # Title / severity unchanged per the promotion rules.
        self.assertEqual(f["severity"], "medium")
        self.assertIn("hostInfo", f["title"])
        # Corroborating evidence baked into detail so the tester sees WHAT the
        # T2 probe actually found.
        self.assertIn("serverStatus", f["detail"])
        self.assertIn("prod-db-01.internal.example:27017", f["detail"])
        self.assertIn("mongod", f["detail"])
        self.assertIn("4271", f["detail"])


class MongoHostInfoStaysT1WhenServerStatusDenied(unittest.TestCase):
    """When hostInfo answers but serverStatus is denied (patched RBAC / lower
    privilege), the T1 finding still emits and depth_tier stays at t1 — the
    T2 probe went quiet."""

    def setUp(self):
        replies = _base_replies()
        replies["hostInfo"] = M.bson_doc(
            _e_doc("system", M.bson_doc(
                M._e_str("hostname", "svr01.corp.local"))),
            _e_doc("os", M.bson_doc(
                M._e_str("type", "Linux"),
                M._e_str("name", "RHEL"))),
            _e_double("ok", 1.0))
        replies["serverStatus"] = M.bson_doc(
            M._e_int32("code", 13),
            M._e_str("errmsg", "not authorized on admin to execute "
                     "command { serverStatus: 1 }"),
            _e_double("ok", 0.0))
        self.port = _serve(replies)

    def test_server_status_absent_when_denied(self):
        pr = M.probe("127.0.0.1", self.port)
        self.assertNotIn("server_status", pr.get("host_info") or {})

    def test_finding_stays_t1(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        hf = [f for f in fs if f["kind"] == "mongo_hostinfo"]
        self.assertTrue(hf, "T1 finding must still emit when T2 probe stays quiet")
        f = hf[0]
        self.assertEqual(f["depth_tier"], "t1")
        self.assertIn("svr01.corp.local", f["detail"])
        # No corroboration text when the T2 probe didn't fire.
        self.assertNotIn("serverStatus", f["detail"])


class MongoHostInfoT2CleanTimeout(unittest.TestCase):
    """A hung serverStatus (server accepts hostInfo, then never replies to
    serverStatus) must time out cleanly: the T1 finding still emits, depth
    stays t1, and probe() returns without raising."""

    def setUp(self):
        replies = _base_replies()
        replies["hostInfo"] = M.bson_doc(
            _e_doc("system", M.bson_doc(
                M._e_str("hostname", "slow-node.example"))),
            _e_doc("os", M.bson_doc(
                M._e_str("type", "Linux"),
                M._e_str("name", "Debian"))),
            _e_double("ok", 1.0))
        # Custom handler: replies to hello/buildInfo/listDatabases/hostInfo
        # normally, then goes silent for serverStatus so the socket read hits
        # the timeout.
        unknown = M.bson_doc(M._e_str("errmsg", "no such command"),
                             _e_double("ok", 0.0))

        def handle(conn):
            while True:
                hdr = M._recvn(conn, 16)
                if len(hdr) < 16:
                    return
                length = struct.unpack("<i", hdr[:4])[0]
                rid = struct.unpack("<i", hdr[4:8])[0]
                body = M._recvn(conn, length - 16)
                doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                cmd = next(iter(doc), "")
                if cmd == "serverStatus":
                    # Hang: swallow the request, never reply. Client-side
                    # bounded timeout has to unstick this.
                    return
                conn.sendall(M.op_msg(rid, replies.get(cmd, unknown)))
        self.port = _tcp_once(handle)

    def test_probe_returns_cleanly_and_stays_t1(self):
        pr = M.probe("127.0.0.1", self.port, timeout=1.0)
        self.assertIsInstance(pr, dict)
        self.assertTrue(pr.get("unauth"))
        # hostInfo evidence is still there; serverStatus corroboration is not.
        self.assertEqual(pr["host_info"].get("hostname"), "slow-node.example")
        self.assertNotIn("server_status", pr["host_info"])
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        hf = [f for f in fs if f["kind"] == "mongo_hostinfo"]
        self.assertTrue(hf)
        self.assertEqual(hf[0]["depth_tier"], "t1")


class MongoStartupWarnings(unittest.TestCase):
    """getLog:'startupWarnings' -> warning lines captured + finding emitted."""

    def setUp(self):
        replies = _base_replies()
        # BSON arrays store elements as a subdocument with string keys "0","1",...
        # so a string array is `\x04 <name>\0 <bson_doc containing "0"->str, "1"->str>`.
        log_array = (b"\x04" + M._cstr("log")
                     + M.bson_doc(
                         M._e_str("0",
                                  "** WARNING: Access control is not enabled "
                                  "for the database. Read and write access to "
                                  "data and configuration is unrestricted."),
                         M._e_str("1",
                                  "** WARNING: This server is bound to "
                                  "localhost. Remote systems will be unable "
                                  "to connect to this server."),
                         M._e_str("2",
                                  "** WARNING: soft rlimits too low. rlimits "
                                  "set to 1024 processes, 64000 files."),
                     ))
        replies["getLog"] = M.bson_doc(
            M._e_int32("totalLinesWritten", 3),
            _e_double("ok", 1.0),
            log_array,
        )
        self.port = _serve(replies)

    def test_probe_captures_warnings(self):
        pr = M.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        warns = pr.get("startup_warnings") or []
        self.assertEqual(len(warns), 3)
        self.assertTrue(any("Access control is not enabled" in w for w in warns))
        self.assertTrue(any("bound to localhost" in w for w in warns))

    def test_finding_emitted(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        wf = [f for f in fs if f["kind"] == "mongo_startup_warnings"]
        self.assertTrue(wf)
        self.assertIn("Access control is not enabled", wf[0]["detail"])
        self.assertEqual(wf[0]["severity"], "medium")
        self.assertIn("CWE-532", wf[0]["cwes"])


class MongoStartupWarningsSubFindings(unittest.TestCase):
    """Startup warnings are classified into typed sub-findings (auth-off,
    bind-all, THP) so the tester tracks each misconfig individually. Pure
    parsing over the already-captured `startup_warnings` list — no new
    network — and the generic mongo_startup_warnings finding is preserved."""

    def setUp(self):
        # Wire-realistic real-mongod startup lines. All three categories
        # (auth-off, all-interfaces bind, THP) are present so each sub-
        # finding must fire exactly once. RFC/wire fixtures: these strings
        # come straight from the mongod source's warning generators.
        log_array = (b"\x04" + M._cstr("log")
                     + M.bson_doc(
                         M._e_str("0",
                                  "** WARNING: Access control is not enabled "
                                  "for the database. Read and write access to "
                                  "data and configuration is unrestricted."),
                         M._e_str("1",
                                  "** WARNING: This server is bound to "
                                  "0.0.0.0. Remote systems will be able to "
                                  "connect to this server."),
                         M._e_str("2",
                                  "** WARNING: /sys/kernel/mm/transparent_"
                                  "hugepage/enabled is 'always'. We suggest "
                                  "setting it to 'never'."),
                         M._e_str("3",
                                  "** WARNING: soft rlimits too low."),
                     ))
        replies = _base_replies()
        replies["getLog"] = M.bson_doc(
            M._e_int32("totalLinesWritten", 4),
            _e_double("ok", 1.0),
            log_array,
        )
        self.port = _serve(replies)

    def test_all_three_categories_emit(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        kinds = [f["kind"] for f in fs]
        # Generic finding is preserved (additive contract).
        self.assertIn("mongo_startup_warnings", kinds)
        # Each specific category fires exactly once.
        for expect in ("mongo_misconfig_auth_off",
                       "mongo_misconfig_bind_all",
                       "mongo_misconfig_thp"):
            self.assertEqual(kinds.count(expect), 1,
                             f"expected exactly one {expect} finding")
        # Every sub-finding is medium, T1, tagged with expected CWEs, and
        # carries an exploit_note (tester_next_step) plus the matched line.
        by_kind = {f["kind"]: f for f in fs}
        auth = by_kind["mongo_misconfig_auth_off"]
        self.assertEqual(auth["severity"], "medium")
        self.assertEqual(auth["depth_tier"], "t1")
        self.assertIn("CWE-306", auth["cwes"])
        self.assertTrue(auth.get("exploit_note"))
        self.assertIn("Access control is not enabled", auth["detail"])
        bind = by_kind["mongo_misconfig_bind_all"]
        self.assertEqual(bind["severity"], "medium")
        self.assertIn("CWE-668", bind["cwes"])
        self.assertIn("0.0.0.0", bind["detail"])
        thp = by_kind["mongo_misconfig_thp"]
        self.assertEqual(thp["severity"], "medium")
        self.assertIn("CWE-1188", thp["cwes"])
        self.assertIn("transparent_hugepage", thp["detail"])


class MongoStartupWarningsNoSubFindingsWhenBenign(unittest.TestCase):
    """When the startup log carries only benign / unrecognised lines (server
    patched / hardened), the generic finding still emits from the warnings
    list but NO typed sub-findings appear — the classifier must not
    fabricate misconfigs it didn't see."""

    def setUp(self):
        log_array = (b"\x04" + M._cstr("log")
                     + M.bson_doc(
                         M._e_str("0",
                                  "** WARNING: soft rlimits too low. "
                                  "rlimits set to 1024 processes, 64000 files."),
                     ))
        replies = _base_replies()
        replies["getLog"] = M.bson_doc(
            M._e_int32("totalLinesWritten", 1),
            _e_double("ok", 1.0),
            log_array,
        )
        self.port = _serve(replies)

    def test_only_generic_finding_emits(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("mongo_startup_warnings", kinds)
        for absent in ("mongo_misconfig_auth_off",
                       "mongo_misconfig_bind_all",
                       "mongo_misconfig_thp"):
            self.assertNotIn(absent, kinds,
                             f"{absent} must not fabricate when line absent")


class MongoStartupWarningsSubFindingsDedupe(unittest.TestCase):
    """A real mongod restart log often repeats the same warning verbatim (or
    with a fresh timestamp) across several lines. Each recognised category
    must fire at MOST once — duplicate lines are collapsed."""

    def setUp(self):
        log_array = (b"\x04" + M._cstr("log")
                     + M.bson_doc(
                         M._e_str("0",
                                  "** WARNING: Access control is not enabled "
                                  "for the database."),
                         M._e_str("1",
                                  "** WARNING: Access control is not enabled "
                                  "for the database."),
                         M._e_str("2",
                                  "** WARNING: Access control is not enabled "
                                  "for the database."),
                     ))
        replies = _base_replies()
        replies["getLog"] = M.bson_doc(
            M._e_int32("totalLinesWritten", 3),
            _e_double("ok", 1.0),
            log_array,
        )
        self.port = _serve(replies)

    def test_single_finding_per_category(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        auth_hits = [f for f in fs if f["kind"] == "mongo_misconfig_auth_off"]
        self.assertEqual(len(auth_hits), 1,
                         "duplicated warning lines must collapse to one finding")


class MongoStartupWarningsClassifierUnit(unittest.TestCase):
    """Pure-function unit test of the classifier — no sockets, no wire — to
    pin the regex behaviour independently of the probe path."""

    def test_recognises_expected_categories(self):
        lines = [
            "** WARNING: Access control is not enabled for the database.",
            "** WARNING: bindIpAll is true; listening on all interfaces.",
            "** WARNING: /sys/kernel/mm/transparent_hugepage/enabled is 'always'.",
        ]
        got = {t[0] for t in M._classify_startup_warnings(lines)}
        self.assertEqual(got, {"mongo_misconfig_auth_off",
                               "mongo_misconfig_bind_all",
                               "mongo_misconfig_thp"})

    def test_empty_and_non_list_input_safe(self):
        self.assertEqual(M._classify_startup_warnings([]), [])
        self.assertEqual(M._classify_startup_warnings(None), [])  # type: ignore[arg-type]
        # Non-string entries must be ignored, not raise.
        self.assertEqual(M._classify_startup_warnings([123, None, {}]), [])

    def test_unrecognised_lines_produce_nothing(self):
        lines = ["** WARNING: soft rlimits too low.",
                 "** WARNING: mongod is running as root.",
                 "info line, not a warning"]
        self.assertEqual(M._classify_startup_warnings(lines), [])


class MongoClusterKeyfileExtraction(unittest.TestCase):
    """local.system.keys read -> __system credential harvested + critical finding."""

    def setUp(self):
        replies = _base_replies()
        # replSetGetStatus so we get member relay targets in the credential note
        replies["replSetGetStatus"] = M.bson_doc(
            M._e_str("set", "rs0"),
            _e_array("members", [
                M.bson_doc(M._e_str("name", "mongo1:27017")),
                M.bson_doc(M._e_str("name", "mongo2:27017")),
            ]),
            _e_double("ok", 1.0))
        # local.system.keys find: two keys, both with 32-byte HMAC-SHA-256 material
        key_a = b"A" * 32
        key_b = b"B" * 32
        keys_batch = M.bson_doc(
            _e_doc("cursor", M.bson_doc(
                _e_array("firstBatch", [
                    M.bson_doc(_e_int64("_id", 7101234567890123456),
                               M._e_str("purpose", "HMAC"),
                               _e_binary_gen("key", key_a),
                               _e_int64("expiresAt", 1893456000000)),
                    M.bson_doc(_e_int64("_id", 7101234567890123457),
                               M._e_str("purpose", "HMAC"),
                               _e_binary_gen("key", key_b),
                               _e_int64("expiresAt", 1893456000000)),
                ]))),
            _e_double("ok", 1.0))
        # `find` is dispatched by command name — but datamine also sends `find`
        # for user collections; we only expect the keyfile one here because
        # this fake instance advertises an empty user collection list. Return
        # the keys batch for any `find` and rely on the assertions to check
        # cluster_keys was populated.
        replies["find"] = keys_batch
        self.port = _serve(replies)

    def test_probe_captures_cluster_keys(self):
        pr = M.probe("127.0.0.1", self.port)
        keys = pr.get("cluster_keys") or []
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[0]["purpose"], "HMAC")
        self.assertEqual(keys[0]["key_len"], 32)
        # base64 of 32 bytes of 'A' == "QUFB..." len 44
        self.assertEqual(len(keys[0]["key_b64"]), 44)
        self.assertTrue(keys[0]["key_b64"].startswith("QUFB"))

    def test_finding_and_credential_emitted(self):
        pr = M.probe("127.0.0.1", self.port)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        ckf = [f for f in fs if f["kind"] == "mongo_cluster_keyfile"]
        self.assertTrue(ckf)
        self.assertEqual(ckf[0]["severity"], "critical")
        self.assertIn("CWE-798", ckf[0]["cwes"])
        self.assertIn("local.system.keys", ckf[0]["detail"])

    def test_analyze_emits_system_credential_with_relay_targets(self):
        h = _host(self.port)
        analysis = M.analyze([h], creds=None)
        creds = analysis["credentials"]
        keyfile_creds = [c for c in creds if c.source == "mongodb-keyfile"]
        self.assertTrue(keyfile_creds, "expected __system keyfile credential in loot")
        c = keyfile_creds[0]
        self.assertEqual(c.username, "__system")
        self.assertTrue(c.secret, "cred secret (base64 key) must be non-empty")
        # relay target list is populated from replset_members
        self.assertIn("mongo1:27017", c.notes)
        self.assertIn("mongo2:27017", c.notes)


class MongoAdditionsSilentOnLockedInstance(unittest.TestCase):
    """When every command returns 'not authorized', the new additions must not
    fabricate host_info / startup_warnings / cluster_keys — the fields stay absent
    and no spurious findings appear."""

    def setUp(self):
        # hello succeeds so it fingerprints as MongoDB, but listDatabases fails.
        hello = M.bson_doc(M._e_int32("maxWireVersion", 17), _e_double("ok", 1.0))
        build = M.bson_doc(M._e_str("version", "6.0.1"), _e_double("ok", 1.0))
        deny = M.bson_doc(_e_double("ok", 0.0), M._e_int32("code", 13),
                          M._e_str("errmsg", "not authorized"))

        def handle(conn):
            while True:
                hdr = M._recvn(conn, 16)
                if len(hdr) < 16:
                    return
                length = struct.unpack("<i", hdr[:4])[0]
                rid = struct.unpack("<i", hdr[4:8])[0]
                body = M._recvn(conn, length - 16)
                doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                cmd = next(iter(doc), "")
                if cmd == "hello":
                    conn.sendall(M.op_msg(rid, hello))
                elif cmd == "buildInfo":
                    conn.sendall(M.op_msg(rid, build))
                else:
                    conn.sendall(M.op_msg(rid, deny))
        self.port = _tcp_once(handle)

    def test_no_new_fields_or_findings(self):
        pr = M.probe("127.0.0.1", self.port)
        # unauth path is not taken (listDatabases errored) so _deep_mongo never
        # ran and none of the new keys should be present.
        self.assertFalse(pr.get("unauth"))
        self.assertNotIn("host_info", pr)
        self.assertNotIn("startup_warnings", pr)
        self.assertNotIn("cluster_keys", pr)
        fs = M.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        for kind in ("mongo_hostinfo", "mongo_startup_warnings",
                     "mongo_cluster_keyfile"):
            self.assertNotIn(kind, {f["kind"] for f in fs})


if __name__ == "__main__":
    unittest.main()
