"""Coverage-boosting tests for the gated active-attack layer of
recce.services.telnet: try_login, default_cred_sweep, solaris_dashf_bypass,
timing_user_enum, and the analyze() active_attacks fold-in.

The existing tests/test_telnet.py covers the pre-auth IAC negotiator, the
encrypt-probe T2 path, findings, and the gate-off refuse path — this file
drives the gate-on paths through a scripted fake telnet server.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import unittest

from recce.core.models import Host, Port
from recce.services import telnet


# --- wire fixtures ---------------------------------------------------------

IAC_WILL_ECHO = bytes.fromhex("fffb01")
IAC_WILL_SUPPRESS_GA = bytes.fromhex("fffb03")

LOGIN_PROMPT = b"\r\nlab-router login: "
PASSWORD_PROMPT = b"Password: "
SHELL_PROMPT = b"\r\nlab-router# "
FAIL_LINE = b"\r\nLogin incorrect\r\n"


class _ScriptedTelnetServer:
    """Fake telnet server that follows a scripted request/response flow.

    The `script` is a list of send-bytes chunks. The server sends the
    first chunk immediately after accept (the pre-auth IAC + banner),
    then for every subsequent chunk waits until it has received at
    least one \\n-terminated line from the client before sending. This
    matches the shape of recce.try_login: initial-read → reply → send
    username → send password → …
    """
    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self.recv_log = bytearray()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                self._handle(conn)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def _handle(self, conn):
        conn.settimeout(2.0)
        for i, chunk in enumerate(self._chunks):
            if i > 0:
                # Wait for a client line before answering. This synchronises
                # sends with reads so a login prompt lands AFTER the client
                # has consumed the pre-auth options.
                _wait_line(conn, self.recv_log)
            try:
                conn.sendall(chunk)
            except OSError:
                return
        # Drain anything the client still writes so it does not RST.
        try:
            deadline = time.monotonic() + 0.8
            while time.monotonic() < deadline:
                conn.settimeout(0.3)
                try:
                    extra = conn.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not extra:
                    break
                self.recv_log.extend(extra)
        except OSError:
            pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


def _wait_line(conn, log: bytearray) -> bytes:
    """Read from `conn` until we see a \\n (client's line-terminated
    input) or the socket goes quiet. Appends everything read to `log`."""
    deadline = time.monotonic() + 1.5
    buf = bytearray()
    while time.monotonic() < deadline:
        try:
            conn.settimeout(min(0.3, deadline - time.monotonic()))
            chunk = conn.recv(4096)
        except (socket.timeout, OSError):
            # Also break out when we already have some data waiting.
            if b"\n" in buf:
                break
            continue
        if not chunk:
            break
        buf.extend(chunk)
        log.extend(chunk)
        if b"\n" in buf:
            break
    return bytes(buf)


# --- try_login: success + failure + saw_password branches -------------------

class TryLoginTest(unittest.TestCase):
    def test_success_reaches_prompt(self):
        # Chunk 0: initial IAC options only. Chunk 1: LOGIN_PROMPT after
        # the client sends its option-reply line. Chunk 2: PASSWORD after
        # the username. Chunk 3: shell prompt after the password.
        chunks = [
            IAC_WILL_ECHO + IAC_WILL_SUPPRESS_GA,
            LOGIN_PROMPT,
            PASSWORD_PROMPT,
            SHELL_PROMPT,
        ]
        srv = _ScriptedTelnetServer(chunks)
        try:
            r = telnet.try_login(srv.host, srv.port, "admin", "admin",
                                 timeout=4)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertTrue(r["saw_login"])
        self.assertTrue(r["saw_password"])
        self.assertTrue(r["success"])
        self.assertIn(b"admin\r\n", bytes(srv.recv_log))

    def test_failure_records_incorrect(self):
        chunks = [
            IAC_WILL_ECHO,
            LOGIN_PROMPT,
            PASSWORD_PROMPT,
            FAIL_LINE + LOGIN_PROMPT,
        ]
        srv = _ScriptedTelnetServer(chunks)
        try:
            r = telnet.try_login(srv.host, srv.port, "root", "wrong",
                                 timeout=4)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertTrue(r["saw_login"])
        self.assertTrue(r["saw_password"])
        self.assertFalse(r["success"])

    def test_dead_port_returns_reachable_false(self):
        r = telnet.try_login("127.0.0.1", 1, "x", "y", timeout=1)
        self.assertFalse(r["reachable"])
        self.assertFalse(r["success"])
        self.assertIn("connect failed", r["evidence"])


# --- default_cred_sweep gated ON --------------------------------------------

class DefaultCredSweepGatedOnTest(unittest.TestCase):
    def test_active_attacks_true_runs_sweep_and_hits_first_match(self):
        """With active_attacks=True the sweep iterates the vendor's default
        pair list. Serve a scripted 'success' only when the first pair is
        offered, everything else fails — the first hit stops the sweep."""
        vendor = "unknown"
        creds = telnet._VENDOR_DEFAULTS.get(vendor) or []
        self.assertTrue(creds, "vendor table shape changed unexpectedly")
        wanted_user, wanted_pwd = creds[0]

        seen: list[tuple[bytes, bytes]] = []
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        host, port = srv.getsockname()
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                srv.settimeout(0.3)
                try:
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(6.0)             # allow try_login's timers
                    # Match try_login's expected shape: IAC options first,
                    # then LOGIN prompt only after the client answers.
                    conn.sendall(IAC_WILL_ECHO)
                    _wait_line(conn, bytearray())    # client sends replies
                    conn.sendall(LOGIN_PROMPT)
                    user_line = _readline(conn)
                    conn.sendall(PASSWORD_PROMPT)
                    pwd_line = _readline(conn)
                    seen.append((user_line, pwd_line))
                    user = user_line.rstrip(b"\r\n")
                    pwd = pwd_line.rstrip(b"\r\n")
                    if (user == wanted_user.encode() and
                            pwd == wanted_pwd.encode()):
                        conn.sendall(SHELL_PROMPT)
                    else:
                        conn.sendall(FAIL_LINE + LOGIN_PROMPT)
                except OSError:
                    pass
                finally:
                    try: conn.close()
                    except OSError: pass

        threading.Thread(target=serve, daemon=True).start()
        try:
            hits = telnet.default_cred_sweep(host, port, vendor, timeout=4,
                                             active_attacks=True)
        finally:
            stop.set()
            try: srv.close()
            except OSError: pass

        self.assertTrue(hits, "expected at least one hit against the "
                              "scripted server")
        self.assertEqual(hits[0]["user"], wanted_user)
        self.assertEqual(hits[0]["password"], wanted_pwd)


def _readline(conn) -> bytes:
    """Read from `conn` until we see a \\n or the socket closes / times out."""
    buf = bytearray()
    while b"\n" not in buf:
        try:
            chunk = conn.recv(1024)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


# --- solaris_dashf_bypass gated ON ------------------------------------------

class SolarisDashFTest(unittest.TestCase):
    def test_gate_on_calls_try_login_with_dash_f_prefix(self):
        """With active_attacks=True, solaris_dashf_bypass MUST prepend
        '-f' to the username and pass empty password — the exact primitive
        CVE-2007-0882 exploits. try_login itself is exercised elsewhere;
        here we intercept it to make the timing deterministic."""
        captured: dict = {}

        def fake_try_login(ip, port, user, pwd, timeout=6.0):
            captured["ip"] = ip
            captured["port"] = port
            captured["user"] = user
            captured["pwd"] = pwd
            # Simulate a successful bypass: the CVE-2007-0882 primitive
            # never sees a password prompt because auth is skipped.
            return {"reachable": True, "saw_login": True,
                    "saw_password": False, "success": True,
                    "evidence": "SunOS 5.10 root#", "elapsed": 0.05}

        orig = telnet.try_login
        telnet.try_login = fake_try_login
        try:
            r = telnet.solaris_dashf_bypass("10.0.0.9", 23, username="root",
                                            timeout=2, active_attacks=True)
        finally:
            telnet.try_login = orig

        # Bypass injects the -f prefix and empty password.
        self.assertEqual(captured["user"], "-froot")
        self.assertEqual(captured["pwd"], "")
        self.assertFalse(r["gated"])
        self.assertTrue(r["success"])
        self.assertTrue(r["reachable"])

    def test_gate_off_returns_without_calling_try_login(self):
        # No env, no active_attacks=True -> returns gated result immediately
        # without touching the network. Existing GateTest covers env-absent;
        # this asserts try_login is genuinely NOT called.
        called = [False]

        def guard(*_a, **_kw):
            called[0] = True
            return {}

        prev_env = os.environ.pop("RECCE_ACTIVE_ATTACKS", None)
        orig = telnet.try_login
        telnet.try_login = guard
        try:
            r = telnet.solaris_dashf_bypass("10.0.0.9", 23, timeout=1)
        finally:
            telnet.try_login = orig
            if prev_env is not None:
                os.environ["RECCE_ACTIVE_ATTACKS"] = prev_env
        self.assertFalse(called[0])
        self.assertTrue(r["gated"])


# --- timing_user_enum -------------------------------------------------------

class TimingUserEnumTest(unittest.TestCase):
    def test_empty_candidates_returns_empty(self):
        # Fast path — no baseline probes get issued when candidates is [].
        self.assertEqual(telnet.timing_user_enum("127.0.0.1", 1, []), [])

    def test_valid_flag_set_when_candidate_elapsed_exceeds_baseline(self):
        """Baseline logins are fast (immediate PW prompt); the candidate
        gets a scripted 0.6s delay before the password prompt — enough to
        clear the 1.3x threshold."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        host, port = srv.getsockname()
        stop = threading.Event()
        candidate_user = b"admin"

        def serve():
            while not stop.is_set():
                srv.settimeout(0.3)
                try:
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(6.0)
                    conn.sendall(IAC_WILL_ECHO)
                    _wait_line(conn, bytearray())
                    conn.sendall(LOGIN_PROMPT)
                    user_line = _readline(conn).rstrip(b"\r\n")
                    if user_line == candidate_user:
                        time.sleep(0.6)     # simulate real-user work
                    conn.sendall(PASSWORD_PROMPT)
                    _ = _readline(conn)
                    conn.sendall(FAIL_LINE + LOGIN_PROMPT)
                except OSError:
                    pass
                finally:
                    try: conn.close()
                    except OSError: pass

        threading.Thread(target=serve, daemon=True).start()
        try:
            results = telnet.timing_user_enum(
                host, port, candidates=[candidate_user.decode()],
                baseline_users=["nope1", "nope2"], timeout=4)
        finally:
            stop.set()
            try: srv.close()
            except OSError: pass

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["user"], "admin")
        # elapsed >= baseline_avg * 1.3 → valid True
        self.assertGreater(results[0]["elapsed"],
                           results[0]["baseline_avg"] * 1.3)
        self.assertTrue(results[0]["valid"])


# --- analyze() with active_attacks=True fold-in -----------------------------

class AnalyzeActiveAttacksTest(unittest.TestCase):
    def test_active_attacks_triggers_default_cred_sweep_and_solaris(self):
        """analyze() with active_attacks=True runs default_cred_sweep and,
        when the vendor is 'solaris', solaris_dashf_bypass. Both get stubbed
        so we exercise the branch without a real login roundtrip."""
        h = Host(ip="10.0.0.9", ports=[Port(portid=23, service="telnet")])
        canned_probe = {
            "ip": "10.0.0.9", "port": 23,
            "banner": "SunOS 5.10\r\nlogin:",
            "options_will": [telnet.OPT_ECHO],
            "options_do": [], "options_wont": [], "options_dont": [],
            "encrypt_offered": False, "auth_offered": False,
            "environ_offered": False, "environ_leak": {},
            "vendor": "solaris", "vendor_desc": "Solaris/SunOS",
            "ntlm": {}, "ayt_ok": False, "tls": False,
            "looks_like_telnet": True,
        }
        default_hit = [{"user": "root", "password": "toor",
                        "evidence": "shell prompt reached", "elapsed": 0.1}]
        solaris_hit = {"success": True, "reachable": True, "gated": False,
                       "evidence": "prompt reached without password"}

        orig_probe = telnet.probe
        orig_ep = telnet.encrypt_probe
        orig_sweep = telnet.default_cred_sweep
        orig_solaris = telnet.solaris_dashf_bypass
        telnet.probe = lambda ip, port, use_tls=False: canned_probe
        telnet.encrypt_probe = lambda ip, port, use_tls=False: None
        telnet.default_cred_sweep = (
            lambda ip, port, vendor, timeout=6.0, active_attacks=None:
                default_hit)
        telnet.solaris_dashf_bypass = (
            lambda ip, port=23, username="root", timeout=6.0,
                   active_attacks=None: solaris_hit)
        try:
            out = telnet.analyze([h], active=True, active_attacks=True)
        finally:
            telnet.probe = orig_probe
            telnet.encrypt_probe = orig_ep
            telnet.default_cred_sweep = orig_sweep
            telnet.solaris_dashf_bypass = orig_solaris

        pr = list(out["probes"].values())[0]
        self.assertEqual(pr["default_creds"], default_hit)
        self.assertEqual(pr["solaris_dashf"], solaris_hit)
        # Findings must include the critical hits.
        kinds = [f["kind"] for f in out["findings"]]
        self.assertIn("telnet_default_creds", kinds)
        self.assertIn("telnet_solaris_dashf_rce", kinds)

    def test_active_attacks_env_var_gate(self):
        """RECCE_ACTIVE_ATTACKS=1 also flips the gate on — no explicit
        active_attacks= arg needed."""
        prev = os.environ.get("RECCE_ACTIVE_ATTACKS")
        os.environ["RECCE_ACTIVE_ATTACKS"] = "1"
        try:
            self.assertTrue(telnet._active_gate())
        finally:
            if prev is None:
                del os.environ["RECCE_ACTIVE_ATTACKS"]
            else:
                os.environ["RECCE_ACTIVE_ATTACKS"] = prev

    def test_active_off_leaves_probes_empty(self):
        h = Host(ip="10.0.0.9", ports=[Port(portid=23, service="telnet")])
        out = telnet.analyze([h], active=False, active_attacks=False)
        self.assertEqual(out["probes"], {})


if __name__ == "__main__":
    unittest.main()
