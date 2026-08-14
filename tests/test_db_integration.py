"""Real-server integration for the MySQL + PostgreSQL deep modules.

Stands up an actual trust-auth PostgreSQL and an actual empty-password MariaDB in
throwaway data dirs and drives the REAL probes against them - positive (unauth) and
negative (password required) - so the wire protocol is exercised end to end, not
mocked. Skips cleanly when the server binaries aren't installed.

Auto-marked `slow` (see tests/conftest.py); run with `pytest -m slow`.
"""
from __future__ import annotations

import glob
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from recce import mysql, postgres


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port: int, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _pg_bindir():
    for d in sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if os.path.exists(os.path.join(d, "initdb")):
            return d
    return None


@unittest.skipUnless(_pg_bindir(), "PostgreSQL server binaries not installed")
class PostgresRealServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bindir = _pg_bindir()
        cls.datadir = tempfile.mkdtemp(prefix="recce_pg_")
        # unix socket path has a 107-byte limit -> keep it short, outside the data dir
        cls.sock = tempfile.mkdtemp(prefix="rpg_", dir="/tmp")
        cls.port = _free_port()
        subprocess.run([os.path.join(cls.bindir, "initdb"), "-D", cls.datadir,
                        "-U", "postgres", "--auth-host=trust", "--auth-local=trust"],
                       check=True, capture_output=True)
        with open(os.path.join(cls.datadir, "pg_hba.conf"), "a") as f:
            f.write("\nhost all all 127.0.0.1/32 trust\n")
        cls._pgctl("start", "-w")
        assert _wait_port(cls.port), "postgres did not come up"

    @classmethod
    def _pgctl(cls, *args):
        opts = (f"-p {cls.port} -c listen_addresses=127.0.0.1 "
                f"-c unix_socket_directories={cls.sock}")
        subprocess.run([os.path.join(cls.bindir, "pg_ctl"), "-D", cls.datadir,
                        "-o", opts, *args], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls._pgctl("stop", "-m", "immediate")
        shutil.rmtree(cls.datadir, ignore_errors=True)
        shutil.rmtree(cls.sock, ignore_errors=True)

    def test_trust_auth_detected_then_scram_not_flagged(self):
        pr = postgres.probe("127.0.0.1", self.port, timeout=5)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"], f"trust auth not detected: {pr}")
        self.assertTrue(pr["version"])

        # now require a password and confirm NO false positive
        psql = os.path.join(self.bindir, "psql")
        subprocess.run([psql, f"host=127.0.0.1 port={self.port} user=postgres dbname=postgres",
                        "-c", "ALTER USER postgres PASSWORD 'secret'"], capture_output=True)
        hba = os.path.join(self.datadir, "pg_hba.conf")
        text = open(hba).read().replace("127.0.0.1/32            trust",
                                        "127.0.0.1/32            scram-sha-256")
        text = text.replace("127.0.0.1/32 trust", "127.0.0.1/32 scram-sha-256")
        open(hba, "w").write(text)
        self._pgctl("reload")
        time.sleep(1.0)
        pr2 = postgres.probe("127.0.0.1", self.port, timeout=5)
        self.assertFalse(pr2["unauth"], f"password-required pg flagged as trust: {pr2}")
        self.assertTrue(pr2["auth_required"])


def _mariadb_tools():
    install = shutil.which("mariadb-install-db") or shutil.which("mysql_install_db")
    server = shutil.which("mariadbd") or "/usr/sbin/mariadbd"
    if not os.path.exists(server):
        server = shutil.which("mysqld") or "/usr/sbin/mysqld"
    client = shutil.which("mariadb") or shutil.which("mysql")
    if install and os.path.exists(server) and client:
        return install, server, client
    return None


@unittest.skipUnless(_mariadb_tools(), "MariaDB/MySQL server binaries not installed")
class MysqlRealServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install, cls.server, cls.client = _mariadb_tools()
        cls.datadir = tempfile.mkdtemp(prefix="recce_my_")
        cls.sock = os.path.join(tempfile.mkdtemp(prefix="rmy_", dir="/tmp"), "m.sock")
        cls.port = _free_port()
        subprocess.run([cls.install, f"--datadir={cls.datadir}",
                        "--auth-root-authentication-method=normal", "--skip-test-db",
                        f"--socket={cls.sock}"], check=True, capture_output=True)
        # --skip-name-resolve => 127.0.0.1 matches ONLY root@'127.0.0.1' (deterministic)
        cls.proc = subprocess.Popen(
            [cls.server, f"--datadir={cls.datadir}", f"--socket={cls.sock}",
             f"--port={cls.port}", "--bind-address=127.0.0.1", "--skip-name-resolve",
             f"--pid-file={cls.datadir}/my.pid"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert _wait_port(cls.port), "mariadb did not come up"
        cls._sql("CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY ''; "
                 "GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1'; FLUSH PRIVILEGES;")

    @classmethod
    def _sql(cls, stmt):
        subprocess.run([cls.client, f"--socket={cls.sock}", "-u", "root", "-e", stmt],
                       capture_output=True)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=10)
        except Exception:
            cls.proc.kill()
        shutil.rmtree(cls.datadir, ignore_errors=True)
        try:
            os.unlink(cls.sock)
        except OSError:
            pass

    def test_empty_password_detected_then_password_not_flagged(self):
        pr = mysql.probe("127.0.0.1", self.port, timeout=5)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"], f"empty-password login not detected: {pr}")
        self.assertTrue(pr["version"])

        self._sql("SET PASSWORD FOR 'root'@'127.0.0.1' = PASSWORD('secret'); FLUSH PRIVILEGES;")
        time.sleep(0.5)
        pr2 = mysql.probe("127.0.0.1", self.port, timeout=5)
        self.assertFalse(pr2["unauth"], f"password-protected mysql flagged as empty: {pr2}")
        self.assertTrue(pr2["auth_required"])


if __name__ == "__main__":
    unittest.main()
