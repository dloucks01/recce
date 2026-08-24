"""Every services/db/<engine>.py must conform to the DbEngine Protocol.

Rationale: 12 engine modules share a de-facto contract (probe / analyze /
findings / findings_to_vulns) that the CLI + workbook dispatch layers
call by name. Nothing at import time enforces this — a rename or typo
in one engine wouldn't surface until a runtime call. This test walks
the dispatch table and asserts every engine still exposes the contract.

If you add a new DB engine, adding it here is the only test change
needed — the shape check does the rest.
"""
from __future__ import annotations

import importlib
import inspect
import unittest


# Every engine that's dispatched from services/db/__init__.DB_PORTS
# (the "postgresql" entry maps to the module named "postgres" — the only
# name mismatch in the tree).
ENGINE_MODULES = [
    "mysql", "postgres", "mssql", "mongodb", "oracle", "db2",
    "redis", "memcached", "cassandra", "couchdb", "elasticsearch", "influxdb",
]

# Public functions every engine must expose. See services/db/base.py DbEngine
# Protocol for the semantics. `probe` intentionally NOT required — each engine
# has an internal read-only detection function but their names vary (probe /
# probe_target / probe_creds), so we only enforce the DISPATCHED surface.
REQUIRED_FUNCTIONS = {
    "analyze":          {"min_positional": 1},   # hosts + optional creds/active
    "findings":         {"min_positional": 1},   # hosts + optional probes
    "findings_to_vulns": {"min_positional": 1},  # findings list -> dict
}


class DbEngineContractTest(unittest.TestCase):
    def _load(self, name: str):
        return importlib.import_module(f"recce.services.db.{name}")

    def test_every_engine_module_imports(self):
        """Every dispatch target actually exists as a submodule."""
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                self._load(name)

    def test_every_engine_has_some_probe_function(self):
        """Each engine has an internal read-only detection function, but
        naming varies (probe / probe_target / probe_creds). Assert that
        SOMETHING probe-ish exists — a callable whose name contains 'probe'."""
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                mod = self._load(name)
                probe_fns = [n for n in dir(mod)
                             if "probe" in n and callable(getattr(mod, n))
                             and not n.startswith("_")]
                self.assertTrue(probe_fns,
                    f"{name} exposes no probe-* function (probe/probe_target/probe_creds)")

    def test_every_engine_exposes_analyze(self):
        """`analyze(hosts, creds=None, active=True)` — the top-level entry."""
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                mod = self._load(name)
                self.assertTrue(callable(getattr(mod, "analyze", None)),
                                f"{name}.analyze is missing or not callable")

    def test_every_engine_exposes_findings(self):
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                mod = self._load(name)
                self.assertTrue(callable(getattr(mod, "findings", None)),
                                f"{name}.findings is missing or not callable")

    def test_every_engine_exposes_findings_to_vulns(self):
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                mod = self._load(name)
                self.assertTrue(callable(getattr(mod, "findings_to_vulns", None)),
                                f"{name}.findings_to_vulns is missing or not callable")

    def test_every_engine_has_is_engine_predicate(self):
        """Each engine exposes `is_<engine>(port) -> bool` for dispatch classification.
        Naming quirk: postgres.py's predicate is `is_postgres` (matches the module
        name, not the DB_PORTS value 'postgresql')."""
        for name in ENGINE_MODULES:
            with self.subTest(engine=name):
                mod = self._load(name)
                pred = getattr(mod, f"is_{name}", None)
                self.assertTrue(callable(pred),
                                f"{name}.is_{name}(port) is missing or not callable")

    def test_engine_names_in_dispatch_map(self):
        """DB_PORTS values must line up with actual engine modules. Prevents a
        typo in the dispatcher that would silently fail to detect a service."""
        from recce.services.db import DB_PORTS, _NAME_HINTS
        # postgresql dispatch value → postgres module (documented alias)
        aliases = {"postgresql": "postgres"}
        for value in set(DB_PORTS.values()) | set(_NAME_HINTS.values()):
            resolved = aliases.get(value, value)
            with self.subTest(dispatch=value, resolved=resolved):
                self.assertIn(resolved, ENGINE_MODULES,
                              f"DB_PORTS/NAME_HINTS references '{value}' "
                              f"but no matching engine module exists")


class DbBaseHelpersTest(unittest.TestCase):
    """The shared helpers in services/db/base.py have simple contracts —
    verify they behave as documented so migrated engines can rely on them."""

    def test_recvn_returns_full_buffer(self):
        from recce.services.db.base import recvn
        # Fake socket that emits data in two chunks.
        class FakeSock:
            def __init__(self, data): self.data = data; self.pos = 0
            def recv(self, n):
                out = self.data[self.pos:self.pos + n]
                self.pos += len(out)
                return out
        s = FakeSock(b"hello world")
        self.assertEqual(recvn(s, 5), b"hello")
        self.assertEqual(recvn(s, 6), b" world")

    def test_recvn_short_read_on_eof(self):
        """EOF-before-N: return the partial buffer (mysql/postgres contract)."""
        from recce.services.db.base import recvn
        class EOFSock:
            def recv(self, n): return b""   # immediate EOF
        self.assertEqual(recvn(EOFSock(), 10), b"")

    def test_cred_list_normalizes_dict_and_list(self):
        from recce.services.db.base import cred_list
        # single dict -> one tuple
        self.assertEqual(cred_list({"user": "alice", "password": "hunter2"}),
                         [("alice", "hunter2")])
        # list of dicts -> multi
        self.assertEqual(cred_list([
            {"username": "bob", "secret": "pw1"},
            {"user": "carol", "password": "pw2"},
        ]), [("bob", "pw1"), ("carol", "pw2")])

    def test_cred_list_dedupes(self):
        from recce.services.db.base import cred_list
        r = cred_list([{"user": "a", "password": "b"},
                       {"user": "a", "password": "b"}])
        self.assertEqual(r, [("a", "b")])

    def test_cred_list_drops_incomplete(self):
        from recce.services.db.base import cred_list
        r = cred_list([{"user": "a"},                # no password
                       {"password": "b"},            # no user
                       {"user": "c", "password": "d"}])
        self.assertEqual(r, [("c", "d")])

    def test_cred_list_empty(self):
        from recce.services.db.base import cred_list
        self.assertEqual(cred_list(None), [])
        self.assertEqual(cred_list([]), [])
        self.assertEqual(cred_list({}), [])

    def test_finding_shape(self):
        from recce.services.db.base import finding
        f = finding("mytool", "high", "T", "10.0.0.1", "detail", "cmd", "rem", ["CWE-1"])
        self.assertEqual(f["tool"], "mytool")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["title"], "T")
        self.assertEqual(f["target"], "10.0.0.1")
        self.assertEqual(f["cwes"], ["CWE-1"])
        self.assertEqual(f["kind"], "")   # default

    def test_dbengine_protocol_runtime_check(self):
        """DbEngine is @runtime_checkable — isinstance() should hold for
        every engine module. This is the strictest form of the contract check."""
        from recce.services.db.base import DbEngine
        for name in ENGINE_MODULES:
            mod = importlib.import_module(f"recce.services.db.{name}")
            with self.subTest(engine=name):
                self.assertIsInstance(mod, DbEngine,
                    f"{name} does not satisfy DbEngine Protocol")


if __name__ == "__main__":
    unittest.main()
