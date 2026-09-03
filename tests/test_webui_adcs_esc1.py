"""P1-7 — WebGUI endpoints for the ADCS ESC1 auto-request wrapper.

Covers the three protection layers on POST /api/adcs/esc1/attempt:

  1. missing / mistyped `confirm` sentinel — a boolean or "yes" alone
     must be rejected, only the exact confirm_sentinel string flies;
  2. no matching credential in the store — the endpoint MUST NOT
     accept a password from the request body, it looks up the AD
     principal in the recce store;
  3. certipy not installed — surfaces as a clean {ok: False, error:
     "certipy not installed"} rather than a 500.

Also covers the read-only /api/adcs/esc1/available snapshot.
"""
from __future__ import annotations

import os
import tempfile
import textwrap
import shutil
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Credential
from recce.core.store import Store
from recce.webui.app import create_app


def _write_fake_certipy(dirpath: str, script_body: str) -> str:
    """Same helper as tests/test_adcs_exploit.py — POSIX script that
    stands in for certipy. Returns the path so a caller can drop it on
    PATH and drive the endpoint through the real subprocess spawner."""
    path = os.path.join(dirpath, "certipy")
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\n" + textwrap.dedent(script_body))
    st = os.stat(path)
    os.chmod(path, st.st_mode | 0o111)
    return path


def _seed_engagement(eng: Path, add_ad_cred: bool = True):
    st = Store(_open_paths(str(eng))["db"])
    if add_ad_cred:
        st.add_credential(Credential(
            username="alice", secret="Password1!", kind="password",
            domain="corp.local", source="test-seed",
            origin_ip="10.0.0.10"))
        # Also seed a non-AD cred so we can prove available/matching
        # doesn't over-select it.
        st.add_credential(Credential(
            username="mysqluser", secret="mysqlpass", kind="password",
            domain="", source="mysql-brute", origin_ip="10.0.0.5"))
    st.close()


class Esc1AvailableTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rc-esc1-avail-")
        self.eng = Path(self.tmp) / "eng"
        _seed_engagement(self.eng)
        # PATH scrubbed — certipy not installed by default.
        self._orig_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self.tmp

    def tearDown(self):
        os.environ["PATH"] = self._orig_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshots_tool_state_and_matching_creds(self):
        with TestClient(create_app(str(self.eng))) as c:
            r = c.get("/api/adcs/esc1/available")
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertFalse(body["tool_installed"])
            self.assertIn("pip install certipy-ad", body["tool_hint"])
            self.assertEqual(body["confirm_sentinel"], "yes-run-certipy")
            # matching_creds includes the AD cred, excludes the mysql one
            usernames = {c["username"] for c in body["matching_creds"]}
            self.assertIn("alice", usernames)
            self.assertNotIn("mysqluser", usernames)
            row = next(c for c in body["matching_creds"]
                       if c["username"] == "alice")
            self.assertEqual(row["domain"], "corp.local")
            self.assertTrue(row["has_password"])
            self.assertFalse(row["has_hash"])

    def test_flips_tool_installed_when_certipy_on_path(self):
        _write_fake_certipy(self.tmp, "exit 0")
        with TestClient(create_app(str(self.eng))) as c:
            body = c.get("/api/adcs/esc1/available").json()
        self.assertTrue(body["tool_installed"])
        self.assertEqual(body["tool_hint"], "")


class Esc1AttemptGatingTest(unittest.TestCase):
    """Locks in the three gating layers before we let a request reach
    the certipy subprocess."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rc-esc1-gate-")
        self.eng = Path(self.tmp) / "eng"
        _seed_engagement(self.eng)
        self._orig_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self.tmp

    def tearDown(self):
        os.environ["PATH"] = self._orig_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _body(self, **over):
        b = dict(template="VulnT", ca="CORP-CA", dc_ip="10.0.0.10",
                 domain="corp.local", username="alice",
                 upn_target="administrator@corp.local",
                 confirm="yes-run-certipy")
        b.update(over)
        return b

    def test_missing_fields_400(self):
        with TestClient(create_app(str(self.eng))) as c:
            for key in ("template", "ca", "dc_ip", "domain", "username",
                        "upn_target", "confirm"):
                body = self._body()
                body.pop(key)
                r = c.post("/api/adcs/esc1/attempt", json=body)
                self.assertEqual(r.status_code, 400,
                    f"expected 400 for missing {key}, got {r.status_code}")
                self.assertIn("missing required field", r.json()["detail"])

    def test_confirm_boolean_rejected(self):
        # A JS-side `confirm: true` boolean is exactly the accidental
        # replay case the sentinel string exists to guard against.
        with TestClient(create_app(str(self.eng))) as c:
            r = c.post("/api/adcs/esc1/attempt", json=self._body(confirm=True))
            self.assertEqual(r.status_code, 400)
            self.assertIn("confirm field must be the exact string", r.json()["detail"])

    def test_confirm_wrong_string_rejected(self):
        with TestClient(create_app(str(self.eng))) as c:
            for c_val in ("yes", "confirm", "run", "YES-RUN-CERTIPY",
                          "yes-run-certipy ", "yes-run-certip"):
                r = c.post("/api/adcs/esc1/attempt",
                           json=self._body(confirm=c_val))
                self.assertEqual(r.status_code, 400,
                    f"expected 400 for confirm={c_val!r}, got {r.status_code}")

    def test_credential_not_in_store_404_not_500(self):
        # Recce must never accept a password from the request body.
        # Requesting an unknown AD principal → 404, and body-side
        # `password=` is IGNORED.
        with TestClient(create_app(str(self.eng))) as c:
            body = self._body(username="doesnotexist", password="hunter2")
            r = c.post("/api/adcs/esc1/attempt", json=body)
            self.assertEqual(r.status_code, 404)
            self.assertIn("no credential in the store matches", r.json()["detail"])

    def test_certipy_missing_returns_200_with_actionable_error(self):
        # PATH scrubbed — certipy not on PATH. The attempt endpoint
        # returns 200 (not 500) with ok=False + the install-hint error
        # so the frontend can render it inline.
        with TestClient(create_app(str(self.eng))) as c:
            r = c.post("/api/adcs/esc1/attempt", json=self._body())
            self.assertEqual(r.status_code, 200, r.text[:200])
            body = r.json()
            self.assertFalse(body["ok"])
            self.assertIn("certipy not installed", body["error"])
            # No PFX file was written on the failure path
            self.assertEqual(body["pfx_size"], 0)
            self.assertFalse(body["credential_added"])


class Esc1AttemptSuccessTest(unittest.TestCase):
    """End-to-end happy path with the fake certipy — proves the ok
    branch writes the PFX, folds a cert Credential into the store, and
    surfaces the result in the API response."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rc-esc1-ok-")
        self.eng = Path(self.tmp) / "eng"
        _seed_engagement(self.eng)
        self._orig_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self.tmp
        _write_fake_certipy(self.tmp, r"""
            printf 'FAKE-PFX-BYTES\n' > administrator.pfx
            printf '[*] Got certificate with UPN administrator@corp.local\n'
            printf 'Saved certificate and private key to administrator.pfx\n'
            exit 0
        """)

    def tearDown(self):
        os.environ["PATH"] = self._orig_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_success_writes_pfx_and_folds_cert_credential(self):
        with TestClient(create_app(str(self.eng))) as c:
            r = c.post("/api/adcs/esc1/attempt", json=dict(
                template="VulnT", ca="CORP-CA", dc_ip="10.0.0.10",
                domain="corp.local", username="alice",
                upn_target="administrator@corp.local",
                confirm="yes-run-certipy",
            ), headers={"X-Tester": "smoke"})
            self.assertEqual(r.status_code, 200, r.text[:300])
            body = r.json()
            self.assertTrue(body["ok"], f"expected ok, got {body!r}")
            # PFX persisted under session-loot/adcs/
            self.assertTrue(body["pfx_saved_at"].endswith(".pfx"))
            self.assertTrue(os.path.isfile(body["pfx_saved_at"]))
            with open(body["pfx_saved_at"], "rb") as fh:
                self.assertEqual(fh.read(), b"FAKE-PFX-BYTES\n")
            self.assertEqual(body["pfx_size"], len(b"FAKE-PFX-BYTES\n"))
            self.assertTrue(body["credential_added"])
            self.assertNotIn("Password1!", str(body))     # secret not echoed

        # Cert cred landed in the store
        with Store(_open_paths(str(self.eng))["db"]) as st:
            certs = [c for c in st.all_credentials() if c.kind == "cert"]
            self.assertEqual(len(certs), 1)
            self.assertEqual(certs[0].domain, "corp.local")
            self.assertEqual(certs[0].source, "adcs-esc1(VulnT)")
            self.assertIn("smoke", certs[0].notes)


if __name__ == "__main__":
    unittest.main()
