"""The shared Playbook endpoint (/api/playbook) — the phase track, live branches, and
attack-path narrative that the workbench's Playbook tab + header 'next' chip render. It
derives entirely from engagement state, so it must reflect where the engagement actually
is: sweep-next after enum+vulns, creds/foothold unlocking as they appear.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

from recce.core.models import Credential, Host, Port, Vuln
from recce.core.store import Store
from recce.webui.app import create_app


def _pb(hosts, creds=None):
    d = tempfile.mkdtemp()
    st = Store(os.path.join(d, "results.sqlite"))
    st.set_meta("engagement", "t")
    for h in hosts:
        st.upsert_host(h)
    for c in (creds or []):
        st.add_credential(c)
    st.close()
    return TestClient(create_app(d)).get("/api/playbook").json()


def _host(**kw):
    h = Host(ip=kw.pop("ip", "10.0.0.5"), state="up", **kw)
    return h


class PlaybookState(unittest.TestCase):
    def test_fresh_enum_vulns_makes_sweep_current(self):
        h = _host(enumerated=True)
        h.ports.append(Port(portid=445, protocol="tcp", state="open", vuln_scanned=True))
        h.vulns.append(Vuln(ip=h.ip, port=445, protocol="tcp", script_id="v",
                            state="VULNERABLE", title="x", severity="medium", source="vulndb"))
        pb = _pb([h])
        self.assertEqual(pb["current"], "sweep")
        self.assertEqual(pb["next"]["label"], "Deep sweep")
        states = {p["key"]: p["state"] for p in pb["phases"]}
        self.assertEqual(states["enum"], "done")
        self.assertEqual(states["vulns"], "done")
        self.assertEqual(states["sweep"], "current")
        self.assertEqual(states["creds"], "locked")
        self.assertEqual(states["foothold"], "locked")

    def test_sweep_done_when_deep_finding_present(self):
        h = _host(enumerated=True)
        h.ports.append(Port(portid=6379, protocol="tcp", state="open", vuln_scanned=True))
        h.vulns.append(Vuln(ip=h.ip, port=6379, protocol="tcp", script_id="r",
                            state="finding", title="Unauth Redis", severity="critical",
                            source="redis"))            # a deep-module source
        pb = _pb([h])
        states = {p["key"]: p["state"] for p in pb["phases"]}
        self.assertEqual(states["sweep"], "done")
        self.assertIsNone(pb["current"])                # enum/vulns/sweep all done

    def test_creds_and_foothold_activate(self):
        h = _host(enumerated=True, access_gained=True)
        h.ports.append(Port(portid=445, protocol="tcp", state="open", vuln_scanned=True))
        pb = _pb([h], creds=[Credential(username="alice", secret="Pw!", kind="password")])
        states = {p["key"]: p["state"] for p in pb["phases"]}
        self.assertEqual(states["creds"], "active")
        self.assertEqual(states["foothold"], "active")

    def test_empty_engagement(self):
        pb = _pb([])
        self.assertEqual(pb["current"], "enum")         # nothing done -> enum is the move
        self.assertIsInstance(pb["branches"], list)
        self.assertIsInstance(pb["path"], list)


if __name__ == "__main__":
    unittest.main()
