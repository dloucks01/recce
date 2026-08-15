"""GUI flow tests: the web UI must carry the operator along the path
Findings -> Act (what to do) -> Loot (what was extracted) -> ATT&CK, and surface
the engine's real output - not stop at a list of findings.

Three tiers, each gated to what it needs:
  * always-on: the GUI-feeding API endpoints return the shape the frontend consumes;
  * build-gated (skips if the frontend isn't built): the shipped SPA actually contains
    the Act/Loot views (catches 'forgot to rebuild' / a view deleted);
  * opt-in headless (RECCE_GUI_IT=1 + firefox): drive the REAL SPA in a browser, click
    each tab, and assert the flow renders - the click-through that catches a dead tab or
    an unwired view, the exact class of bug unit tests miss.
"""
from __future__ import annotations

import os
import tempfile
import unittest
import warnings
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce.cli import _open_paths                 # noqa: E402
from tools.mock_engagement import build           # noqa: E402

_STATIC = Path(__file__).resolve().parent.parent / "recce" / "webui" / "static"
_BUILT = (_STATIC / "index.html").exists()


def _client(eng):
    warnings.filterwarnings("ignore")
    from starlette.testclient import TestClient
    from recce.webui.app import create_app
    return TestClient(create_app(eng))


class ApiShape(unittest.TestCase):
    """Always-on: the endpoints the Act/Loot/ATT&CK views consume return usable data."""

    @classmethod
    def setUpClass(cls):
        cls.eng = tempfile.mkdtemp()
        build(cls.eng, hosts=16, seed=99)

    @classmethod
    def tearDownClass(cls):
        __import__("shutil").rmtree(cls.eng, ignore_errors=True)

    def test_act_endpoint_feeds_the_action_plan_view(self):
        with _client(self.eng) as c:
            plan = c.get("/api/act").json()
        self.assertTrue(plan["top"], "no top priorities for the Act view")
        top = plan["top"][0]
        for field in ("archetype", "title", "command", "yields", "attack_id", "tier"):
            self.assertIn(field, top)
        self.assertTrue(any(t["tier"] == 0 for t in plan["tiers"]))   # an AUTO tier exists

    def test_credentials_endpoint_feeds_the_loot_view(self):
        with _client(self.eng) as c:
            creds = c.get("/api/credentials").json()
        self.assertTrue(creds, "no credentials for the Loot view")
        c0 = creds[0]
        for field in ("label", "secret", "kind", "source", "origin_ip"):
            self.assertIn(field, c0)
        # the loot we build must be represented, not just AD captures
        self.assertTrue({"web-loot", "postgres-loot", "mysql-loot"} & {c["source"] for c in creds})

    def test_attack_endpoint_feeds_the_coverage_panel(self):
        with _client(self.eng) as c:
            cov = c.get("/api/attack").json()
        self.assertGreater(cov["technique_count"], 0)
        self.assertTrue(cov["tactics"] and cov["tactics"][0]["techniques"])


@unittest.skipUnless(_BUILT, "frontend not built (recce/webui/static absent)")
class ShippedSpa(unittest.TestCase):
    """Build-gated: the SPA that actually ships contains the flow views."""

    def test_spa_is_served(self):
        eng = tempfile.mkdtemp()
        build(eng, hosts=4, seed=1)
        try:
            with _client(eng) as c:
                r = c.get("/")
                self.assertEqual(r.status_code, 200)
                self.assertIn("<script", r.text)
        finally:
            __import__("shutil").rmtree(eng, ignore_errors=True)

    def test_bundle_contains_the_act_and_loot_views(self):
        js = "".join(p.read_text(errors="replace")
                     for p in (_STATIC / "assets").glob("index-*.js"))
        for marker in ("Top priorities", "Extracted credentials", "MITRE ATT",
                       "recce creds --plan"):
            self.assertIn(marker, js, f"shipped SPA is missing {marker!r} - rebuild it")


@unittest.skipUnless(os.environ.get("RECCE_GUI_IT") == "1" and _BUILT,
                     "headless GUI walk is opt-in (RECCE_GUI_IT=1 + a built frontend)")
class HeadlessClickThrough(unittest.TestCase):
    """Opt-in: drive the real SPA in Firefox and walk the flow. See the module docstring."""

    def test_walk_the_flow(self):
        import shutil
        if not (shutil.which("firefox") or shutil.which("firefox-esr")):
            self.skipTest("no firefox")
        from tests._gui_harness import serve_app, firefox_session
        eng = tempfile.mkdtemp()
        build(eng, hosts=16, seed=99)
        try:
            with serve_app(eng) as base, firefox_session() as fx:
                fx.navigate(base + "/")
                fx.wait_text("recce")                       # React mounted
                # walk the guided path; each click must reveal that tab's content
                fx.click_button("Act")
                self.assertTrue(fx.wait_text("Top priorities"))
                fx.click_button("Loot")
                self.assertTrue(fx.wait_text("Extracted credentials"))
                fx.click_button("Findings")
                self.assertTrue(fx.wait_text("Unreviewed"))
                self.assertEqual(fx.console_errors(), [], "JS console errors during the walk")
        finally:
            __import__("shutil").rmtree(eng, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
