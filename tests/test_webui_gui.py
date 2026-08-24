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
            creds = c.get("/api/credentials").json()["items"]
        self.assertTrue(creds, "no credentials for the Loot view")
        c0 = creds[0]
        for field in ("label", "secret", "kind", "source", "origin_ip"):
            self.assertIn(field, c0)
        # the loot we build must be represented, not just AD captures
        self.assertTrue({"web-loot", "postgres-loot", "mysql-loot"} & {c["source"] for c in creds})

    def test_import_endpoint_folds_external_tool_output(self):
        """The Import panel must accept output from a number of tools and fold it in:
        netexec SMB (host access), and impacket Kerberoast / AS-REP / secretsdump
        (credentials). Auto-detection routes each to the right parser."""
        from recce.webui.app import _detect_import_kind
        NXC = ("SMB  10.9.9.9  445  BOX  [*] Windows 10 Build 19041 x64 (name:BOX) (domain:corp.local)\n"
               "SMB  10.9.9.9  445  BOX  [+] corp.local\\eve:Winter2024! (Pwn3d!)\n")
        KRB = "$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web*$deadbeefcafe"
        ASREP = "$krb5asrep$23$noauth@CORP.LOCAL:00112233445566"
        SECRETS = "sql_svc:1104:aad3b435b51404eeaad3b435b51404ee:cafebabecafebabecafebabecafebabe:::"
        # detection is unambiguous per format
        self.assertEqual(_detect_import_kind(NXC), "nxc")
        self.assertEqual(_detect_import_kind(KRB), "kerberoast")
        self.assertEqual(_detect_import_kind(ASREP), "asrep")
        self.assertEqual(_detect_import_kind(SECRETS), "secretsdump")
        with _client(self.eng) as c:
            before = len(c.get("/api/credentials").json()["items"])
            r = c.post("/api/import", json={"content": NXC, "filename": "nxc.txt", "kind": "auto"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["kind"], "nxc")
            self.assertTrue(any(h["ip"] == "10.9.9.9" for h in c.get("/api/hosts").json()["items"]))
            for txt in (KRB, ASREP, SECRETS):
                self.assertEqual(c.post("/api/import", json={"content": txt, "kind": "auto"}).status_code, 200)
            after = c.get("/api/credentials").json()["items"]
            # nxc captures the validated login (eve), plus kerberoast + asrep + secretsdump
            self.assertEqual(len(after) - before, 4)
            self.assertTrue({"nxc-validated", "kerberoast", "asrep", "secretsdump"}
                            <= {c["source"] for c in after})
            # a scanner export folds findings onto the right host
            NESSUS = ('<?xml version="1.0"?><NessusClientData_v2><Report name="s">'
                      '<ReportHost name="10.9.9.20"><HostProperties>'
                      '<tag name="host-ip">10.9.9.20</tag></HostProperties>'
                      '<ReportItem port="445" protocol="tcp" severity="4" pluginID="1" '
                      'pluginName="EternalBlue"><cve>CVE-2017-0143</cve>'
                      '<synopsis>rce</synopsis></ReportItem></ReportHost></Report></NessusClientData_v2>')
            self.assertEqual(_detect_import_kind(NESSUS), "nessus")
            self.assertEqual(c.post("/api/import", json={"content": NESSUS, "kind": "auto"}).status_code, 200)
            self.assertTrue(any(f["title"] == "EternalBlue" and f["kev"]
                                for f in c.get("/api/findings").json()["items"]))
            # an undetectable blob is rejected with guidance, not silently swallowed
            self.assertEqual(c.post("/api/import", json={"content": "hello world", "kind": "auto"}).status_code, 422)

    def test_collab_endpoints_track_team_state(self):
        """The multi-tester layer: claim/assign, triage labels, per-port status,
        dismiss, manual add (finding/cred/host/access), presence, activity feed."""
        H = {"X-Tester": "alice"}
        with _client(self.eng) as c:
            ip = c.get("/api/hosts").json()["items"][0]["ip"]
            self.assertEqual(c.post("/api/assign", json={"ip": ip, "tester": "alice"}, headers=H).json(), {"ok": True})
            c.post("/api/label", json={"ip": ip, "label": "interesting", "on": True}, headers=H)
            c.post("/api/port_status", json={"ip": ip, "port": 445, "status": "wip"}, headers=H)
            c.post("/api/add/finding", json={"ip": ip, "port": 3389, "title": "Manual RDP finding",
                                             "severity": "high", "cve": "CVE-2019-0708"}, headers=H)
            self.assertTrue(c.post("/api/add/credential",
                            json={"username": "svc", "secret": "s3cret", "origin_ip": ip}, headers=H).json()["added"])
            self.assertEqual(c.post("/api/add/host", json={"targets": "10.77.0.9"}, headers=H).json()["added"], 1)
            c.post("/api/add/access", json={"ip": ip, "note": "SYSTEM via manual"}, headers=H)
            c.post("/api/presence", headers={"X-Tester": "bob"})
            state = c.get("/api/collab").json()
            self.assertEqual(state["assignments"].get(ip), "alice")
            self.assertIn("interesting", state["labels"].get(ip, []))
            self.assertEqual(state["port_status"].get(f"{ip}:445"), "wip")
            self.assertIn("bob", state["online"])
            self.assertTrue(state["activity"], "activity feed is empty")
            # manual finding folded + KEV-annotated; manual host + access landed
            self.assertTrue(any(f["title"] == "Manual RDP finding" and f["kev"]
                                for f in c.get("/api/findings").json()["items"]))
            hs = {h["ip"]: h for h in c.get("/api/hosts").json()["items"]}
            self.assertIn("10.77.0.9", hs)
            self.assertTrue(hs[ip]["access"])
            # bad input is rejected
            self.assertEqual(c.post("/api/label", json={"ip": ip, "label": "bogus"}, headers=H).status_code, 400)

    def test_chat_endpoints_text_and_image(self):
        """Team chat: post text + a pasted image (stored on disk, served back), history."""
        import base64
        PNG = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhf"
               "DwAChwGA60e6kgAAAABJRU5ErkJggg==")
        with _client(self.eng) as c:
            self.assertEqual(c.post("/api/chat", json={"text": "dc01 looks juicy"},
                                    headers={"X-Tester": "alex"}).status_code, 200)
            r = c.post("/api/chat", json={"text": "proof:", "image": PNG},
                       headers={"X-Tester": "bob"})
            self.assertEqual(r.status_code, 200)
            img = r.json()["image"]
            self.assertTrue(img.endswith(".png"))
            hist = c.get("/api/chat").json()
            self.assertEqual([m["tester"] for m in hist[-2:]], ["alex", "bob"])
            media = c.get(f"/api/chat/media/{img}")
            self.assertEqual((media.status_code, media.headers["content-type"]), (200, "image/png"))
            # guards: empty message + path traversal + missing file
            self.assertEqual(c.post("/api/chat", json={"text": ""}).status_code, 400)
            self.assertEqual(c.get("/api/chat/media/nope.png").status_code, 404)

    def test_chat_general_file_attachment(self):
        """Drag-and-drop / file-picker attachments: any file type, not just images -
        served as a forced download (never rendered in-origin) with the filename
        sanitized against path traversal / control-char injection."""
        import base64
        payload = b"user:pass\nadmin:admin\n"
        with _client(self.eng) as c:
            r = c.post("/api/chat", json={
                "text": "loot from the share", "image": "",
                "file": {"data": base64.b64encode(payload).decode(),
                         "name": "../../etc/passwd"}},
                headers={"X-Tester": "carol"})
            self.assertEqual(r.status_code, 200)
            f = r.json()["file"]
            self.assertNotIn("/", f["name"])       # path components stripped
            self.assertNotIn("..", f["name"])
            self.assertEqual(f["size"], len(payload))
            got = c.get(f"/api/chat/file/{f['stored']}", params={"dl": f["name"]})
            self.assertEqual(got.status_code, 200)
            self.assertEqual(got.content, payload)
            # never rendered inline - always a forced download, regardless of content
            self.assertEqual(got.headers["content-type"], "application/octet-stream")
            self.assertIn("attachment", got.headers["content-disposition"])
            # a message with ONLY a file (no text) is valid
            self.assertEqual(c.post("/api/chat", json={"text": "", "image": "",
                             "file": {"data": base64.b64encode(b"x").decode(), "name": "a.txt"}}
                             ).status_code, 200)
            # oversize file rejected before it's written to disk
            big = base64.b64encode(b"x" * 20_000_001).decode()
            self.assertEqual(c.post("/api/chat", json={"text": "", "image": "",
                             "file": {"data": big, "name": "big.bin"}}).status_code, 413)
            # a file whose UPLOADED CONTENT is HTML must still be served as a safe
            # download, not rendered - the stored-XSS check that motivated the
            # separate /api/chat/file endpoint in the first place.
            html = base64.b64encode(b"<script>alert(1)</script>").decode()
            r2 = c.post("/api/chat", json={"text": "", "image": "",
                        "file": {"data": html, "name": "notes.html"}})
            f2 = r2.json()["file"]
            got2 = c.get(f"/api/chat/file/{f2['stored']}")
            self.assertEqual(got2.headers["content-type"], "application/octet-stream")
            # traversal / missing-file guards, same contract as /api/chat/media
            self.assertEqual(c.get("/api/chat/file/nope.bin").status_code, 404)
            self.assertEqual(c.get(r"/api/chat/file/a%5c..%5cb").status_code, 400)

    def test_collab_writes_survive_concurrency(self):
        """Concurrent chat/assignment writes (threadpool + per-request connection) must
        not clobber each other — the load-modify-save is serialised by a process lock."""
        import tempfile, threading
        from recce.cli import _open_paths
        from recce.store import Store
        from recce.webui import collab
        eng = tempfile.mkdtemp()
        db = _open_paths(eng)["db"]
        Store(db).close()
        N = 40

        def post(i):
            st = Store(db)                       # each thread its own connection, like a request
            try:
                collab.add_chat(st, f"u{i % 4}", f"msg {i}")
                collab.set_assignment(st, f"10.0.0.{i}", f"u{i % 4}")
            finally:
                st.close()
        threads = [threading.Thread(target=post, args=(i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        st = Store(db)
        try:
            self.assertEqual(len(collab.get_chat(st, 1000)), N, "concurrent chat lost a message")
            self.assertEqual(len(collab.get_assignments(st)), N, "concurrent assignment lost an entry")
        finally:
            st.close()

    def test_attack_endpoint_feeds_the_coverage_panel(self):
        with _client(self.eng) as c:
            cov = c.get("/api/attack").json()
        self.assertGreater(cov["technique_count"], 0)
        self.assertTrue(cov["tactics"] and cov["tactics"][0]["techniques"])

    def test_spray_endpoint_is_graceful_without_netexec(self):
        # the Loot "Spray" button POSTs here; with no netexec it must report cleanly,
        # not 500 (and not hang - no tool means no network attempts).
        from recce import credenum
        orig = credenum.smb_tool
        credenum.smb_tool = lambda: None
        try:
            with _client(self.eng) as c:
                r = c.post("/api/spray", json={})
                self.assertEqual(r.status_code, 200)
                self.assertFalse(r.json()["ok"])
                self.assertIn("netexec", r.json()["error"])
        finally:
            credenum.smb_tool = orig

    def test_act_run_button_endpoint_is_safe(self):
        # the "Run read-only loot" button POSTs here; on an empty engagement it must be a
        # fast, clean no-op (the real loot chain is covered by the act unit tests).
        empty = tempfile.mkdtemp()
        from recce.store import Store
        Store(_open_paths(empty)["db"]).close()
        try:
            with _client(empty) as c:
                r = c.post("/api/act/run")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()["looted"], 0)
        finally:
            __import__("shutil").rmtree(empty, ignore_errors=True)


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
        for marker in ("Top priorities", "Collected credentials", "MITRE ATT",
                       "Spray these credentials", "Next moves", "Import tool output",
                       "Team chat"):
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
