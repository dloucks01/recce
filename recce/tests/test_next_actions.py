"""W1: the next-best-action engine — ranked guidance from datastore state."""

import unittest

from recce.models import Host, Port, Vuln
from recce.workflow import next_actions


def _h(ip="10.0.0.1", ports=(), **flags):
    ps = [Port(portid=p, protocol="tcp", state="open", service=s) for p, s in ports]
    h = Host(ip=ip, up_reason="syn-ack", ports=ps)
    for k, v in flags.items():
        setattr(h, k, v)
    return h


def _cmds(actions):
    return [a.command for a in actions]


class NextActionsTest(unittest.TestCase):
    def test_empty_engagement_suggests_run(self):
        acts = next_actions([], output_dir="eng")
        self.assertEqual(acts[0].command, "recce run <targets> -o eng")

    def test_open_ports_unscanned_tops_the_list(self):
        h = _h(ports=[(445, "microsoft-ds")])          # vuln_scanned defaults False
        acts = next_actions([h], output_dir="eng")
        self.assertEqual(acts[0].command, "recce vulns -o eng")

    def test_db_host_suggests_db(self):
        h = _h(ports=[(3306, "mysql")])
        for p in h.ports:
            p.vuln_scanned = True                      # already vuln-scanned
        acts = next_actions([h], output_dir="eng")
        self.assertIn("recce db -o eng", _cmds(acts))

    def test_web_host_suggests_web(self):
        h = _h(ports=[(80, "http")])
        for p in h.ports:
            p.vuln_scanned = True
        self.assertIn("recce web -o eng", _cmds(next_actions([h], output_dir="eng")))

    def test_foothold_suggests_privesc_high(self):
        h = _h(ports=[(445, "microsoft-ds")], access_gained=True)
        for p in h.ports:
            p.vuln_scanned = True
        acts = next_actions([h], output_dir="eng")
        # privesc outranks lower-priority service enum
        self.assertEqual(acts[0].command, "recce privesc -o eng")

    def test_captured_creds_suggest_credsweep(self):
        h = _h(ports=[(445, "microsoft-ds")])
        for p in h.ports:
            p.vuln_scanned = True
        acts = next_actions([h], credentials=[{"user": "a"}], output_dir="eng")
        self.assertIn("recce credsweep -o eng", _cmds(acts))

    def test_findings_present_suggest_report_and_writeup(self):
        h = _h(ports=[(80, "http")])
        for p in h.ports:
            p.vuln_scanned = True
        h.vulns = [Vuln(ip=h.ip, port=80, protocol="tcp", script_id="x", title="finding")]
        cmds = _cmds(next_actions([h], output_dir="eng"))
        self.assertIn("recce report -o eng", cmds)

    def test_down_host_is_ignored(self):
        # a host with no proof of life shouldn't drive suggestions
        down = Host(ip="10.0.0.9")   # no ports, no up_reason -> is_up False
        acts = next_actions([down], output_dir="eng")
        self.assertEqual(acts[0].command, "recce run <targets> -o eng")


class RunOrchestrationTest(unittest.TestCase):
    """W2: `recce run` coordinates the existing phases (scan --deep + credsweep)."""

    def setUp(self):
        from recce import cli
        self.cli = cli
        self._orig = {k: getattr(cli, k) for k in
                      ("cmd_scan", "_run_sweep", "_print_next", "_open_paths")}
        self.calls = []
        cli.cmd_scan = lambda args: (self.calls.append(("scan", getattr(args, "deep", None))) or 0)
        cli._run_sweep = lambda args, authenticated: self.calls.append(("sweep", authenticated))
        cli._print_next = lambda *a, **k: None
        cli._open_paths = lambda o: {"db": "x", "xlsx": "x"}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(self.cli, k, v)

    def _args(self, **kw):
        import argparse
        base = dict(deep=False, username=None, output_dir="eng", title="t")
        base.update(kw)
        return argparse.Namespace(**base)

    def test_run_sets_deep_and_calls_scan(self):
        self.cli.cmd_run(self._args())
        self.assertIn(("scan", True), self.calls)              # --deep forced on

    def test_run_without_creds_skips_authenticated_sweep(self):
        self.cli.cmd_run(self._args())
        self.assertFalse(any(c[0] == "sweep" for c in self.calls))

    def test_run_with_creds_runs_authenticated_sweep(self):
        self.cli.cmd_run(self._args(username="bob", password="pw"))
        self.assertIn(("sweep", True), self.calls)             # authenticated modules run


if __name__ == "__main__":
    unittest.main()
