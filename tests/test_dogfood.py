"""Dogfood / first-use smoke tests: run recce the way an operator does.

Our other ~880 tests are unit tests - they exercise analyze()/parse() against fake
servers and synthetic data, and prove the LOGIC. They cannot catch the class of bug you
hit the moment you actually USE the package: a subcommand that crashes on invocation, a
command that dies on a fresh empty engagement, a web endpoint that 500s, a packaging gap
that ImportErrors. This file closes that gap by driving the REAL CLI and the REAL web app
end to end, from a clean state, and failing loudly on the first traceback.

No network / nmap: everything here runs against a seeded or empty datastore.
"""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
import warnings
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce import cli                       # noqa: E402
from recce.cli import _open_paths           # noqa: E402
from recce.store import Store               # noqa: E402
from tools.mock_engagement import build     # noqa: E402


def _subcommands():
    p = cli.build_arg_parser()
    return next(list(a.choices.keys()) for a in p._actions
                if getattr(a, "dest", "") == "command" and a.choices)


def _run(argv):
    """Run the real CLI in-process; return rc, or ('CRASH', exc) on an unhandled error."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            return cli.main(argv)
        except SystemExit as e:                       # argparse / clean exits are fine
            return e.code
        except Exception as e:                        # noqa: BLE001 - that's the bug we hunt
            return ("CRASH", e)


# Read-only commands that operate purely on the datastore (no network / nmap). These are
# the ones an operator invokes constantly; a crash here is a first-use showstopper.
_READONLY = ["status", "next", "act", "attack", "report", "creds", "attackpath",
             "exploitplan", "review", "verify"]


class CliDogfood(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seeded = tempfile.mkdtemp()
        build(cls.seeded, hosts=12, seed=7)
        cls.empty = tempfile.mkdtemp()
        Store(_open_paths(cls.empty)["db"]).close()     # a fresh, zero-host engagement

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.seeded, ignore_errors=True)
        shutil.rmtree(cls.empty, ignore_errors=True)

    def test_every_subcommand_help_builds(self):
        # a subparser that fails to construct is an instant crash for that whole command.
        for cmd in _subcommands():
            rc = _run([cmd, "-h"])
            self.assertNotIsInstance(rc, tuple, f"`recce {cmd} -h` crashed: {rc}")

    def test_readonly_commands_survive_a_seeded_engagement(self):
        for cmd in _READONLY:
            rc = _run([cmd, "-o", self.seeded])
            self.assertNotIsInstance(rc, tuple,
                                     f"`recce {cmd}` crashed on a seeded engagement: {rc}")

    def test_readonly_commands_survive_an_empty_engagement(self):
        # the classic first-run state: the datastore exists but has zero hosts. Commands
        # must degrade gracefully (a clean message + rc), never traceback.
        for cmd in _READONLY:
            rc = _run([cmd, "-o", self.empty])
            self.assertNotIsInstance(rc, tuple,
                                     f"`recce {cmd}` crashed on an EMPTY engagement: {rc}")


class WebUiDogfood(unittest.TestCase):
    """Spin up the real FastAPI app and hit every non-streaming endpoint on both a
    seeded and an empty engagement - no route may 500."""

    @classmethod
    def setUpClass(cls):
        warnings.filterwarnings("ignore")
        cls.seeded = tempfile.mkdtemp()
        build(cls.seeded, hosts=12, seed=7)
        cls.empty = tempfile.mkdtemp()
        Store(_open_paths(cls.empty)["db"]).close()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.seeded, ignore_errors=True)
        shutil.rmtree(cls.empty, ignore_errors=True)

    def _sweep(self, eng):
        from starlette.testclient import TestClient
        from recce.webui.app import create_app
        app = create_app(eng)
        bad = []
        with TestClient(app) as c:
            for r in app.routes:
                methods = getattr(r, "methods", set()) or set()
                if "GET" not in methods:
                    continue
                path = getattr(r, "path", "")
                if "events" in path:            # SSE streams - a plain GET never returns
                    continue
                url = (path.replace("{ip}", "10.20.10.10")
                            .replace("{kind}", "xlsx").replace("{jid}", "nope"))
                resp = c.get(url)
                if resp.status_code >= 500:
                    bad.append((url, resp.status_code))
        return bad

    def test_no_endpoint_500s_on_a_seeded_engagement(self):
        bad = self._sweep(self.seeded)
        self.assertEqual(bad, [], f"web endpoints 500'd: {bad}")

    def test_no_endpoint_500s_on_an_empty_engagement(self):
        bad = self._sweep(self.empty)
        self.assertEqual(bad, [], f"web endpoints 500'd on empty engagement: {bad}")

    def test_every_report_format_downloads(self):
        from starlette.testclient import TestClient
        from recce.webui.app import create_app
        with TestClient(create_app(self.seeded)) as c:
            for kind in ("xlsx", "csv", "md", "html"):
                r = c.get(f"/api/report/{kind}")
                self.assertEqual(r.status_code, 200, kind)
                self.assertGreater(len(r.content), 100, kind)


class PackagingDogfood(unittest.TestCase):
    """Catch the 'ships a broken package' class: every module must import, and every
    package pyproject claims to ship must actually be importable (the recce.webui bug -
    cli.py imports recce.webui.app, but pyproject shipped only 'recce' - was exactly
    this: a package that imports fine from source but not once installed)."""

    def test_every_module_imports(self):
        import importlib
        root = Path(__file__).resolve().parent.parent / "recce"
        failed = []
        for py in sorted(root.rglob("*.py")):
            if "webui/frontend" in py.as_posix() or py.name == "__main__.py":
                continue
            rel = py.relative_to(root.parent).with_suffix("")
            mod = ".".join(rel.parts)
            try:
                importlib.import_module(mod)
            except Exception as e:                    # noqa: BLE001
                failed.append((mod, repr(e)))
        self.assertEqual(failed, [], f"modules that fail to import: {failed}")

    def test_pyproject_declared_packages_are_importable(self):
        import importlib
        import tomllib
        pyproj = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with open(pyproj, "rb") as fh:
            packages = tomllib.load(fh)["tool"]["setuptools"]["packages"]
        for pkg in packages:
            importlib.import_module(pkg)              # ImportError here = a shipping bug

    def test_cli_imports_webui_which_must_be_a_declared_package(self):
        # the regression guard for the exact bug we hit: cli imports recce.webui, so
        # recce.webui MUST be in the shipped package list.
        import tomllib
        pyproj = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with open(pyproj, "rb") as fh:
            packages = set(tomllib.load(fh)["tool"]["setuptools"]["packages"])
        self.assertIn("recce.webui", packages,
                      "cli.py imports recce.webui.app - it must be a shipped package")


if __name__ == "__main__":
    unittest.main()
