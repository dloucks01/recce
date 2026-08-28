"""Stage 8 (de-bloat): the shared subprocess runner the tool-runners now share."""

import unittest

from recce.ad import bloodhound
from recce.creds import credenum
from recce.services import smb
from recce.core.util import run_tool


class RunToolTest(unittest.TestCase):
    def test_success_combines_output(self):
        out, err = run_tool(["echo", "hello"])
        self.assertIsNone(err)
        self.assertIn("hello", out)

    def test_missing_tool_is_a_returned_error_not_a_raise(self):
        out, err = run_tool(["definitely-not-a-real-binary-xyzzy"])
        self.assertIsNotNone(err)
        self.assertEqual(out, "")

    def test_modules_delegate_to_the_shared_runner(self):
        # credenum / bloodhound / smb _run now all route through run_tool
        for mod in (credenum, bloodhound, smb):
            out, err = mod._run(["echo", "x"])
            self.assertIsNone(err)
            self.assertIn("x", out)

    def test_bad_flag_is_surfaced_as_an_error_not_a_silent_empty_result(self):
        # The regression that motivated this: a tool run with a stale/unknown flag exits
        # non-zero and prints an argparse error (often to stdout), which used to come back
        # as err=None so the caller parsed empty output and silently reported "nothing".
        out, err = run_tool([
            "python3", "-c",
            "import argparse; argparse.ArgumentParser(prog='nxc').parse_args()",
            "--definitely-not-a-real-flag"])
        self.assertIsNotNone(err, "a broken invocation must surface as an error")
        self.assertIn("unrecognized arguments", err)

    def test_a_crashing_tool_is_surfaced_as_an_error(self):
        out, err = run_tool(["python3", "-c", "raise ValueError('boom')"])
        self.assertIsNotNone(err)
        self.assertIn("boom", err)

    def test_nonzero_exit_with_no_output_is_an_error(self):
        out, err = run_tool(["sh", "-c", "exit 4"])
        self.assertIsNotNone(err)
        self.assertIn("4", err)

    def test_failed_operation_with_normal_output_stays_parseable(self):
        # A tool that RAN correctly but whose operation failed (e.g. netexec's failed-auth
        # exit) prints its own result lines and exits non-zero WITHOUT an argparse/traceback
        # signature - that must stay err=None so the caller parses the result, not be
        # mistaken for a broken invocation.
        out, err = run_tool([
            "sh", "-c",
            r'echo "SMB 10.0.0.1 445 DC [-] corp\\u:p STATUS_LOGON_FAILURE"; exit 1'])
        self.assertIsNone(err, "a non-zero exit with a normal result line is not a hard error")
        self.assertIn("STATUS_LOGON_FAILURE", out)


if __name__ == "__main__":
    unittest.main()
