"""Stage 8 (de-bloat): the shared subprocess runner the tool-runners now share."""

import unittest

from recce import bloodhound, credenum, smb
from recce.util import run_tool


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


if __name__ == "__main__":
    unittest.main()
