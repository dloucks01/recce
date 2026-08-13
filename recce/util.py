"""Small shared utilities — one home for helpers that were duplicated across modules.

Part of the de-bloat work (SOTA roadmap Stage 8): a single implementation each module
imports, instead of near-identical copies drifting apart over time.
"""

from __future__ import annotations

import os
import subprocess


def run_tool(cmd, timeout: int = 120, *, env_extra: dict | None = None,
             stdin_data: str | None = None, new_session: bool = False) -> tuple[str, str | None]:
    """Run an external tool; return (combined stdout+stderr, error-or-None). Never raises -
    a missing tool, a timeout, or a decode error becomes a returned error string so one bad
    invocation can't crash a phase. The single implementation the credenum / bloodhound /
    smb tool-runners share (previously three byte-identical copies).

    Keyword-only options for keeping secrets off the (world-readable) process argv:
      * env_extra   - merged into the child's environment (/proc/<pid>/environ is
                      owner-only, unlike the world-readable cmdline), e.g. SSHPASS.
      * stdin_data  - fed to the tool's stdin (e.g. a password answered to an
                      impacket getpass() prompt, then the rest of the script).
      * new_session - start the child in its own session (setsid), detaching it
                      from the controlling terminal so a getpass() prompt falls
                      back to stdin instead of blocking on /dev/tty."""
    try:
        env = {**os.environ, **env_extra} if env_extra else None
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, input=stdin_data, env=env,
                           start_new_session=new_session)
        return (p.stdout or "") + (p.stderr or ""), None
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "", str(e)
