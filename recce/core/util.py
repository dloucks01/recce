"""Small shared utilities — one home for helpers that were duplicated across modules.

Part of the de-bloat work (SOTA roadmap Stage 8): a single implementation each module
imports, instead of near-identical copies drifting apart over time.
"""

from __future__ import annotations

import os
import re
import subprocess

# A description/notes field that looks like it contains a password (AD accounts often
# stash them there). Shared by the ldap and bloodhound enumeration paths.
PW_DESC_RE = re.compile(
    r"\b(pass(word|wd)?|pwd|secret|cred(ential)?|kennwort|mot\s+de\s+passe)\b"
    r"|pw\s*[:=]", re.I)

# Signatures in a tool's output that mean the INVOCATION itself was broken - recce built
# a wrong command (a stale/renamed CLI flag) or the tool crashed - as opposed to "the
# tool ran fine and the operation just didn't succeed" (a failed auth, no roastable
# accounts, an empty result). The distinction matters: the first is a recce bug that must
# be surfaced; the second is a normal result the caller parses. Keyed conservatively so a
# normal failed run - which prints its own result lines and none of this text - is left
# for the caller. (A renamed netexec flag once made the whole call fail with an argparse
# error printed to stdout while run_tool returned err=None, so recce silently recorded
# "no session" for a credential that worked - this is the guard against that class.)
_BROKEN_INVOCATION_RE = re.compile(
    r"^\S+: error: "                            # argparse: '<prog>: error: <msg>' (bad flag)
    r"|Traceback \(most recent call last\):",   # the tool crashed
    re.M)


def _broken_detail(out: str, returncode: int) -> str | None:
    """A one-line reason if a non-zero exit's output shows the invocation was broken (a
    bad/renamed flag or a crash) or the tool died silently; None for a normal failed
    operation the caller should still parse."""
    m = re.search(r"^\S+: error: (.+)$", out, re.M)          # argparse's actionable line
    if m:
        return m.group(1).strip()[:200]
    if "Traceback (most recent call last):" in out:          # a crash: report the exception
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return (lines[-1][:200] if lines else "crashed")
    if not out.strip():                                      # non-zero, produced nothing
        return f"exited {returncode} with no output"
    return None


def run_tool(cmd, timeout: int = 120, *, env_extra: dict | None = None,
             stdin_data: str | None = None, new_session: bool = False) -> tuple[str, str | None]:
    """Run an external tool; return (combined stdout+stderr, error-or-None). Never raises -
    a missing tool, a timeout, or a decode error becomes a returned error string so one bad
    invocation can't crash a phase. The single implementation the credenum / bloodhound /
    smb tool-runners share (previously three byte-identical copies).

    The error is also set when the tool exits non-zero AND its output shows the invocation
    was broken (a stale/unknown CLI flag, a crash, or no output at all) - so a mis-built
    command surfaces as an error instead of being silently parsed as an empty result. A
    non-zero exit with normal output and no such signature (e.g. netexec's failed-auth
    exit) is returned with err=None for the caller to parse, exactly as before.

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
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "", str(e)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        detail = _broken_detail(out, p.returncode)
        if detail is not None:
            prog = os.path.basename(cmd[0]) if cmd else "tool"
            return out, f"{prog}: {detail}"
    return out, None
