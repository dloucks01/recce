"""Small shared utilities — one home for helpers that were duplicated across modules.

Part of the de-bloat work (SOTA roadmap Stage 8): a single implementation each module
imports, instead of near-identical copies drifting apart over time.
"""

from __future__ import annotations

import subprocess


def run_tool(cmd, timeout: int = 120) -> tuple[str, str | None]:
    """Run an external tool; return (combined stdout+stderr, error-or-None). Never raises -
    a missing tool, a timeout, or a decode error becomes a returned error string so one bad
    invocation can't crash a phase. The single implementation the credenum / bloodhound /
    smb tool-runners share (previously three byte-identical copies)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
        return (p.stdout or "") + (p.stderr or ""), None
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "", str(e)
