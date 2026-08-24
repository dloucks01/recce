"""Backward-compat shim: recce.report_markdown is the same module object as recce.report.markdown.
Prefer `from recce.report.markdown import ...` in new code."""
import sys
from .report import markdown as _mod
sys.modules[__name__] = _mod
