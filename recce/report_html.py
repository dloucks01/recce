"""Backward-compat shim: recce.report_html is the same module object as recce.report.html.
Prefer `from recce.report.html import ...` in new code."""
import sys
from .report import html as _mod
sys.modules[__name__] = _mod
