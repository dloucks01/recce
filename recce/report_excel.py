"""Backward-compat shim: recce.report_excel is the same module object as recce.report.excel.
Prefer `from recce.report.excel import ...` in new code."""
import sys
from .report import excel as _mod
sys.modules[__name__] = _mod
