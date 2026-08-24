"""Backward-compat shim: recce.xlsx is the same module object as recce.report.formats.xlsx.
Prefer `from recce.report.formats.xlsx import ...` in new code."""
import sys
from .report.formats import xlsx as _mod
sys.modules[__name__] = _mod
