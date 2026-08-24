"""Backward-compat shim: recce.report_docx is the same module object as recce.report.docx.
Prefer `from recce.report.docx import ...` in new code."""
import sys
from .report import docx as _mod
sys.modules[__name__] = _mod
