"""Backward-compat shim: recce.docx is the same module object as recce.report.formats.docx.
Prefer `from recce.report.formats.docx import ...` in new code."""
import sys
from .report.formats import docx as _mod
sys.modules[__name__] = _mod
