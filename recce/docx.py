"""Backward-compat shim. Moved to recce.report.formats.docx.
Prefer `from recce.report.formats.docx import ...` in new code."""
from .report.formats import docx as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
