"""Backward-compat shim. Moved to recce.report.docx.
Prefer `from recce.report.docx import ...` in new code."""
from .report import docx as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
