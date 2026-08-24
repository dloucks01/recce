"""Backward-compat shim. Moved to recce.report.markdown.
Prefer `from recce.report.markdown import ...` in new code."""
from .report import markdown as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
