"""Backward-compat shim. Moved to recce.report.html.
Prefer `from recce.report.html import ...` in new code."""
from .report import html as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
