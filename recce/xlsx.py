"""Backward-compat shim. Moved to recce.report.formats.xlsx.
Prefer `from recce.report.formats.xlsx import ...` in new code."""
from .report.formats import xlsx as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
