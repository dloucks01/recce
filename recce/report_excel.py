"""Backward-compat shim. Moved to recce.report.excel.
Prefer `from recce.report.excel import ...` in new code."""
from .report import excel as _mod
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith("__")})
