"""Backward-compat shim: recce.smtp is the same module object as recce.services.smtp.
Prefer `from recce.services.smtp import ...` in new code."""
import sys
from .services import smtp as _mod
sys.modules[__name__] = _mod
