"""Backward-compat shim: recce.tracking is the same module object as recce.core.tracking.
Prefer `from recce.core.tracking import ...` in new code."""
import sys
from .core import tracking as _mod
sys.modules[__name__] = _mod
