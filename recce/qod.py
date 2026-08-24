"""Backward-compat shim: recce.qod is the same module object as recce.core.qod.
Prefer `from recce.core.qod import ...` in new code."""
import sys
from .core import qod as _mod
sys.modules[__name__] = _mod
