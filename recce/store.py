"""Backward-compat shim: recce.store is the same module object as recce.core.store.
Prefer `from recce.core.store import ...` in new code."""
import sys
from .core import store as _mod
sys.modules[__name__] = _mod
