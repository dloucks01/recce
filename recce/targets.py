"""Backward-compat shim: recce.targets is the same module object as recce.core.targets.
Prefer `from recce.core.targets import ...` in new code."""
import sys
from .core import targets as _mod
sys.modules[__name__] = _mod
