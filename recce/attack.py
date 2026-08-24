"""Backward-compat shim: recce.attack is the same module object as recce.act.attack.
Prefer `from recce.act.attack import ...` in new code."""
import sys
from .act import attack as _mod
sys.modules[__name__] = _mod
