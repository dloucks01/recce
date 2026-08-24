"""Backward-compat shim: recce.attackpath is the same module object as recce.act.attackpath.
Prefer `from recce.act.attackpath import ...` in new code."""
import sys
from .act import attackpath as _mod
sys.modules[__name__] = _mod
