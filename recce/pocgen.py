"""Backward-compat shim: recce.pocgen is the same module object as recce.act.pocgen.
Prefer `from recce.act.pocgen import ...` in new code."""
import sys
from .act import pocgen as _mod
sys.modules[__name__] = _mod
