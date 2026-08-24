"""Backward-compat shim: recce.credenum is the same module object as recce.creds.credenum.
Prefer `from recce.creds.credenum import ...` in new code."""
import sys
from .creds import credenum as _mod
sys.modules[__name__] = _mod
