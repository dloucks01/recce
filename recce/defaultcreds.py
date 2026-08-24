"""Backward-compat shim: recce.defaultcreds is the same module object as recce.creds.defaultcreds.
Prefer `from recce.creds.defaultcreds import ...` in new code."""
import sys
from .creds import defaultcreds as _mod
sys.modules[__name__] = _mod
