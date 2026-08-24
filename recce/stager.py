"""Backward-compat shim: recce.stager is the same module object as recce.creds.stager.
Prefer `from recce.creds.stager import ...` in new code."""
import sys
from .creds import stager as _mod
sys.modules[__name__] = _mod
