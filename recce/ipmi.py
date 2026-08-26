"""Backward-compat shim: recce.ipmi is the same module object as recce.services.ipmi.
Prefer `from recce.services.ipmi import ...` in new code."""
import sys
from .services import ipmi as _mod
sys.modules[__name__] = _mod
