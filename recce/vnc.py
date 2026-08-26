"""Backward-compat shim: recce.vnc is the same module object as recce.services.vnc.
Prefer `from recce.services.vnc import ...` in new code."""
import sys
from .services import vnc as _mod
sys.modules[__name__] = _mod
