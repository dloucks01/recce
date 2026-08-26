"""Backward-compat shim: recce.rdp is the same module object as recce.services.rdp.
Prefer `from recce.services.rdp import ...` in new code."""
import sys
from .services import rdp as _mod
sys.modules[__name__] = _mod
