"""Backward-compat shim: recce.dns is the same module object as recce.services.dns.
Prefer `from recce.services.dns import ...` in new code."""
import sys
from .services import dns as _mod
sys.modules[__name__] = _mod
