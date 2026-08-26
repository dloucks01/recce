"""Backward-compat shim: recce.consul is the same module object as recce.services.consul.
Prefer `from recce.services.consul import ...` in new code."""
import sys
from .services import consul as _mod
sys.modules[__name__] = _mod
