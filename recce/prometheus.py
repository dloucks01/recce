"""Backward-compat shim: recce.prometheus is the same module object as recce.services.prometheus.
Prefer `from recce.services.prometheus import ...` in new code."""
import sys
from .services import prometheus as _mod
sys.modules[__name__] = _mod
