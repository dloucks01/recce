"""Backward-compat shim: recce.poc is the same module object as recce.act.poc.
Prefer `from recce.act.poc import ...` in new code."""
import sys
from .act import poc as _mod
sys.modules[__name__] = _mod
