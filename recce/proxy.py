"""Backward-compat shim: recce.proxy is the same module object as recce.core.proxy.
Prefer `from recce.core.proxy import ...` in new code."""
import sys
from .core import proxy as _mod
sys.modules[__name__] = _mod
