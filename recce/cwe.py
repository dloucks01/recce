"""Backward-compat shim: recce.cwe is the same module object as recce.core.cwe.
Prefer `from recce.core.cwe import ...` in new code."""
import sys
from .core import cwe as _mod
sys.modules[__name__] = _mod
