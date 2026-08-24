"""Backward-compat shim: recce.verify is the same module object as recce.vuln.verify.
Prefer `from recce.vuln.verify import ...` in new code."""
import sys
from .vuln import verify as _mod
sys.modules[__name__] = _mod
