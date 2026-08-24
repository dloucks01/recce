"""Backward-compat shim: recce.kev is the same module object as recce.vuln.kev.
Prefer `from recce.vuln.kev import ...` in new code."""
import sys
from .vuln import kev as _mod
sys.modules[__name__] = _mod
