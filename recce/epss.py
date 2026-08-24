"""Backward-compat shim: recce.epss is the same module object as recce.vuln.epss.
Prefer `from recce.vuln.epss import ...` in new code."""
import sys
from .vuln import epss as _mod
sys.modules[__name__] = _mod
