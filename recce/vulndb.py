"""Backward-compat shim: recce.vulndb is the same module object as recce.vuln.vulndb.
Prefer `from recce.vuln.vulndb import ...` in new code."""
import sys
from .vuln import vulndb as _mod
sys.modules[__name__] = _mod
