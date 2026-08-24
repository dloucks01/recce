"""Backward-compat shim: recce.verify_rules is the same module object as recce.vuln.verify_rules.
Prefer `from recce.vuln.verify_rules import ...` in new code."""
import sys
from .vuln import verify_rules as _mod
sys.modules[__name__] = _mod
