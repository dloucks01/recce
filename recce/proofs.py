"""Backward-compat shim: recce.proofs is the same module object as recce.vuln.proofs.
Prefer `from recce.vuln.proofs import ...` in new code."""
import sys
from .vuln import proofs as _mod
sys.modules[__name__] = _mod
