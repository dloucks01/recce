"""Backward-compat shim: recce.fieldkit is the same module object as recce.intake.fieldkit.
Prefer `from recce.intake.fieldkit import ...` in new code."""
import sys
from .intake import fieldkit as _mod
sys.modules[__name__] = _mod
