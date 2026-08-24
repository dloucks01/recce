"""Backward-compat shim: recce.dedup is the same module object as recce.intake.dedup.
Prefer `from recce.intake.dedup import ...` in new code."""
import sys
from .intake import dedup as _mod
sys.modules[__name__] = _mod
