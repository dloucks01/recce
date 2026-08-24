"""Backward-compat shim: recce.importers is the same module object as recce.intake.importers.
Prefer `from recce.intake.importers import ...` in new code."""
import sys
from .intake import importers as _mod
sys.modules[__name__] = _mod
