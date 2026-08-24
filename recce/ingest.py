"""Backward-compat shim: recce.ingest is the same module object as recce.intake.ingest.
Prefer `from recce.intake.ingest import ...` in new code."""
import sys
from .intake import ingest as _mod
sys.modules[__name__] = _mod
