"""Backward-compat shim: recce.oracle is the same module object as recce.services.db.oracle.
Prefer `from recce.services.db.oracle import ...` in new code."""
import sys
from .services.db import oracle as _mod
sys.modules[__name__] = _mod
