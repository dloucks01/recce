"""Backward-compat shim: recce.mongodb is the same module object as recce.services.db.mongodb.
Prefer `from recce.services.db.mongodb import ...` in new code."""
import sys
from .services.db import mongodb as _mod
sys.modules[__name__] = _mod
