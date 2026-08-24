"""Backward-compat shim: recce.db2 is the same module object as recce.services.db.db2.
Prefer `from recce.services.db.db2 import ...` in new code."""
import sys
from .services.db import db2 as _mod
sys.modules[__name__] = _mod
