"""Backward-compat shim: recce.db is the same module object as recce.services.db.
Prefer `from recce.services.db import ...` in new code."""
import sys
from .services import db as _mod
sys.modules[__name__] = _mod
