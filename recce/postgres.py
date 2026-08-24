"""Backward-compat shim: recce.postgres is the same module object as recce.services.db.postgres.
Prefer `from recce.services.db.postgres import ...` in new code."""
import sys
from .services.db import postgres as _mod
sys.modules[__name__] = _mod
