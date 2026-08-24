"""Backward-compat shim: recce.cassandra is the same module object as recce.services.db.cassandra.
Prefer `from recce.services.db.cassandra import ...` in new code."""
import sys
from .services.db import cassandra as _mod
sys.modules[__name__] = _mod
