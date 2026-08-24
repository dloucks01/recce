"""Backward-compat shim: recce.memcached is the same module object as recce.services.db.memcached.
Prefer `from recce.services.db.memcached import ...` in new code."""
import sys
from .services.db import memcached as _mod
sys.modules[__name__] = _mod
