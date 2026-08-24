"""Backward-compat shim: recce.redis is the same module object as recce.services.db.redis.
Prefer `from recce.services.db.redis import ...` in new code."""
import sys
from .services.db import redis as _mod
sys.modules[__name__] = _mod
