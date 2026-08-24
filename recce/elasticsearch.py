"""Backward-compat shim: recce.elasticsearch is the same module object as recce.services.db.elasticsearch.
Prefer `from recce.services.db.elasticsearch import ...` in new code."""
import sys
from .services.db import elasticsearch as _mod
sys.modules[__name__] = _mod
