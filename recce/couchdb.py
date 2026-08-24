"""Backward-compat shim: recce.couchdb is the same module object as recce.services.db.couchdb.
Prefer `from recce.services.db.couchdb import ...` in new code."""
import sys
from .services.db import couchdb as _mod
sys.modules[__name__] = _mod
