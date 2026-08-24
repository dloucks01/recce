"""Backward-compat shim: recce.mysql is the same module object as recce.services.db.mysql.
Prefer `from recce.services.db.mysql import ...` in new code."""
import sys
from .services.db import mysql as _mod
sys.modules[__name__] = _mod
