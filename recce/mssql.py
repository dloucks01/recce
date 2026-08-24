"""Backward-compat shim: recce.mssql is the same module object as recce.services.db.mssql.
Prefer `from recce.services.db.mssql import ...` in new code."""
import sys
from .services.db import mssql as _mod
sys.modules[__name__] = _mod
