"""Backward-compat shim: recce.influxdb is the same module object as recce.services.db.influxdb.
Prefer `from recce.services.db.influxdb import ...` in new code."""
import sys
from .services.db import influxdb as _mod
sys.modules[__name__] = _mod
