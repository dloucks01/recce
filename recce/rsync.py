"""Backward-compat shim: recce.rsync is the same module object as recce.services.rsync.
Prefer `from recce.services.rsync import ...` in new code."""
import sys
from .services import rsync as _mod
sys.modules[__name__] = _mod
