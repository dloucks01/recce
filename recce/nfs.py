"""Backward-compat shim: recce.nfs is the same module object as recce.services.nfs.
Prefer `from recce.services.nfs import ...` in new code."""
import sys
from .services import nfs as _mod
sys.modules[__name__] = _mod
