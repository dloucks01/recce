"""Backward-compat shim: recce.ftp is the same module object as recce.services.ftp.
Prefer `from recce.services.ftp import ...` in new code."""
import sys
from .services import ftp as _mod
sys.modules[__name__] = _mod
