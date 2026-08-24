"""Backward-compat shim: recce.smb is the same module object as recce.services.smb.
Prefer `from recce.services.smb import ...` in new code."""
import sys
from .services import smb as _mod
sys.modules[__name__] = _mod
