"""Backward-compat shim: recce.credentials is the same module object as recce.creds.credentials.
Prefer `from recce.creds.credentials import ...` in new code."""
import sys
from .creds import credentials as _mod
sys.modules[__name__] = _mod
