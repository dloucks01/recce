"""Backward-compat shim: recce.api is the same module object as recce.services.api.
Prefer `from recce.services.api import ...` in new code."""
import sys
from .services import api as _mod
sys.modules[__name__] = _mod
