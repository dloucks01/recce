"""Backward-compat shim: recce.web is the same module object as recce.services.web.
Prefer `from recce.services.web import ...` in new code."""
import sys
from .services import web as _mod
sys.modules[__name__] = _mod
