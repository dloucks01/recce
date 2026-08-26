"""Backward-compat shim: recce.nomad is the same module object as recce.services.nomad.
Prefer `from recce.services.nomad import ...` in new code."""
import sys
from .services import nomad as _mod
sys.modules[__name__] = _mod
