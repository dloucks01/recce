"""Backward-compat shim: recce.kubernetes is the same module object as recce.services.kubernetes.
Prefer `from recce.services.kubernetes import ...` in new code."""
import sys
from .services import kubernetes as _mod
sys.modules[__name__] = _mod
