"""Backward-compat shim: recce.gitdump is the same module object as recce.services.gitdump.
Prefer `from recce.services.gitdump import ...` in new code."""
import sys
from .services import gitdump as _mod
sys.modules[__name__] = _mod
