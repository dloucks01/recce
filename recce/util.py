"""Backward-compat shim: recce.util is the same module object as recce.core.util.
Prefer `from recce.core.util import ...` in new code."""
import sys
from .core import util as _mod
sys.modules[__name__] = _mod
