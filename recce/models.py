"""Backward-compat shim: recce.models is the same module object as recce.core.models.
Prefer `from recce.core.models import ...` in new code."""
import sys
from .core import models as _mod
sys.modules[__name__] = _mod
