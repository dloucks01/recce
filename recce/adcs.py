"""Backward-compat shim: recce.adcs is the same module object as recce.ad.adcs.
sys.modules aliasing so tests that patch recce.adcs.X still affect the real code.
Prefer `from recce.ad.adcs import ...` in new code."""
import sys
from .ad import adcs as _mod
sys.modules[__name__] = _mod
