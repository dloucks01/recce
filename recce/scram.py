"""Backward-compat shim: recce.scram is the same module object as recce.ad.scram.
sys.modules aliasing so tests that patch recce.scram.X still affect the real code.
Prefer `from recce.ad.scram import ...` in new code."""
import sys
from .ad import scram as _mod
sys.modules[__name__] = _mod
