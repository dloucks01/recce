"""Backward-compat shim: recce.bloodhound is the same module object as recce.ad.bloodhound.
sys.modules aliasing so tests that patch recce.bloodhound.X still affect the real code.
Prefer `from recce.ad.bloodhound import ...` in new code."""
import sys
from .ad import bloodhound as _mod
sys.modules[__name__] = _mod
