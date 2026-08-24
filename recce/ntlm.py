"""Backward-compat shim: recce.ntlm is the same module object as recce.ad.ntlm.
sys.modules aliasing so tests that patch recce.ntlm.X still affect the real code.
Prefer `from recce.ad.ntlm import ...` in new code."""
import sys
from .ad import ntlm as _mod
sys.modules[__name__] = _mod
