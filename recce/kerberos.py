"""Backward-compat shim: recce.kerberos is the same module object as recce.ad.kerberos.
sys.modules aliasing so tests that patch recce.kerberos.X still affect the real code.
Prefer `from recce.ad.kerberos import ...` in new code."""
import sys
from .ad import kerberos as _mod
sys.modules[__name__] = _mod
