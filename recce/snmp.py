"""Backward-compat shim: recce.snmp is the same module object as recce.services.snmp.
Prefer `from recce.services.snmp import ...` in new code."""
import sys
from .services import snmp as _mod
sys.modules[__name__] = _mod
