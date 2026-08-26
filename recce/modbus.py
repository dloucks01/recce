"""Backward-compat shim: recce.modbus is the same module object as recce.services.modbus.
Prefer `from recce.services.modbus import ...` in new code."""
import sys
from .services import modbus as _mod
sys.modules[__name__] = _mod
