"""Backward-compat shim: recce.kafka is the same module object as recce.services.kafka.
Prefer `from recce.services.kafka import ...` in new code."""
import sys
from .services import kafka as _mod
sys.modules[__name__] = _mod
