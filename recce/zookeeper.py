"""Backward-compat shim: recce.zookeeper is the same module object as recce.services.zookeeper.
Prefer `from recce.services.zookeeper import ...` in new code."""
import sys
from .services import zookeeper as _mod
sys.modules[__name__] = _mod
