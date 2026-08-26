"""Backward-compat shim: recce.etcd is the same module object as recce.services.etcd.
Prefer `from recce.services.etcd import ...` in new code."""
import sys
from .services import etcd as _mod
sys.modules[__name__] = _mod
