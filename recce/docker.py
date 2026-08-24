"""Backward-compat shim: recce.docker is the same module object as recce.services.docker.
Prefer `from recce.services.docker import ...` in new code."""
import sys
from .services import docker as _mod
sys.modules[__name__] = _mod
