"""Backward-compat shim: recce.docker_registry is the same module object as recce.services.docker_registry.
Prefer `from recce.services.docker_registry import ...` in new code."""
import sys
from .services import docker_registry as _mod
sys.modules[__name__] = _mod
