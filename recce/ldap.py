"""Backward-compat shim: recce.ldap is the same module object as recce.services.ldap.
Prefer `from recce.services.ldap import ...` in new code."""
import sys
from .services import ldap as _mod
sys.modules[__name__] = _mod
