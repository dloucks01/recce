"""Backward-compat shim: recce.deploy is the same module object as recce.creds.deploy.
Prefer `from recce.creds.deploy import ...` in new code."""
import sys
from .creds import deploy as _mod
sys.modules[__name__] = _mod
