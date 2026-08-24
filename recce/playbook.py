"""Backward-compat shim: recce.playbook is the same module object as recce.act.playbook.
Prefer `from recce.act.playbook import ...` in new code."""
import sys
from .act import playbook as _mod
sys.modules[__name__] = _mod
