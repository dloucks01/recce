"""Backward-compat shim: recce.workflow is the same module object as recce.act.workflow.
Prefer `from recce.act.workflow import ...` in new code."""
import sys
from .act import workflow as _mod
sys.modules[__name__] = _mod
