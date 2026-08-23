"""Collaborative, engagement-native shell sessions — recce's differentiating C2 layer.

See DESIGN.md. The public surface is the SessionManager (one owner of listeners + sessions)
and the Session object; everything else (Transport, Listener, tasking) is wiring behind it.
"""
from .manager import SessionManager
from .session import Session
from .transport import SocketTransport, Transport

__all__ = ["SessionManager", "Session", "Transport", "SocketTransport"]
