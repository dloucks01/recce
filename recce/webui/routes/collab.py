"""Routes: collaboration (chat, presence, assignments, activity)."""
from __future__ import annotations

from fastapi import APIRouter
from ..schemas import ChatPayload, PresencePayload, AssignPayload

router = APIRouter(prefix="/api", tags=["collaboration"])


def register_collab_routes(app, collab):
    """Register collaboration routes on the app."""

    @router.get("/collab")
    def get_collab_state():
        """Get current collaboration state (assignments, online users, activity)."""
        return {
            "assignments": dict(collab.assignments),
            "online": list(collab.online),
            "activity": collab.activity[-50:],  # Last 50 events
            "credentials_shared": len(collab.credentials),
        }

    @router.post("/presence")
    def update_presence(payload: PresencePayload):
        """Update user presence (online/offline)."""
        collab.online.add(payload.tester)
        collab.activity.append({
            "type": "presence",
            "tester": payload.tester,
            "ts": __import__("time").time(),
        })
        return {"status": "ok"}

    @router.post("/assign")
    def assign_host(payload: AssignPayload):
        """Assign a host to a tester."""
        if payload.tester:
            collab.assignments[payload.ip] = payload.tester
        else:
            collab.assignments.pop(payload.ip, None)

        collab.activity.append({
            "type": "assign",
            "ip": payload.ip,
            "tester": payload.tester or "unassigned",
            "ts": __import__("time").time(),
        })
        return {"status": "ok"}

    @router.get("/chat")
    def get_chat_history(limit: int = 100):
        """Get chat message history."""
        return collab.messages[-limit:]

    @router.post("/chat")
    def post_chat(payload: ChatPayload):
        """Post a chat message."""
        msg = {
            "author": payload.tester,
            "text": payload.text,
            "timestamp": __import__("time").time(),
        }
        collab.messages.append(msg)
        collab.activity.append({
            "type": "chat",
            "by": payload.tester,
            "ts": msg["timestamp"],
            "what": f"message ({len(payload.text)} chars)",
        })
        return {"status": "ok"}

    app.include_router(router)
