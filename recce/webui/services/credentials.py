"""Credential store service."""
from __future__ import annotations

from ...core.store import Store


def list_credentials(db_path: str, limit: int = 0, offset: int = 0) -> dict:
    """Return the credential store, paginated. limit=0 means no page cap."""
    with Store(db_path) as st:
        creds = st.all_credentials()
    items = [{
        "username": c.username, "secret": c.secret, "kind": c.kind,
        "domain": c.domain, "source": c.source, "origin_ip": c.origin_ip,
        "notes": c.notes, "label": c.label,
    } for c in creds]
    total = len(items)
    if limit > 0:
        items = items[offset:offset + limit]
    elif offset > 0:
        items = items[offset:]
    return {"items": items, "total": total, "limit": limit, "offset": offset}
