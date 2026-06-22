# services/audit.py
import json
from typing import Any, Optional
from fastapi import Request
from sqlalchemy.orm import Session
from models import AuditLog


def _safe_json(meta: Any) -> Optional[str]:
    if meta is None:
        return None
    try:
        return json.dumps(meta, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_meta_str": str(meta)}, ensure_ascii=False)


def write_audit(
    db: Session,
    *,
    request: Optional[Request],
    action: str,
    entity_type: str,
    entity_id: Optional[str],
    actor_name: str,
    actor_role: str,
    meta: Any = None,
) -> None:
    try:
        ip = None
        user_agent = None

        if request and request.client:
            ip = request.client.host
            user_agent = request.headers.get("user-agent")

        row = AuditLog(
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            actor_name=actor_name or "unknown",
            actor_role=actor_role or "VIEWER",
            ip=ip,
            user_agent=user_agent,
            meta_json=_safe_json(meta),
        )

        db.add(row)

    except Exception:
        return
