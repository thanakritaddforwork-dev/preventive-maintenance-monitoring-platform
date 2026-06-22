# routers/audit.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence, Literal, List

from fastapi import APIRouter, Depends, HTTPException, Query, Header
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from database import get_db
from models import AuditLog

router = APIRouter(prefix="/api/audit", tags=["Audit"])

# =========================================================
# RBAC + Actor Identity (reuse pattern from tickets.py)
# =========================================================

Role = Literal["VIEWER", "OPERATOR", "ADMIN"]


class Actor(BaseModel):
    name: str
    role: Role


def get_actor(
    x_operator: Optional[str] = Header(default=None, alias="X-Operator"),
    x_role: Optional[str] = Header(default=None, alias="X-Role"),
) -> Actor:
    name = (x_operator or "unknown").strip() or "unknown"
    role = (x_role or "VIEWER").strip().upper()

    if role not in ("VIEWER", "OPERATOR", "ADMIN"):
        raise HTTPException(status_code=400, detail="Invalid X-Role (VIEWER|OPERATOR|ADMIN)")

    return Actor(name=name, role=role)  # type: ignore


def require_role(actor: Actor, allowed: Sequence[Role]) -> None:
    if actor.role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient role")


def _parse_since(s: str) -> datetime:
    """
    Accept:
    - ISO 8601: 2026-02-11T06:45:38
    - with Z:    2026-02-11T06:45:38Z
    - date only: 2026-02-11 (treated as 00:00:00)
    """
    s = (s or "").strip()
    if not s:
        raise ValueError("empty")

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    dt = datetime.fromisoformat(s)  # may be naive or aware
    # normalize to naive UTC-ish for sqlite comparisons
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# =========================================================
# GET /api/audit
# =========================================================
@router.get("", response_model=List[dict])
def list_audit(
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
    # filters
    action: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[str] = Query(None),
    actor_name: Optional[str] = Query(None),
    actor_role: Optional[str] = Query(None),
    since: Optional[str] = Query(None, description="ISO time e.g. 2026-02-11T00:00:00 or 2026-02-11"),
    since_hours: Optional[int] = Query(None, ge=1, le=24 * 30),
    # paging
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Audit Log Viewer
    - VIEWER/OPERATOR/ADMIN can read
    - Filters: action, entity_type, entity_id, actor_name, actor_role, since/since_hours
    """
    require_role(actor, ["VIEWER", "OPERATOR", "ADMIN"])

    q = db.query(AuditLog)

    if action:
        q = q.filter(AuditLog.action == action)

    if entity_type:
        q = q.filter(AuditLog.entity_type == entity_type)

    if entity_id:
        q = q.filter(AuditLog.entity_id == str(entity_id))

    if actor_name:
        q = q.filter(AuditLog.actor_name == actor_name)

    if actor_role:
        q = q.filter(AuditLog.actor_role == actor_role)

    # time filter
    if since:
        try:
            dt = _parse_since(since)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid since. Use ISO like 2026-02-11T00:00:00 or 2026-02-11")
        q = q.filter(AuditLog.created_at >= dt)
    elif since_hours is not None:
        dt = datetime.utcnow() - timedelta(hours=since_hours)
        q = q.filter(AuditLog.created_at >= dt)

    rows = (
        q.order_by(desc(AuditLog.created_at), desc(AuditLog.id))
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": r.id,
            "created_at": r.created_at,
            "action": r.action,
            "entity_type": r.entity_type,
            "entity_id": r.entity_id,
            "actor_name": r.actor_name,
            "actor_role": r.actor_role,
            "ip": getattr(r, "ip", None),
            "user_agent": getattr(r, "user_agent", None),
            "meta_json": getattr(r, "meta_json", None),
        }
        for r in rows
    ]
