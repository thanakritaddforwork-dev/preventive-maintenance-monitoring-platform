# /opt/pm-backend/routers/tickets.py
from fastapi import APIRouter, Depends, Query, HTTPException, Request, Header
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from typing import List, Optional, Sequence, Literal
from datetime import datetime, timedelta, date
from pydantic import BaseModel
from json import JSONDecodeError

from database import get_db
from models import Ticket, TicketComment
from schemas import TicketOut, TicketSLAOut, TicketKPITrendOut

from services.audit import write_audit

router = APIRouter(prefix="/api/tickets", tags=["Tickets"])

# =========================================================
# RBAC + Actor Identity (Phase 14-3)
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


# =========================================================
# 1) QUERY APIs
# =========================================================

@router.get("/", response_model=List[TicketOut])
def list_tickets(
    status: Optional[str] = Query(None),
    inventory_id: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    q = db.query(Ticket)

    if status:
        q = q.filter(Ticket.status == status)

    if inventory_id:
        q = q.filter(Ticket.inventory_id == inventory_id)

    return (
        q.order_by(Ticket.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/inventory/{inventory_id}", response_model=List[TicketOut])
def tickets_by_inventory(inventory_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Ticket)
        .filter(Ticket.inventory_id == inventory_id)
        .order_by(Ticket.created_at.desc())
        .all()
    )


# =========================================================
# 2) OPS ACTION APIs (14-1 Operator Identity + 14-3 RBAC)
# =========================================================

@router.post("/{ticket_id}/ack", response_model=TicketOut)
def ack_ticket(
    ticket_id: int,
    request: Request,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
):
    require_role(actor, ["OPERATOR", "ADMIN"])

    ticket = db.query(Ticket).get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # ack ได้เมื่อยังไม่ ACK/RESOLVED
    if ticket.status not in ["ACK", "RESOLVED"]:
        ticket.status = "ACK"
        ticket.acknowledged_at = datetime.utcnow()
        if hasattr(ticket, "ack_by"):
            setattr(ticket, "ack_by", actor.name)
        ticket.owner = actor.name

        db.add(
            TicketComment(
                ticket_id=ticket.id,
                author=actor.name,
                message="Ticket acknowledged",
            )
        )

        # ✅ Audit (best-effort, commit พร้อม transaction นี้)
        write_audit(
            db,
            request=request,
            action="TICKET_ACK",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={"ticket_id": ticket.id, "instance": ticket.instance, "alert_name": ticket.alert_name},
        )

        db.commit()
        db.refresh(ticket)

    return ticket


@router.post("/{ticket_id}/resolve", response_model=TicketOut)
def resolve_ticket(
    ticket_id: int,
    request: Request,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
):
    require_role(actor, ["OPERATOR", "ADMIN"])

    ticket = db.query(Ticket).get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    if ticket.status != "RESOLVED":
        ticket.status = "RESOLVED"
        ticket.resolved_at = datetime.utcnow()
        ticket.resolve_source = "MANUAL"
        if hasattr(ticket, "resolve_by"):
            setattr(ticket, "resolve_by", actor.name)
        ticket.owner = actor.name

        db.add(
            TicketComment(
                ticket_id=ticket.id,
                author=actor.name,
                message="Ticket resolved",
            )
        )

        # ✅ Audit
        write_audit(
            db,
            request=request,
            action="TICKET_RESOLVE",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={"ticket_id": ticket.id, "instance": ticket.instance, "alert_name": ticket.alert_name},
        )

        db.commit()
        db.refresh(ticket)

    return ticket


# =========================================================
# 2.1) COMMENTS (GET/POST)
# =========================================================

@router.get("/{ticket_id}/comments", response_model=List[dict])
def list_comments(ticket_id: int, db: Session = Depends(get_db)):
    ticket = db.query(Ticket).get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    rows = (
        db.query(TicketComment)
        .filter(TicketComment.ticket_id == ticket_id)
        .order_by(TicketComment.created_at.asc())
        .all()
    )

    return [
        {
            "id": c.id,
            "ticket_id": c.ticket_id,
            "author": c.author,
            "message": c.message,
            "created_at": c.created_at,
        }
        for c in rows
    ]


@router.post("/{ticket_id}/comments", response_model=dict)
async def add_comment(
    ticket_id: int,
    request: Request,
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
):
    require_role(actor, ["OPERATOR", "ADMIN"])

    ticket = db.query(Ticket).get(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # ---- Robust body parsing ----
    content_type = (request.headers.get("content-type") or "").lower()

    data = None
    message = ""

    if "application/json" in content_type:
        try:
            data = await request.json()
        except JSONDecodeError:
            raw = (await request.body()).decode("utf-8", errors="ignore").strip()
            raise HTTPException(
                status_code=400,
                detail=f'Invalid JSON body. Expect JSON like {{"message":"..."}}. Got: {raw[:200]}',
            )
    else:
        raw = (await request.body()).decode("utf-8", errors="ignore").strip()
        message = raw

    if data is not None:
        if isinstance(data, dict):
            message = (data.get("message") or "").strip()
        else:
            raise HTTPException(status_code=400, detail="JSON body must be an object")

    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    comment = TicketComment(
        ticket_id=ticket.id,
        author=actor.name,
        message=message,
    )
    db.add(comment)

    # ✅ Audit (ก่อน commit)
    write_audit(
        db,
        request=request,
        action="TICKET_COMMENT_ADD",
        entity_type="ticket",
        entity_id=ticket.id,
        actor_name=actor.name,
        actor_role=actor.role,
        meta={"ticket_id": ticket.id, "comment_preview": message[:200]},
    )

    db.commit()
    db.refresh(comment)

    return {
        "id": comment.id,
        "ticket_id": comment.ticket_id,
        "author": comment.author,
        "message": comment.message,
        "created_at": comment.created_at,
    }


# =========================================================
# 3) SLA / MTTR
# =========================================================

@router.get("/sla", response_model=List[TicketSLAOut])
def ticket_sla(db: Session = Depends(get_db)):
    tickets = db.query(Ticket).all()
    result = []

    for t in tickets:
        duration = None
        if t.created_at and t.resolved_at:
            duration = int((t.resolved_at - t.created_at).total_seconds())

        result.append(
            TicketSLAOut(
                id=t.id,
                alert_name=t.alert_name,
                instance=t.instance,
                status=t.status,
                duration_seconds=duration,
            )
        )

    return result


# =========================================================
# 4) AUTO RECONCILE
# =========================================================

@router.post("/reconcile", response_model=List[TicketOut])
def reconcile_tickets(
    dry_run: bool = Query(False),
    request: Request = None,  # type: ignore
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
):
    # NOTE:
    # FastAPI ปกติ inject Request ได้ แต่เพื่อกัน signature เปลี่ยนพังของเดิม
    # เลยปล่อย optional ไว้ (ถ้าเป็น None ก็ audit เก็บ ip/ua ไม่ได้)

    require_role(actor, ["ADMIN"])

    from services.prometheus import is_alert_firing

    tickets = (
        db.query(Ticket)
        .filter(Ticket.status.in_(["OPEN", "ACK"]))
        .all()
    )

    resolved: List[Ticket] = []

    for t in tickets:
        still_firing = is_alert_firing(instance=t.instance)

        if not still_firing:
            if not dry_run:
                t.status = "RESOLVED"
                t.resolved_at = datetime.utcnow()
                t.resolve_source = "AUTO"
                if hasattr(t, "resolve_by"):
                    setattr(t, "resolve_by", actor.name)
            resolved.append(t)

    if not dry_run:
        # ✅ Audit: bulk action
        write_audit(
            db,
            request=request,
            action="TICKET_RECONCILE",
            entity_type="tickets",
            entity_id=None,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={"dry_run": dry_run, "resolved_count": len(resolved)},
        )
        db.commit()

    return resolved


# =========================================================
# 5) KPI SUMMARY
# =========================================================

@router.get("/kpi")
def ticket_kpi(db: Session = Depends(get_db)):
    tickets = (
        db.query(Ticket)
        .filter(Ticket.status == "RESOLVED")
        .filter(Ticket.resolved_at.isnot(None))
        .all()
    )

    total = len(tickets)
    auto = []
    manual = []

    for t in tickets:
        if not t.created_at or not t.resolved_at:
            continue
        dur = (t.resolved_at - t.created_at).total_seconds()
        if t.resolve_source == "AUTO":
            auto.append(dur)
        elif t.resolve_source == "MANUAL":
            manual.append(dur)

    def avg(arr):
        return int(sum(arr) / len(arr)) if arr else None

    auto_pct = round((len(auto) / total) * 100, 1) if total else 0

    return {
        "total_resolved": total,
        "auto_resolved": len(auto),
        "manual_resolved": len(manual),
        "auto_resolve_pct": auto_pct,
        "mttr_auto_seconds": avg(auto),
        "mttr_manual_seconds": avg(manual),
    }


# =========================================================
# 6) KPI TREND
# =========================================================

@router.get("/kpi/trend", response_model=List[TicketKPITrendOut])
def ticket_kpi_trend(
    days: int = Query(14, ge=1, le=90),
    db: Session = Depends(get_db),
):
    today = date.today()
    start_date = today - timedelta(days=days - 1)

    rows = (
        db.query(
            func.date(Ticket.resolved_at).label("day"),
            func.count(Ticket.id).label("total"),
            func.sum(case((Ticket.resolve_source == "AUTO", 1), else_=0)).label("auto_cnt"),
            func.sum(case((Ticket.resolve_source == "MANUAL", 1), else_=0)).label("manual_cnt"),
        )
        .filter(
            Ticket.status == "RESOLVED",
            Ticket.resolved_at.isnot(None),
            func.date(Ticket.resolved_at) >= start_date,
        )
        .group_by(func.date(Ticket.resolved_at))
        .order_by(func.date(Ticket.resolved_at))
        .all()
    )

    result = []
    for r in rows:
        total = r.total or 0
        auto_cnt = r.auto_cnt or 0
        result.append(
            TicketKPITrendOut(
                date=r.day,
                total_resolved=total,
                auto_resolved=auto_cnt,
                manual_resolved=r.manual_cnt or 0,
                auto_resolve_pct=round((auto_cnt / total) * 100, 2) if total else 0,
                mttr_auto_seconds=None,
                mttr_manual_seconds=None,
            )
        )
    return result
