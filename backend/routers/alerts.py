from __future__ import annotations

from datetime import datetime
import re
from typing import Any

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket
from routers.ticket_maintenance import Actor, send_to_maintenance
from services.audit import write_audit

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


def _now() -> datetime:
    return datetime.utcnow()


def _parse_instance_to_ip(instance: str) -> str | None:
    """
    instance เช่น:
      - "192.168.87.131:9100"
      - "vm-node-01:9100"
    คืนค่า ip ถ้าเป็น ip:port
    """
    if not instance:
        return None
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+):\d+$", instance.strip())
    if m:
        return m.group(1)
    return None


def _find_inventory(db: Session, instance: str) -> Inventory | None:
    ip = _parse_instance_to_ip(instance)
    if ip:
        return db.query(Inventory).filter(Inventory.ip_address == ip).first()

    host = instance.split(":")[0] if instance else ""
    if host:
        inv = db.query(Inventory).filter(Inventory.hostname == host).first()
        if inv:
            return inv
    return None


def _find_open_ticket(db: Session, alertname: str, instance: str, severity: str) -> Ticket | None:
    """
    Production rule:
    - ใช้ key (alertname, instance, severity) + status=OPEN เพื่อความ idempotent
    """
    return (
        db.query(Ticket)
        .filter(Ticket.alert_name == alertname)
        .filter(Ticket.instance == instance)
        .filter(Ticket.severity == severity)
        .filter(Ticket.status == "OPEN")
        .order_by(Ticket.id.desc())
        .first()
    )


def _try_auto_send_to_maintenance(
    *,
    db: Session,
    req: Request,
    ticket_id: int,
) -> dict[str, Any]:
    """
    best-effort:
    - ใช้ logic/send route เดิมของ ticket_maintenance
    - ไม่ให้ล้มทั้ง webhook batch
    """
    actor = Actor(name="alertmanager", role="ADMIN")

    try:
        link = send_to_maintenance(
            ticket_id=ticket_id,
            request=req,
            db=db,
            actor=actor,
        )

        return {
            "auto_handoff": "sent",
            "maintenance_ticket_id": getattr(link, "maintenance_ticket_id", None),
            "maintenance_status": getattr(link, "maintenance_status", None),
            "maintenance_url": getattr(link, "maintenance_url", None),
        }
    except HTTPException as e:
        detail = e.detail
        return {
            "auto_handoff": "blocked",
            "handoff_status_code": e.status_code,
            "handoff_detail": detail,
        }
    except Exception as e:
        return {
            "auto_handoff": "error",
            "handoff_error": str(e),
        }


@router.post("/webhook")
async def alertmanager_webhook(req: Request, db: Session = Depends(get_db)):
    """
    Alertmanager -> Webhook (Production-ish)
    - firing   => create OPEN ticket if not exists
    - resolved => close OPEN ticket -> RESOLVED
    - idempotent
    - batch-safe (error รายตัว ไม่ล้มทั้ง batch)

    เพิ่มเติม:
    - หลัง create ticket ใหม่ จะพยายาม auto send ไป maintenance
      โดย reuse policy/logic เดิมจาก ticket_maintenance
    """
    payload: Any = await req.json()

    alerts = payload.get("alerts") if isinstance(payload, dict) else None
    if not isinstance(alerts, list):
        raise HTTPException(
            status_code=400,
            detail="Invalid Alertmanager payload: missing alerts[]",
        )

    results: list[dict[str, Any]] = []

    for a in alerts:
        try:
            if not isinstance(a, dict):
                results.append({"action": "skip_invalid_item"})
                continue

            labels = a.get("labels") or {}
            annotations = a.get("annotations") or {}

            alertname = labels.get("alertname", "UnknownAlert")
            instance = labels.get("instance", "unknown")
            severity = labels.get("severity", "unknown")
            fingerprint = labels.get("fingerprint") or a.get("fingerprint")

            status = (a.get("status") or "").lower()  # firing / resolved
            summary = annotations.get("summary", "")
            description = annotations.get("description", "")

            inv = _find_inventory(db, instance)

            existing_open = _find_open_ticket(
                db,
                alertname=alertname,
                instance=instance,
                severity=severity,
            )

            # =========================
            # FIRING => CREATE (idempotent)
            # =========================
            if status == "firing":
                if existing_open:
                    if existing_open.inventory_id is None and inv is not None:
                        existing_open.inventory_id = inv.id
                        db.add(existing_open)

                        try:
                            write_audit(
                                db,
                                request=req,
                                action="TICKET_BACKFILL_INVENTORY_AUTO",
                                entity_type="ticket",
                                entity_id=existing_open.id,
                                actor_name="alertmanager",
                                actor_role="SYSTEM",
                                meta={
                                    "ticket_id": existing_open.id,
                                    "inventory_id": inv.id,
                                    "alert_name": alertname,
                                    "instance": instance,
                                    "severity": severity,
                                },
                            )
                        except Exception:
                            pass

                        db.commit()
                        results.append(
                            {
                                "action": "noop_open_exists_backfilled_inventory",
                                "ticket_id": existing_open.id,
                                "inventory_id": inv.id,
                            }
                        )
                    else:
                        results.append(
                            {
                                "action": "noop_open_exists",
                                "ticket_id": existing_open.id,
                            }
                        )
                    continue

                t = Ticket(
                    alert_name=alertname,
                    instance=instance,
                    severity=severity,
                    status="OPEN",
                    owner=None,
                    acknowledged_at=None,
                    inventory_id=(inv.id if inv else None),
                    created_at=_now(),
                    resolved_at=None,
                )

                if hasattr(t, "fingerprint"):
                    try:
                        setattr(t, "fingerprint", fingerprint)
                    except Exception:
                        pass

                db.add(t)
                db.flush()

                try:
                    write_audit(
                        db,
                        request=req,
                        action="TICKET_OPEN_AUTO",
                        entity_type="ticket",
                        entity_id=t.id,
                        actor_name="alertmanager",
                        actor_role="SYSTEM",
                        meta={
                            "ticket_id": t.id,
                            "inventory_id": t.inventory_id,
                            "alert_name": alertname,
                            "instance": instance,
                            "severity": severity,
                            "summary": summary,
                            "description": description,
                            "fingerprint": fingerprint,
                            "source": "alertmanager_webhook",
                        },
                    )
                except Exception:
                    pass

                db.commit()
                db.refresh(t)

                auto_handoff = _try_auto_send_to_maintenance(
                    db=db,
                    req=req,
                    ticket_id=t.id,
                )

                result_row = {
                    "action": "created",
                    "ticket_id": t.id,
                    "inventory_id": t.inventory_id,
                    "summary": summary,
                    "description": description,
                    **auto_handoff,
                }

                results.append(result_row)
                continue

            # =========================
            # RESOLVED => CLOSE OPEN
            # =========================
            if status == "resolved":
                if not existing_open:
                    results.append(
                        {
                            "action": "noop_no_open_ticket",
                            "key": f"{alertname}|{instance}|{severity}",
                        }
                    )
                    continue

                existing_open.status = "RESOLVED"
                existing_open.resolved_at = _now()
                db.add(existing_open)

                try:
                    write_audit(
                        db,
                        request=req,
                        action="TICKET_RESOLVE_AUTO",
                        entity_type="ticket",
                        entity_id=existing_open.id,
                        actor_name="alertmanager",
                        actor_role="SYSTEM",
                        meta={
                            "ticket_id": existing_open.id,
                            "inventory_id": existing_open.inventory_id,
                            "alert_name": alertname,
                            "instance": instance,
                            "severity": severity,
                            "summary": summary,
                            "description": description,
                            "fingerprint": fingerprint,
                            "source": "alertmanager_webhook",
                        },
                    )
                except Exception:
                    pass

                db.commit()

                results.append(
                    {
                        "action": "resolved",
                        "ticket_id": existing_open.id,
                    }
                )
                continue

            # =========================
            # UNKNOWN STATUS
            # =========================
            results.append(
                {
                    "action": "skip_unknown_status",
                    "status": status,
                }
            )

        except Exception as e:
            results.append(
                {
                    "action": "error",
                    "error": str(e),
                }
            )

    return {"ok": True, "results": results}
