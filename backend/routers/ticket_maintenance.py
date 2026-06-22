import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from typing import Any, Dict, Literal, Optional, Sequence

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket, TicketMaintenanceLink
from schemas import TicketMaintenanceLinkOut
from services.audit import write_audit

router = APIRouter(prefix="/api/tickets", tags=["Ticket Maintenance Integration"])

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


def _safe_json(data: Any) -> Optional[str]:
    if data is None:
        return None
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps({"_raw": str(data)}, ensure_ascii=False)


def _maintenance_api_base() -> str:
    return os.getenv("MAINTENANCE_API_BASE", "http://127.0.0.1:8020").rstrip("/")


def _maintenance_web_base() -> str:
    return os.getenv("MAINTENANCE_WEB_BASE", "http://10.198.210.97:4000").rstrip("/")


def _monitoring_web_base() -> str:
    return os.getenv("MONITORING_WEB_BASE", "http://10.198.210.97:3000").rstrip("/")


def _json_request(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
) -> Any:
    req_headers = dict(headers or {})
    data = None

    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"Maintenance API HTTP {e.code}: {body[:500]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Maintenance API connection failed: {e}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Maintenance API returned invalid JSON: {e}")


def _get_maintenance_auth_headers() -> Dict[str, str]:
    token = (os.getenv("MAINTENANCE_API_TOKEN") or "").strip()
    if token:
        return {"Authorization": f"Bearer {token}"}

    username = (os.getenv("MAINTENANCE_API_USERNAME") or "").strip()
    password = (os.getenv("MAINTENANCE_API_PASSWORD") or "").strip()

    if username and password:
        login_url = f"{_maintenance_api_base()}/auth/login"
        login_payload = {"username": username, "password": password}
        data = _json_request(login_url, method="POST", payload=login_payload)

        access_token = None
        if isinstance(data, dict):
            access_token = (data.get("access_token") or "").strip()

        if not access_token:
            raise RuntimeError("Maintenance auth login did not return access_token")

        return {"Authorization": f"Bearer {access_token}"}

    raise RuntimeError(
        "Maintenance auth is not configured. Set MAINTENANCE_API_TOKEN "
        "or MAINTENANCE_API_USERNAME + MAINTENANCE_API_PASSWORD."
    )


def _severity_to_priority(severity: Optional[str]) -> str:
    sev = (severity or "").strip().lower()
    if sev in ("critical", "fatal", "high"):
        return "High"
    if sev in ("warning", "warn", "medium"):
        return "Medium"
    return "Low"


def _build_serial_number(ticket: Ticket, inventory: Optional[Inventory]) -> str:
    for candidate in [
        getattr(inventory, "asset_name", None),
        getattr(inventory, "hostname", None),
        getattr(ticket, "instance", None),
        f"MONITOR-TICKET-{ticket.id}",
    ]:
        value = (candidate or "").strip()
        if value:
            return value
    return f"MONITOR-TICKET-{ticket.id}"


def _build_subject(ticket: Ticket, inventory: Optional[Inventory]) -> str:
    asset_name = (getattr(inventory, "asset_name", None) or "").strip()
    hostname = (getattr(inventory, "hostname", None) or "").strip()
    target = asset_name or hostname or (ticket.instance or "").strip() or f"ticket-{ticket.id}"
    alert_name = (ticket.alert_name or "Monitoring Alert").strip()
    return f"[Monitoring] {alert_name} on {target}"


def _build_description(ticket: Ticket, inventory: Optional[Inventory]) -> str:
    asset_name = (getattr(inventory, "asset_name", None) or "").strip()
    hostname = (getattr(inventory, "hostname", None) or "").strip()
    ip_address = (getattr(inventory, "ip_address", None) or "").strip()
    location = (getattr(inventory, "location", None) or "").strip()
    device_type = (getattr(inventory, "device_type", None) or "").strip()

    monitoring_web = _monitoring_web_base()
    monitoring_ticket_list_url = f"{monitoring_web}/tickets"
    monitoring_inventory_url = (
        f"{monitoring_web}/nodes/{ticket.inventory_id}" if ticket.inventory_id else monitoring_ticket_list_url
    )

    lines = [
        "Incident handoff from Monitoring / NOC Dashboard",
        "",
        f"Monitoring Ticket ID: {ticket.id}",
        f"Alert Name: {ticket.alert_name or '-'}",
        f"Severity: {ticket.severity or '-'}",
        f"Status: {ticket.status or '-'}",
        f"Instance: {ticket.instance or '-'}",
        f"Fingerprint: {ticket.fingerprint or '-'}",
        "",
        f"Asset Name: {asset_name or '-'}",
        f"Hostname: {hostname or '-'}",
        f"IP Address: {ip_address or '-'}",
        f"Location/Room: {location or '-'}",
        f"Device Type: {device_type or '-'}",
        "",
        f"Monitoring Ticket List: {monitoring_ticket_list_url}",
        f"Monitoring Device Detail: {monitoring_inventory_url}",
    ]

    return "\n".join(lines).strip()


def _build_payload(ticket: Ticket, inventory: Optional[Inventory]) -> Dict[str, Any]:
    return {
        "subject": _build_subject(ticket, inventory),
        "description": _build_description(ticket, inventory),
        "priority": _severity_to_priority(ticket.severity),
        "category": "Monitoring Incident",
        "serial_number": _build_serial_number(ticket, inventory),
        "status": "Submitted",
        "verified_by_admin": False,
        "asset_id": None,
    }


def _get_ticket_or_404(db: Session, ticket_id: int) -> Ticket:
    ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


def _policy_allowlist() -> set[str]:
    raw = os.getenv(
        "MAINTENANCE_ALLOWED_ALERTS",
        "NodeDown,agent_heartbeat_lost,agent_disk_high_critical,device_unreachable",
    )
    return {x.strip() for x in raw.split(",") if x.strip()}


def _policy_min_age_minutes() -> int:
    try:
        return int(os.getenv("MAINTENANCE_MIN_AGE_MINUTES", "10"))
    except Exception:
        return 10


def _policy_cooldown_minutes() -> int:
    try:
        return int(os.getenv("MAINTENANCE_COOLDOWN_MINUTES", "360"))
    except Exception:
        return 360


def _policy_allow_resolved_send() -> bool:
    raw = (os.getenv("MAINTENANCE_ALLOW_RESOLVED_SEND", "false") or "").strip().lower()
    return raw in ("1", "true", "yes", "y", "on")


def _same_asset_scope(ticket: Ticket, other: Ticket) -> bool:
    if ticket.inventory_id and other.inventory_id:
        return ticket.inventory_id == other.inventory_id

    if (ticket.instance or "").strip() and (other.instance or "").strip():
        return (ticket.instance or "").strip() == (other.instance or "").strip()

    return False


def _evaluate_handoff_policy(
    db: Session,
    ticket: Ticket,
    inventory: Optional[Inventory],
) -> Dict[str, Any]:
    allowlist = _policy_allowlist()
    min_age_minutes = _policy_min_age_minutes()
    cooldown_minutes = _policy_cooldown_minutes()
    allow_resolved_send = _policy_allow_resolved_send()

    now = datetime.utcnow()
    reasons = []
    meta = {
        "allowlist": sorted(list(allowlist)),
        "min_age_minutes": min_age_minutes,
        "cooldown_minutes": cooldown_minutes,
        "allow_resolved_send": allow_resolved_send,
        "evaluated_at": now.isoformat(),
    }

    if ticket.status == "RESOLVED" and not allow_resolved_send:
        reasons.append("ticket already resolved")

    alert_name = (ticket.alert_name or "").strip()
    if alert_name not in allowlist:
        reasons.append(f"alert '{alert_name or '-'}' is not in maintenance allowlist")

    age_minutes = None
    if ticket.created_at:
        age_minutes = max(0, int((now - ticket.created_at).total_seconds() // 60))
        if age_minutes < min_age_minutes:
            reasons.append(
                f"ticket age {age_minutes} minutes is below minimum {min_age_minutes} minutes"
            )
    else:
        reasons.append("ticket has no created_at timestamp")

    cooldown_cutoff = now - timedelta(minutes=cooldown_minutes)

    sent_links = (
        db.query(TicketMaintenanceLink)
        .filter(TicketMaintenanceLink.maintenance_status == "SENT")
        .filter(TicketMaintenanceLink.sent_at.isnot(None))
        .filter(TicketMaintenanceLink.sent_at >= cooldown_cutoff)
        .all()
    )

    duplicate_link = None
    for link in sent_links:
        other_ticket = db.query(Ticket).filter(Ticket.id == link.ticket_id).first()
        if not other_ticket or other_ticket.id == ticket.id:
            continue
        if (other_ticket.alert_name or "").strip() != alert_name:
            continue
        if not _same_asset_scope(ticket, other_ticket):
            continue
        duplicate_link = link
        break

    if duplicate_link:
        reasons.append(
            f"similar maintenance handoff already sent recently for same asset/alert "
            f"(ticket_id={duplicate_link.ticket_id}, maintenance_ticket_id={duplicate_link.maintenance_ticket_id})"
        )

    return {
        "eligible": len(reasons) == 0,
        "reasons": reasons,
        "meta": {
            **meta,
            "age_minutes": age_minutes,
            "inventory_id": ticket.inventory_id,
            "asset_name": getattr(inventory, "asset_name", None),
            "hostname": getattr(inventory, "hostname", None),
            "instance": ticket.instance,
            "alert_name": alert_name,
            "severity": ticket.severity,
            "duplicate_ticket_id": getattr(duplicate_link, "ticket_id", None) if duplicate_link else None,
            "duplicate_maintenance_ticket_id": getattr(duplicate_link, "maintenance_ticket_id", None) if duplicate_link else None,
        },
    }


@router.get("/{ticket_id}/maintenance-link", response_model=TicketMaintenanceLinkOut)
def get_maintenance_link(ticket_id: int, db: Session = Depends(get_db)):
    _get_ticket_or_404(db, ticket_id)

    link = db.query(TicketMaintenanceLink).filter(TicketMaintenanceLink.ticket_id == ticket_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Maintenance link not found")

    return link


@router.get("/{ticket_id}/maintenance-eligibility")
def get_maintenance_eligibility(ticket_id: int, db: Session = Depends(get_db)):
    ticket = _get_ticket_or_404(db, ticket_id)
    inventory = None
    if ticket.inventory_id:
        inventory = db.query(Inventory).filter(Inventory.id == ticket.inventory_id).first()

    result = _evaluate_handoff_policy(db, ticket, inventory)
    return {
        "ticket_id": ticket.id,
        **result,
    }


@router.post("/{ticket_id}/send-to-maintenance", response_model=TicketMaintenanceLinkOut)
def send_to_maintenance(
    ticket_id: int,
    request: Request,
    force_resend: bool = Query(False),
    actor: Actor = Depends(get_actor),
    db: Session = Depends(get_db),
):
    require_role(actor, ["OPERATOR", "ADMIN"])

    ticket = _get_ticket_or_404(db, ticket_id)
    inventory = None
    if ticket.inventory_id:
        inventory = db.query(Inventory).filter(Inventory.id == ticket.inventory_id).first()

    existing = db.query(TicketMaintenanceLink).filter(TicketMaintenanceLink.ticket_id == ticket.id).first()
    policy = _evaluate_handoff_policy(db, ticket, inventory)

    if not policy["eligible"] and not force_resend:
        write_audit(
            db,
            request=request,
            action="TICKET_SEND_TO_MAINTENANCE_BLOCKED",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={
                "ticket_id": ticket.id,
                "inventory_id": ticket.inventory_id,
                "existing_maintenance_ticket_id": getattr(existing, "maintenance_ticket_id", None) if existing else None,
                "existing_maintenance_status": getattr(existing, "maintenance_status", None) if existing else None,
                "reasons": policy["reasons"],
                "policy": policy["meta"],
            },
        )
        db.commit()
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Ticket is not eligible for maintenance handoff",
                "reasons": policy["reasons"],
                "policy": policy["meta"],
                "existing_maintenance_ticket_id": getattr(existing, "maintenance_ticket_id", None) if existing else None,
                "existing_maintenance_status": getattr(existing, "maintenance_status", None) if existing else None,
            },
        )

    if existing and existing.maintenance_ticket_id and not force_resend:
        return existing

    payload = _build_payload(ticket, inventory)
    api_base = _maintenance_api_base()
    web_base = _maintenance_web_base()

    if not existing:
        existing = TicketMaintenanceLink(
            ticket_id=ticket.id,
            maintenance_status="PENDING",
            maintenance_api_base=api_base,
            sent_by=actor.name,
            sent_role=actor.role,
            updated_at=datetime.utcnow(),
        )
        db.add(existing)
        db.flush()

    existing.maintenance_api_base = api_base
    existing.request_payload_json = _safe_json(payload)
    existing.sent_by = actor.name
    existing.sent_role = actor.role
    existing.updated_at = datetime.utcnow()
    existing.error_message = None

    try:
        auth_headers = _get_maintenance_auth_headers()
        response_data = _json_request(
            f"{api_base}/tickets/",
            method="POST",
            payload=payload,
            headers=auth_headers,
        )

        if not isinstance(response_data, dict):
            raise RuntimeError("Maintenance API create ticket response is not an object")

        maintenance_ticket_id = response_data.get("id")
        if not maintenance_ticket_id:
            raise RuntimeError("Maintenance API create ticket response does not contain id")

        existing.maintenance_ticket_id = int(maintenance_ticket_id)
        existing.maintenance_url = f"{web_base}/admin/tickets/{existing.maintenance_ticket_id}"
        existing.maintenance_status = "SENT"
        existing.response_payload_json = _safe_json(response_data)
        existing.error_message = None
        existing.sent_at = datetime.utcnow()
        existing.updated_at = datetime.utcnow()

        write_audit(
            db,
            request=request,
            action="TICKET_SENT_TO_MAINTENANCE",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={
                "ticket_id": ticket.id,
                "inventory_id": ticket.inventory_id,
                "maintenance_ticket_id": existing.maintenance_ticket_id,
                "maintenance_url": existing.maintenance_url,
                "maintenance_api_base": api_base,
                "force_resend": force_resend,
                "payload": payload,
                "policy": policy["meta"],
            },
        )

        db.commit()
        db.refresh(existing)
        return existing

    except Exception as e:
        existing.maintenance_status = "FAILED"
        existing.error_message = str(e)
        existing.updated_at = datetime.utcnow()

        write_audit(
            db,
            request=request,
            action="TICKET_SEND_TO_MAINTENANCE_FAILED",
            entity_type="ticket",
            entity_id=ticket.id,
            actor_name=actor.name,
            actor_role=actor.role,
            meta={
                "ticket_id": ticket.id,
                "inventory_id": ticket.inventory_id,
                "maintenance_api_base": api_base,
                "force_resend": force_resend,
                "payload": payload,
                "policy": policy["meta"],
                "error": str(e),
            },
        )

        db.commit()
        db.refresh(existing)

        raise HTTPException(status_code=503, detail=str(e))
