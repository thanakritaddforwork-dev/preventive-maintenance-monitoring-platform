from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import PortAudit, PortAuditItem, Rack
from datetime import datetime, timezone
import requests

router = APIRouter(prefix="/port-audit", tags=["port-audit"])

# 🔥 ใส่ IP laptop ที่รัน scanner.py
SCANNER_URL = "http://10.198.200.123:5000/scan"


# =========================
# TIME HELPER
# =========================
def utc_now():
    return datetime.now(timezone.utc)


# =========================
# 🔥 TRIGGER SCAN (FINAL)
# =========================
@router.post("/trigger-scan")
def trigger_scan(payload: dict, db: Session = Depends(get_db)):
    try:
        room = payload.get("room")
        rack_number = payload.get("rack")

        if not room or not rack_number:
            return {"ok": False, "error": "missing room or rack"}

        # =========================
        # หา rack → IP
        # =========================
        rack = (
            db.query(Rack)
            .filter(
                Rack.room_name == room,
                Rack.rack_number == rack_number
            )
            .first()
        )

        if not rack or not rack.switch_ip:
            return {"ok": False, "error": "rack ip not configured"}

        ip = rack.switch_ip

        # =========================
        # ยิง scanner
        # =========================
        r = requests.get(f"{SCANNER_URL}?ip={ip}", timeout=10)
        data = r.json()

        if not data.get("ok"):
            return {"ok": False, "error": "scanner failed"}

        ports = data.get("ports", [])

        # =========================
        # SAVE SNAPSHOT
        # =========================
        audit = PortAudit(
            switch_ip=ip,
            room=room,
            rack=rack_number,
            created_at=utc_now(),
        )

        db.add(audit)
        db.flush()

        for p in ports:
            db.add(
                PortAuditItem(
                    audit_id=audit.id,
                    port=p.get("port"),
                    status=p.get("status"),
                )
            )

        db.commit()

        return {
            "ok": True,
            "ip": ip,
            "ports": ports
        }

    except Exception as e:
        return {"ok": False, "error": str(e)}


# =========================
# LATEST
# =========================
@router.get("/latest")
def latest(ip: str, db: Session = Depends(get_db)):
    audit = (
        db.query(PortAudit)
        .filter(PortAudit.switch_ip == ip)
        .order_by(PortAudit.created_at.desc())
        .first()
    )

    if not audit:
        return {"ports": []}

    items = db.query(PortAuditItem).filter(PortAuditItem.audit_id == audit.id)

    return {
        "created_at": audit.created_at.isoformat(),
        "ports": [{"port": i.port, "status": i.status} for i in items],
    }


# =========================
# HISTORY
# =========================
@router.get("/history")
def history(ip: str, db: Session = Depends(get_db)):
    audits = (
        db.query(PortAudit)
        .filter(PortAudit.switch_ip == ip)
        .order_by(PortAudit.created_at.desc())
        .limit(20)
        .all()
    )

    return {
        "history": [
            {
                "id": a.id,
                "created_at": a.created_at.isoformat(),
            }
            for a in audits
        ]
    }


# =========================
# SNAPSHOT DETAIL
# =========================
@router.get("/snapshot/{audit_id}")
def snapshot(audit_id: int, db: Session = Depends(get_db)):
    items = (
        db.query(PortAuditItem)
        .filter(PortAuditItem.audit_id == audit_id)
        .all()
    )

    return {
        "ports": [
            {"port": i.port, "status": i.status}
            for i in items
        ]
    }
