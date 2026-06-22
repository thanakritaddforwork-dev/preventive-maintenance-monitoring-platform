from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from database import get_db

router = APIRouter(prefix="/api/port-audits", tags=["port_audits"])


# =========================
# 🔥 PORT HISTORY
# =========================
@router.get("/port-history/{room}/{rack}/{port}")
def get_port_history(room: str, rack: int, port: str, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT
                pa.id AS snapshot_id,
                pa.created_at,
                pai.status
            FROM port_audits pa
            JOIN port_audit_items pai
                ON pa.id = pai.audit_id
            WHERE pa.room = :room
              AND pa.rack = :rack
              AND (pai.port = :port OR pai.port_name = :port)
            ORDER BY pa.created_at DESC
        """),
        {"room": room, "rack": rack, "port": port}
    ).mappings().all()

    return rows


# =========================
# 🔥 FLAP DETECTION (ใช้ 2 snapshot ล่าสุด)
# =========================
@router.get("/flap/{room}/{rack}")
def detect_flap_all(room: str, rack: int, db: Session = Depends(get_db)):
    audits = db.execute(
        text("""
            SELECT id
            FROM port_audits
            WHERE room = :room AND rack = :rack
            ORDER BY created_at DESC
            LIMIT 2
        """),
        {"room": room, "rack": rack}
    ).fetchall()

    if len(audits) < 2:
        return {}

    current_id = audits[0][0]
    prev_id = audits[1][0]

    current = db.execute(
        text("""
            SELECT port, status
            FROM port_audit_items
            WHERE audit_id = :id
        """),
        {"id": current_id}
    ).fetchall()

    prev = db.execute(
        text("""
            SELECT port, status
            FROM port_audit_items
            WHERE audit_id = :id
        """),
        {"id": prev_id}
    ).fetchall()

    prev_map = {p: s for p, s in prev}

    result = {}

    for port, status in current:
        prev_status = prev_map.get(port)

        result[port] = (
            prev_status is not None and prev_status != status
        )

    return result


# =========================
# GET port items
# =========================
@router.get("/{audit_id}/items")
def get_items(audit_id: int, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT port, status
            FROM port_audit_items
            WHERE audit_id = :audit_id
            ORDER BY port
        """),
        {"audit_id": audit_id}
    ).mappings().all()

    return rows


# =========================
# GET snapshots
# =========================
@router.get("/{room}/{rack}")
def get_snapshots(room: str, rack: int, db: Session = Depends(get_db)):
    rows = db.execute(
        text("""
            SELECT id, room, rack, switch_ip, created_at
            FROM port_audits
            WHERE room = :room AND rack = :rack
            ORDER BY created_at DESC
        """),
        {"room": room, "rack": rack}
    ).mappings().all()

    return rows
