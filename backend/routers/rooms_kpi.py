# routers/rooms_kpi.py

from typing import List, Dict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket

router = APIRouter(
    prefix="/api/rooms",
    tags=["Rooms-KPI"],
)


# =========================================================
# Helpers
# =========================================================

def worst_health(values: List[str]) -> str:
    if "CRITICAL" in values:
        return "CRITICAL"
    if "WARNING" in values:
        return "WARNING"
    if "UNKNOWN" in values:
        return "UNKNOWN"
    return "OK"


# =========================================================
# API: GET /api/rooms/kpi
# =========================================================

@router.get("/kpi")
def rooms_kpi(db: Session = Depends(get_db)):
    """
    Room KPI (Conservative / Production-safe)
    - No Prometheus import
    - DB + Ticket only
    - Swagger-safe
    """

    inventories = db.query(Inventory).all()
    rooms: Dict[str, Dict] = {}

    for inv in inventories:
        room = inv.location or "UNKNOWN"

        if room not in rooms:
            rooms[room] = {
                "room": room,
                "nodes": 0,
                "open_tickets": 0,
                "healths": [],
            }

        rooms[room]["nodes"] += 1

        open_tickets = (
            db.query(Ticket)
            .filter(
                Ticket.inventory_id == inv.id,
                Ticket.status == "OPEN"
            )
            .count()
        )

        rooms[room]["open_tickets"] += open_tickets

        if open_tickets > 0:
            rooms[room]["healths"].append("WARNING")
        else:
            rooms[room]["healths"].append("OK")

    result = []
    for r in rooms.values():
        result.append({
            "room": r["room"],
            "nodes": r["nodes"],
            "open_tickets": r["open_tickets"],
            "health": worst_health(r["healths"]),
        })

    return result
