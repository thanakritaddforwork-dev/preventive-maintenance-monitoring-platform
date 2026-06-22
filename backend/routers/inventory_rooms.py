# routers/inventory_rooms.py

from typing import Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket

# =========================================================
# Router (Room namespace — IMPORTANT)
# =========================================================
router = APIRouter(prefix="/api/rooms", tags=["Rooms"])


# =========================================================
# Local Health Logic (INLINE – SAFE FOR PHASE 9)
# =========================================================

def compute_node_health(
    up: bool | None,
    open_tickets: int,
) -> str:
    if up is None:
        return "UNKNOWN"
    if up is False:
        return "CRITICAL"
    if open_tickets > 0:
        return "WARNING"
    return "OK"


def _room_health_worst_of(healths: List[str]) -> str:
    """
    Room health aggregation:
    CRITICAL > WARNING > UNKNOWN > OK
    """
    if "CRITICAL" in healths:
        return "CRITICAL"
    if "WARNING" in healths:
        return "WARNING"
    if "UNKNOWN" in healths:
        return "UNKNOWN"
    return "OK"


# =========================================================
# API: GET /api/rooms
# =========================================================

@router.get("")
def list_inventory_by_room(db: Session = Depends(get_db)):
    """
    Room / Location overview (Production-safe)
    - Group inventory by location (room)
    - Conservative health logic (no Prometheus coupling)
    - Used by NOC Room View
    """

    inventories = (
        db.query(Inventory)
        .order_by(Inventory.location.asc(), Inventory.hostname.asc())
        .all()
    )

    rooms: Dict[str, Dict] = {}

    for inv in inventories:
        room = inv.location or "UNKNOWN"

        if room not in rooms:
            rooms[room] = {
                "room": room,
                "total": 0,
                "health": {
                    "OK": 0,
                    "WARNING": 0,
                    "CRITICAL": 0,
                    "UNKNOWN": 0,
                },
                "nodes": [],
            }

        # -----------------------------------------
        # Tickets (DB only)
        # -----------------------------------------
        open_tickets = (
            db.query(Ticket)
            .filter(
                Ticket.inventory_id == inv.id,
                Ticket.status == "OPEN"
            )
            .count()
        )

        # -----------------------------------------
        # Node health (room-level, conservative)
        # -----------------------------------------
        health = compute_node_health(
            up=True,  # room view assumes reachable
            open_tickets=open_tickets,
        )

        rooms[room]["total"] += 1
        rooms[room]["health"][health] += 1

        rooms[room]["nodes"].append({
            "id": inv.id,
            "hostname": inv.hostname,
            "ip_address": inv.ip_address,
            "health": health,
            "openTickets": open_tickets,
        })

    # -----------------------------------------
    # Final response
    # -----------------------------------------
    result = []

    for room_data in rooms.values():
        room_health = _room_health_worst_of(
            [node["health"] for node in room_data["nodes"]]
        )

        result.append({
            "room": room_data["room"],
            "total": room_data["total"],
            "roomHealth": room_health,
            "health": room_data["health"],
            "nodes": room_data["nodes"],
        })

    return result
