# routers/topology.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket

router = APIRouter(prefix="/api", tags=["Topology"])


def compute_health(open_tickets: int) -> str:
    if open_tickets > 0:
        return "WARNING"
    return "OK"


@router.get("/topology")
def get_topology(db: Session = Depends(get_db)):
    inventories = db.query(Inventory).all()

    nodes = []
    links = []

    for inv in inventories:
        open_tickets = db.query(Ticket).filter(
            Ticket.inventory_id == inv.id,
            Ticket.status == "OPEN"
        ).count()

        nodes.append({
            "id": inv.id,
            "label": inv.hostname,
            "ip": inv.ip_address,
            "room": inv.location,
            "type": inv.device_type,
            "health": compute_health(open_tickets),
        })

    # NOTE:
    # links จะเติมจริงตอน phase graph
    return {
        "nodes": nodes,
        "links": links,
    }
