from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from models import Rack

router = APIRouter(prefix="/racks", tags=["racks"])


# =========================
# GET ALL RACKS BY ROOM
# =========================
@router.get("/{room}")
def get_racks_by_room(room: str, db: Session = Depends(get_db)):
    racks = (
        db.query(Rack)
        .filter(Rack.room_name == room)
        .order_by(Rack.rack_number.asc())
        .all()
    )

    return [
        {
            "rack": r.rack_number,
            "switch_ip": r.switch_ip,
        }
        for r in racks
    ]


# =========================
# GET SINGLE
# =========================
@router.get("/{room}/{rack}")
def get_rack(room: str, rack: int, db: Session = Depends(get_db)):
    r = (
        db.query(Rack)
        .filter(Rack.room_name == room, Rack.rack_number == rack)
        .first()
    )

    if not r:
        return {"room": room, "rack": rack, "switch_ip": None}

    return {
        "room": room,
        "rack": rack,
        "switch_ip": r.switch_ip,
    }


# =========================
# CREATE RACK (🔥 NEW)
# =========================
@router.post("/{room}")
def create_racks(room: str, count: int, db: Session = Depends(get_db)):
    existing = (
        db.query(Rack)
        .filter(Rack.room_name == room)
        .count()
    )

    new_racks = []

    for i in range(existing + 1, existing + count + 1):
        r = Rack(
            room_name=room,
            rack_number=i,
        )
        db.add(r)
        new_racks.append(i)

    db.commit()

    return {"ok": True, "created": new_racks}


# =========================
# SET IP
# =========================
@router.post("/{room}/{rack}/ip")
def save_ip(room: str, rack: int, ip: str, db: Session = Depends(get_db)):
    r = (
        db.query(Rack)
        .filter(Rack.room_name == room, Rack.rack_number == rack)
        .first()
    )

    if not r:
        r = Rack(
            room_name=room,
            rack_number=rack,
            switch_ip=ip,
        )
        db.add(r)
    else:
        r.switch_ip = ip

    db.commit()

    return {"ok": True, "ip": ip}


# =========================
# DELETE
# =========================
@router.delete("/{room}/{rack}")
def delete_rack(room: str, rack: int, db: Session = Depends(get_db)):
    r = (
        db.query(Rack)
        .filter(Rack.room_name == room, Rack.rack_number == rack)
        .first()
    )

    if not r:
        return {"ok": False}

    db.delete(r)
    db.commit()

    return {"ok": True}
