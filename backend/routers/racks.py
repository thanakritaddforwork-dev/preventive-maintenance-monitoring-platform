from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database import get_db
from models import Rack

router = APIRouter(prefix="/racks", tags=["racks"])


# =========================
# GET ALL RACKS
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
# 🔥 SET RACK COUNT
# =========================
@router.post("/{room}")
def set_racks(
    room: str,
    count: int = Query(...),
    db: Session = Depends(get_db),
):
    # ลบของเก่าทั้งหมด
    db.query(Rack).filter(Rack.room_name == room).delete()

    # สร้างใหม่
    for i in range(1, count + 1):
        db.add(
            Rack(
                room_name=room,
                rack_number=i,
            )
        )

    db.commit()

    return {"ok": True, "total": count}


# =========================
# GET SINGLE
# =========================
@router.get("/{room}/{rack}")
def get_rack(room: str, rack: int, db: Session = Depends(get_db)):
    rack = int(rack)  # 🔥 กัน type เพี้ยน

    r = (
        db.query(Rack)
        .filter(
            Rack.room_name == room,
            Rack.rack_number == rack
        )
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
# SET IP
# =========================
@router.post("/{room}/{rack}/ip")
def save_ip(
    room: str,
    rack: int,
    ip: str = Query(...),
    db: Session = Depends(get_db),
):
    rack = int(rack)  # 🔥 กัน type เพี้ยน

    r = (
        db.query(Rack)
        .filter(
            Rack.room_name == room,
            Rack.rack_number == rack
        )
        .first()
    )

    if not r:
        r = Rack(
            room_name=room,
            rack_number=rack,
            switch_ip=ip
        )
        db.add(r)
    else:
        r.switch_ip = ip

    db.commit()

    return {"ok": True}


# =========================
# 🔥 DELETE (FIX แน่นอน)
# =========================
@router.delete("/{room}/{rack}")
def delete_rack(room: str, rack: int, db: Session = Depends(get_db)):
    rack = int(rack)  # 🔥 สำคัญมาก

    q = db.query(Rack).filter(
        Rack.room_name == room,
        Rack.rack_number == rack
    )

    found = q.first()

    if not found:
        return {"ok": False, "error": "not found"}

    # 🔥 ใช้ delete() ชัวร์กว่า db.delete()
    q.delete()
    db.commit()

    return {"ok": True}
