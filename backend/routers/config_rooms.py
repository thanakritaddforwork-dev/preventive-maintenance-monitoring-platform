from fastapi import APIRouter, HTTPException
from typing import Optional
from pydantic import BaseModel
import sqlite3

DB_PATH = "/var/lib/monitor-website/pm.db"

router = APIRouter(prefix="/api/rooms-config", tags=["config-rooms"])


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =========================
# SCHEMA
# =========================
class BuildingCreate(BaseModel):
    code: str
    name: Optional[str] = None


class RoomCreate(BaseModel):
    building_id: int
    room_code: str
    room_name: Optional[str] = None


class RoomUpdate(BaseModel):
    building_id: int
    room_code: str
    room_name: Optional[str] = None
    active: Optional[int] = 1


# =========================
# BUILDINGS
# =========================
@router.get("/buildings")
def list_buildings():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, code, name FROM buildings ORDER BY code"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.post("/buildings")
def create_building(payload: BuildingCreate):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO buildings (code, name) VALUES (?, ?)",
            (payload.code.strip().upper(), payload.name),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Building already exists")
    finally:
        conn.close()


# =========================
# ROOMS
# =========================
@router.get("/rooms")
def list_rooms(building_id: Optional[int] = None):
    conn = get_db()
    try:
        if building_id:
            rows = conn.execute(
                """
                SELECT r.id, r.room_code, r.room_name, r.active,
                       b.code as building_code
                FROM rooms r
                JOIN buildings b ON r.building_id = b.id
                WHERE r.building_id = ?
                ORDER BY r.room_code
                """,
                (building_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT r.id, r.room_code, r.room_name, r.active,
                       b.code as building_code
                FROM rooms r
                JOIN buildings b ON r.building_id = b.id
                ORDER BY b.code, r.room_code
                """
            ).fetchall()

        return [dict(r) for r in rows]
    finally:
        conn.close()


@router.get("/rooms/{room_id}")
def get_room(room_id: int):
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT r.id, r.building_id, r.room_code, r.room_name, r.active,
                   b.code as building_code
            FROM rooms r
            JOIN buildings b ON r.building_id = b.id
            WHERE r.id = ?
            """,
            (room_id,),
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Room not found")

        return dict(row)
    finally:
        conn.close()


@router.post("/rooms")
def create_room(payload: RoomCreate):
    conn = get_db()
    try:
        building = conn.execute(
            "SELECT id FROM buildings WHERE id = ?",
            (payload.building_id,),
        ).fetchone()

        if not building:
            raise HTTPException(status_code=404, detail="Building not found")

        cur = conn.execute(
            """
            INSERT INTO rooms (building_id, room_code, room_name, active)
            VALUES (?, ?, ?, 1)
            """,
            (
                payload.building_id,
                payload.room_code.strip().upper(),
                payload.room_name,
            ),
        )
        conn.commit()
        return {"id": cur.lastrowid}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Room already exists")
    finally:
        conn.close()


@router.put("/rooms/{room_id}")
def update_room(room_id: int, payload: RoomUpdate):
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM rooms WHERE id = ?",
            (room_id,),
        ).fetchone()

        if not existing:
            raise HTTPException(status_code=404, detail="Room not found")

        building = conn.execute(
            "SELECT id FROM buildings WHERE id = ?",
            (payload.building_id,),
        ).fetchone()

        if not building:
            raise HTTPException(status_code=404, detail="Building not found")

        try:
            cur = conn.execute(
                """
                UPDATE rooms
                SET building_id = ?,
                    room_code = ?,
                    room_name = ?,
                    active = ?
                WHERE id = ?
                """,
                (
                    payload.building_id,
                    payload.room_code.strip().upper(),
                    payload.room_name,
                    1 if payload.active else 0,
                    room_id,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=400,
                detail="Room already exists in this building"
            )

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Room not found")

        row = conn.execute(
            """
            SELECT r.id, r.building_id, r.room_code, r.room_name, r.active,
                   b.code as building_code
            FROM rooms r
            JOIN buildings b ON r.building_id = b.id
            WHERE r.id = ?
            """,
            (room_id,),
        ).fetchone()

        return dict(row)
    finally:
        conn.close()


@router.delete("/rooms/{room_id}")
def delete_room(room_id: int):
    conn = get_db()
    try:
        cur = conn.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        conn.commit()

        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Room not found")

        return {"ok": True}
    finally:
        conn.close()
