# routers/sla.py

from collections import defaultdict
from datetime import datetime, timedelta
import os

import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket, SLASnapshot

router = APIRouter(prefix="/api/sla", tags=["SLA"])


# =========================================================
# Helpers
# =========================================================

def _prom_base():
    return (os.getenv("PROMETHEUS_BASE") or "http://127.0.0.1:9090").rstrip("/")


def _query_prom(promql: str):
    try:
        r = requests.get(
            f"{_prom_base()}/api/v1/query",
            params={"query": promql},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()["data"]["result"]
    except Exception:
        return []


def calculate_sla_percent(instance: str, days: int = 30):
    promql = f'avg_over_time(up{{instance="{instance}"}}[{days}d])'
    result = _query_prom(promql)

    if not result:
        return None

    uptime_ratio = float(result[0]["value"][1])
    return round(uptime_ratio * 100, 5)


def _clean_text(value):
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _inventory_columns(db: Session) -> set[str]:
    rows = db.execute(text("PRAGMA table_info(inventory)")).mappings().all()
    return {str(r["name"]) for r in rows}


def _select_inventory_meta(db: Session, inventory_id: int) -> dict:
    cols = _inventory_columns(db)
    wanted = ["room", "building", "location"]
    actual = [c for c in wanted if c in cols]

    if not actual:
        return {}

    row = db.execute(
        text(
            f"""
            SELECT {", ".join(actual)}
            FROM inventory
            WHERE id = :inventory_id
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).mappings().first()

    return dict(row) if row else {}


def _room_key(inv: Inventory, db: Session) -> str:
    """
    Source of truth for room-based SLA grouping:
    1) inventory.room
    2) inventory.location
    3) inventory.building
    4) Unknown

    Important:
    We read these via raw SQL because the current ORM Inventory model
    may not expose all newer columns such as room/building.
    """
    meta = _select_inventory_meta(db, inv.id)

    room = _clean_text(meta.get("room"))
    location = _clean_text(meta.get("location"))
    building = _clean_text(meta.get("building"))

    return room or location or building or "Unknown"


def _inventory_meta_payload(inv: Inventory, db: Session) -> dict:
    meta = _select_inventory_meta(db, inv.id)
    room = _clean_text(meta.get("room"))
    location = _clean_text(meta.get("location"))
    building = _clean_text(meta.get("building"))

    return {
        "room": room or location or building or "Unknown",
        "building": building,
        "location": location,
    }


def _same_room_name(a: str, b: str) -> bool:
    return (_clean_text(a) or "").lower() == (_clean_text(b) or "").lower()


# =========================================================
# Core SLA Logic (Single Source of Truth)
# =========================================================

def compute_sla_for_inventory(inv: Inventory, db: Session):
    instance = f"{inv.ip_address}:9100"

    prom_sla = calculate_sla_percent(instance)

    now = datetime.utcnow()
    period_start = now - timedelta(days=30)

    downtime_seconds = 0

    tickets = (
        db.query(Ticket)
        .filter(
            Ticket.inventory_id == inv.id,
            Ticket.created_at >= period_start,
        )
        .all()
    )

    for t in tickets:
        if t.status == "RESOLVED" and t.resolved_at:
            delta = (t.resolved_at - t.created_at).total_seconds()
            downtime_seconds += max(delta, 0)

    total_seconds = 30 * 24 * 60 * 60

    ticket_based_sla = (
        100 - ((downtime_seconds / total_seconds) * 100)
        if downtime_seconds > 0
        else 100
    )

    if prom_sla is None:
        final_sla = ticket_based_sla
    else:
        final_sla = round((prom_sla + ticket_based_sla) / 2, 5)

    breached = final_sla < 99.5

    return final_sla, breached


# =========================================================
# Node SLA
# =========================================================

@router.get("/node/{inventory_id}")
def sla_node(inventory_id: int, db: Session = Depends(get_db)):
    inv = db.query(Inventory).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    sla, breached = compute_sla_for_inventory(inv, db)
    meta = _inventory_meta_payload(inv, db)

    return {
        "node": inv.hostname,
        "ip": inv.ip_address,
        "uptime_percent": sla,
        "breached": breached,
        "period_days": 30,
        "room": meta["room"],
        "building": meta["building"],
        "location": meta["location"],
    }


# =========================================================
# Dashboard
# =========================================================

@router.get("/dashboard")
def sla_dashboard(db: Session = Depends(get_db)):
    nodes = db.query(Inventory).all()

    if not nodes:
        return {
            "global_sla": None,
            "node_count": 0,
            "breach_count": 0,
            "distribution": {
                "gold": 0,
                "silver": 0,
                "bronze": 0,
                "breach": 0,
            },
            "nodes": [],
        }

    results = []
    total_sla = 0.0
    breach_count = 0

    distribution = {
        "gold": 0,
        "silver": 0,
        "bronze": 0,
        "breach": 0,
    }

    for node in nodes:
        sla, breached = compute_sla_for_inventory(node, db)
        meta = _inventory_meta_payload(node, db)

        if sla >= 99.99:
            tier = "Gold"
            distribution["gold"] += 1
        elif sla >= 99.9:
            tier = "Silver"
            distribution["silver"] += 1
        elif sla >= 99.5:
            tier = "Bronze"
            distribution["bronze"] += 1
        else:
            tier = "Breach"
            distribution["breach"] += 1

        if breached:
            breach_count += 1

        total_sla += sla

        results.append({
            "id": node.id,
            "hostname": node.hostname,
            "ip": node.ip_address,
            "uptime_percent": sla,
            "breached": breached,
            "tier": tier,
            "room": meta["room"],
            "building": meta["building"],
            "location": meta["location"],
        })

    global_sla = round(total_sla / len(results), 5)

    return {
        "global_sla": global_sla,
        "node_count": len(results),
        "breach_count": breach_count,
        "distribution": distribution,
        "nodes": results,
    }


# =========================================================
# Snapshot
# =========================================================

@router.post("/snapshot")
def sla_snapshot(db: Session = Depends(get_db)):
    inventories = db.query(Inventory).all()

    for inv in inventories:
        sla, _ = compute_sla_for_inventory(inv, db)

        snap = SLASnapshot(
            inventory_id=inv.id,
            uptime_percent=sla,
            period_days=30
        )

        db.add(snap)

    db.commit()

    return {"status": "snapshot_created"}


# =========================================================
# SLA Trend (Node)
# =========================================================

@router.get("/trend/{inventory_id}")
def sla_trend(inventory_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(SLASnapshot)
        .filter(SLASnapshot.inventory_id == inventory_id)
        .order_by(SLASnapshot.created_at.asc())
        .all()
    )

    return [
        {
            "date": r.created_at,
            "uptime_percent": r.uptime_percent
        }
        for r in rows
    ]


# =========================================================
# SLA by Room (SYNCED TO INVENTORY ROOM)
# =========================================================

@router.get("/rooms")
def sla_by_room(db: Session = Depends(get_db)):
    inventories = db.query(Inventory).all()
    room_data = defaultdict(list)

    for inv in inventories:
        sla, _ = compute_sla_for_inventory(inv, db)
        room_name = _room_key(inv, db)
        room_data[room_name].append(sla)

    results = []

    for room, slas in room_data.items():
        avg_sla = round(sum(slas) / len(slas), 5)
        breach_count = len([x for x in slas if x < 99.5])

        results.append({
            "room": room,
            "avg_sla": avg_sla,
            "node_count": len(slas),
            "breach_count": breach_count,
        })

    results.sort(key=lambda x: (x["avg_sla"], x["room"].lower()))
    return results


# =========================================================
# Room Detail (SYNCED TO INVENTORY ROOM)
# =========================================================

@router.get("/room/{room_name}")
def sla_room_detail(room_name: str, db: Session = Depends(get_db)):
    clean_room = _clean_text(room_name)
    if not clean_room:
        raise HTTPException(status_code=400, detail="Room name is required")

    all_nodes = db.query(Inventory).all()
    nodes = [inv for inv in all_nodes if _same_room_name(_room_key(inv, db), clean_room)]

    if not nodes:
        raise HTTPException(status_code=404, detail="Room not found")

    results = []
    total_sla = 0.0
    breach_count = 0

    for node in nodes:
        sla, breached = compute_sla_for_inventory(node, db)
        meta = _inventory_meta_payload(node, db)

        total_sla += sla
        if breached:
            breach_count += 1

        results.append({
            "id": node.id,
            "hostname": node.hostname,
            "ip": node.ip_address,
            "uptime_percent": sla,
            "breached": breached,
            "room": meta["room"],
            "building": meta["building"],
            "location": meta["location"],
        })

    avg_sla = round(total_sla / len(results), 5)

    return {
        "room": _room_key(nodes[0], db),
        "avg_sla": avg_sla,
        "node_count": len(results),
        "breach_count": breach_count,
        "nodes": results,
    }


# =========================================================
# Room SLA Auto Enforcement (OPEN + AUTO RESOLVE)
# =========================================================

@router.post("/rooms/check")
def check_room_sla(db: Session = Depends(get_db)):
    inventories = db.query(Inventory).all()
    room_data = defaultdict(list)

    for inv in inventories:
        sla, _ = compute_sla_for_inventory(inv, db)
        room_name = _room_key(inv, db)
        room_data[room_name].append(sla)

    opened = []
    resolved = []

    for room, slas in room_data.items():
        avg_sla = sum(slas) / len(slas)
        breach = avg_sla < 99.5

        existing = db.query(Ticket).filter(
            Ticket.alert_name == "ROOM_SLA_BREACH",
            Ticket.instance == room,
            Ticket.status == "OPEN"
        ).first()

        if breach and not existing:
            ticket = Ticket(
                alert_name="ROOM_SLA_BREACH",
                instance=room,
                severity="critical",
                status="OPEN",
                inventory_id=None
            )
            db.add(ticket)
            opened.append(room)

        if not breach and existing:
            existing.status = "RESOLVED"
            existing.resolved_at = datetime.utcnow()
            resolved.append(room)

    db.commit()

    return {
        "rooms_checked": len(room_data),
        "opened": opened,
        "resolved": resolved
    }


# =========================================================
# University SLA Compliance
# =========================================================

@router.get("/compliance")
def sla_compliance(db: Session = Depends(get_db)):
    nodes = db.query(Inventory).all()

    if not nodes:
        return {
            "total_nodes": 0,
            "good_nodes": 0,
            "compliance_percent": 0
        }

    good = 0

    for node in nodes:
        sla, _ = compute_sla_for_inventory(node, db)
        if sla >= 99.5:
            good += 1

    compliance = round((good / len(nodes)) * 100, 2)

    return {
        "total_nodes": len(nodes),
        "good_nodes": good,
        "compliance_percent": compliance
    }


# =========================================================
# Incident Metrics (MTTR / Incident Count)
# =========================================================

@router.get("/incident-metrics")
def sla_incident_metrics(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    period_start = now - timedelta(days=30)

    tickets = (
        db.query(Ticket)
        .filter(Ticket.created_at >= period_start)
        .all()
    )

    if not tickets:
        return {
            "total_incidents": 0,
            "resolved_incidents": 0,
            "avg_mttr_minutes": 0,
            "max_mttr_minutes": 0,
            "open_incidents": 0
        }

    total_incidents = len(tickets)

    resolved = [
        t for t in tickets
        if t.status == "RESOLVED" and t.resolved_at
    ]

    resolved_incidents = len(resolved)
    open_incidents = len([t for t in tickets if t.status != "RESOLVED"])

    if resolved_incidents == 0:
        avg_mttr = 0
        max_mttr = 0
    else:
        durations = [
            (t.resolved_at - t.created_at).total_seconds() / 60
            for t in resolved
        ]

        avg_mttr = round(sum(durations) / len(durations), 2)
        max_mttr = round(max(durations), 2)

    return {
        "total_incidents": total_incidents,
        "resolved_incidents": resolved_incidents,
        "avg_mttr_minutes": avg_mttr,
        "max_mttr_minutes": max_mttr,
        "open_incidents": open_incidents
    }


# =========================================================
# SLA Breach Trend (30 Days)
# =========================================================

@router.get("/breach-trend")
def sla_breach_trend(db: Session = Depends(get_db)):
    from sqlalchemy import func

    rows = (
        db.query(
            func.date(Ticket.created_at).label("day"),
            func.count(Ticket.id).label("count"),
        )
        .filter(Ticket.alert_name == "ROOM_SLA_BREACH")
        .group_by(func.date(Ticket.created_at))
        .order_by(func.date(Ticket.created_at))
        .all()
    )

    return [
        {
            "date": str(r.day),
            "count": r.count,
        }
        for r in rows
    ]


# =========================================================
# Global SLA Trend (Enterprise Level)
# =========================================================

@router.get("/global-trend")
def sla_global_trend(db: Session = Depends(get_db)):
    from sqlalchemy import func, case

    rows = (
        db.query(
            func.date(SLASnapshot.created_at).label("snap_date"),
            func.avg(SLASnapshot.uptime_percent).label("avg_sla"),
            func.sum(
                case(
                    (SLASnapshot.uptime_percent < 99.5, 1),
                    else_=0,
                )
            ).label("breach_count"),
        )
        .group_by(func.date(SLASnapshot.created_at))
        .order_by(func.date(SLASnapshot.created_at))
        .all()
    )

    return [
        {
            "date": str(r.snap_date),
            "global_sla": round(float(r.avg_sla or 0), 5),
            "breach_count": int(r.breach_count or 0),
        }
        for r in rows
    ]
