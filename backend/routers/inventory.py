import json
import os
from datetime import datetime, timezone
from typing import List, Optional, Dict, Tuple, Any

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory, Ticket, AuditLog
from schemas import (
    InventoryOut,
    TicketOut,
    InventorySummaryOut,
    InventoryCreate,
    InventoryMetadataUpdate,
)
from services.prometheus_targets import sync_inventory_to_prometheus

router = APIRouter(prefix="/api/inventory", tags=["Inventory"])


# =========================================================
# Helpers
# =========================================================

def _ticket_to_out(t: Ticket) -> Optional[TicketOut]:
    if not t:
        return None
    if getattr(t, "severity", None) is None:
        t.severity = "unknown"
    return TicketOut.model_validate(t, from_attributes=True)


def _prom_base() -> str:
    return (os.getenv("PROMETHEUS_BASE") or "http://127.0.0.1:9090").rstrip("/")


def _fetch_prom_up_map() -> Optional[Dict[str, float]]:
    try:
        r = requests.get(
            f"{_prom_base()}/api/v1/query",
            params={"query": "up"},
            timeout=3,
        )
        r.raise_for_status()
        data = r.json()["data"]["result"]
    except Exception:
        return None

    out: Dict[str, float] = {}
    for item in data:
        inst = item["metric"].get("instance")
        val = float(item["value"][1])
        if inst:
            out[inst] = val
    return out


def _default_monitoring(
    device_type: Optional[str],
    monitoring_type: Optional[str],
    scrape_port: Optional[int],
) -> Tuple[Optional[str], Optional[int]]:
    mt = monitoring_type
    port = scrape_port

    normalized_type = (device_type or "").strip().lower()

    if not mt:
        if normalized_type in ("network", "switch", "router", "firewall", "ap", "other"):
            mt = "snmp"
        elif normalized_type in ("windows_pc", "pc"):
            mt = "windows_exporter"
        else:
            mt = "node_exporter"

    if port is None:
        if mt == "node_exporter":
            port = 9100
        elif mt == "windows_exporter":
            port = 9182
        elif mt == "snmp":
            port = 161
        elif mt == "blackbox":
            port = None

    return mt, port


def _status_from_prom(
    ip: str,
    prom_map: Optional[Dict[str, float]],
    monitoring_type: Optional[str],
    scrape_port: Optional[int],
) -> Optional[str]:
    if prom_map is None:
        return None

    mt, port = _default_monitoring(None, monitoring_type, scrape_port)

    candidates = []

    if port is not None:
        candidates.append(f"{ip}:{port}")

    if mt == "node_exporter":
        candidates.append(f"{ip}:9100")
    elif mt == "windows_exporter":
        candidates.append(f"{ip}:9182")
    elif mt == "snmp":
        candidates.append(ip)

    for inst in candidates:
        if prom_map.get(inst, 0) >= 1:
            return "UP"

    for inst, val in prom_map.items():
        if inst.startswith(ip) and val >= 1:
            return "UP"

    return "DOWN"


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except Exception:
            return None

    return None


def _agent_up_seconds() -> int:
    try:
        return int(os.getenv("AGENT_UP_SECONDS", "120"))
    except Exception:
        return 120


def _agent_status_from_last_seen(last_seen_at: Any) -> str:
    parsed = _parse_dt(last_seen_at)
    if not parsed:
        return "DOWN"

    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    return "UP" if age <= _agent_up_seconds() else "DOWN"


def _inventory_columns(db: Session) -> set[str]:
    rows = db.execute(text("PRAGMA table_info(inventory)")).mappings().all()
    return {str(r["name"]) for r in rows}


def _select_inventory_extra_map(
    db: Session,
    inventory_id: int,
    wanted: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cols = _inventory_columns(db)

    if wanted is None:
        wanted = [
            "current_ip",
            "room",
            "building",
            "os_type",
            "last_seen_at",
            "device_uid",
            "os_version",
            "agent_version",
            "machine_guid",
            "bios_serial",
            "motherboard_serial",
            "mac_primary",
            "manufacturer",
            "model",
            "cpu_model",
            "ram_bytes",
            "last_boot_time",
            "identity_source",
            "is_discovered",
        ]

    actual = [c for c in wanted if c in cols]
    if not actual:
        return {}

    sql = f"""
        SELECT {", ".join(actual)}
        FROM inventory
        WHERE id = :inventory_id
        LIMIT 1
    """

    row = db.execute(
        text(sql),
        {"inventory_id": inventory_id},
    ).mappings().first()

    return dict(row) if row else {}


def _get_inventory_extra(db: Session, inventory_id: int) -> Dict[str, Any]:
    return _select_inventory_extra_map(
        db,
        inventory_id,
        wanted=[
            "current_ip",
            "room",
            "building",
            "os_type",
            "last_seen_at",
            "device_uid",
            "os_version",
            "agent_version",
            "machine_guid",
            "bios_serial",
            "motherboard_serial",
            "mac_primary",
            "manufacturer",
            "model",
            "cpu_model",
            "ram_bytes",
            "last_boot_time",
            "identity_source",
            "is_discovered",
        ],
    )


def _is_agent_device(inv: Inventory, extra: Dict[str, Any]) -> bool:
    device_type = str(inv.device_type or "").lower()
    monitoring_type = str(inv.monitoring_type or "").lower()
    os_type = str(extra.get("os_type") or "").lower()

    return (
        monitoring_type == "agent"
        or device_type == "pc"
        or device_type == "windows_pc"
        or os_type == "windows"
    )


def _status_live(db: Session, inv: Inventory, prom_map: Optional[Dict[str, float]]) -> str:
    extra = _get_inventory_extra(db, inv.id)

    if _is_agent_device(inv, extra):
        return _agent_status_from_last_seen(extra.get("last_seen_at"))

    status_live = _status_from_prom(
        inv.ip_address,
        prom_map,
        inv.monitoring_type,
        inv.scrape_port,
    )
    return status_live if status_live is not None else (inv.status or "UNKNOWN")


def _latest_agent_metric(db: Session, inventory_id: int) -> Optional[Dict[str, Any]]:
    row = db.execute(
        text(
            """
            SELECT cpu_pct, mem_pct, disk_pct, boot_time, collected_at
            FROM inventory_heartbeats
            WHERE inventory_id = :inventory_id
            ORDER BY collected_at DESC
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).mappings().first()

    return dict(row) if row else None


def _clean_optional_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    x = value.strip()
    return x or None


def _normalize_room(value: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(value)
    return cleaned.upper() if cleaned else None


def _normalize_building(value: Optional[str]) -> Optional[str]:
    cleaned = _clean_optional_str(value)
    return cleaned.upper() if cleaned else None


def _get_actor_name(request: Request) -> str:
    return request.headers.get("X-Operator", "unknown")


def _get_actor_role(request: Request) -> str:
    return request.headers.get("X-Role", "UNKNOWN")


def _get_request_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _get_user_agent(request: Request) -> Optional[str]:
    return request.headers.get("user-agent")


def _inventory_to_out(db: Session, inv: Inventory, status_value: str) -> InventoryOut:
    extra = _get_inventory_extra(db, inv.id)
    return InventoryOut(
        id=inv.id,
        hostname=inv.hostname,
        asset_name=getattr(inv, "asset_name", None),
        ip_address=inv.ip_address,
        current_ip=extra.get("current_ip"),
        device_type=inv.device_type,
        location=inv.location,
        room=extra.get("room"),
        building=extra.get("building"),
        monitoring_type=inv.monitoring_type,
        scrape_port=inv.scrape_port,
        os_type=extra.get("os_type"),
        os_version=extra.get("os_version"),
        agent_version=extra.get("agent_version"),
        device_uid=extra.get("device_uid"),
        machine_guid=extra.get("machine_guid"),
        bios_serial=extra.get("bios_serial"),
        motherboard_serial=extra.get("motherboard_serial"),
        mac_primary=extra.get("mac_primary"),
        manufacturer=extra.get("manufacturer"),
        model=extra.get("model"),
        cpu_model=extra.get("cpu_model"),
        ram_bytes=extra.get("ram_bytes"),
        last_seen_at=extra.get("last_seen_at"),
        last_boot_time=extra.get("last_boot_time"),
        identity_source=extra.get("identity_source"),
        is_discovered=extra.get("is_discovered"),
        status=status_value,
        created_at=inv.created_at,
        is_deleted=int(getattr(inv, "is_deleted", 0) or 0),
        deleted_at=getattr(inv, "deleted_at", None),
        deleted_by=getattr(inv, "deleted_by", None),
    )


def _inventory_summary_to_out(
    db: Session,
    inv: Inventory,
    status_value: str,
    open_count: int,
    last_ticket: Optional[Ticket],
) -> InventorySummaryOut:
    extra = _get_inventory_extra(db, inv.id)
    return InventorySummaryOut(
        id=inv.id,
        hostname=inv.hostname,
        asset_name=getattr(inv, "asset_name", None),
        ip_address=inv.ip_address,
        current_ip=extra.get("current_ip"),
        device_type=inv.device_type,
        location=inv.location,
        room=extra.get("room"),
        building=extra.get("building"),
        monitoring_type=inv.monitoring_type,
        scrape_port=inv.scrape_port,
        os_type=extra.get("os_type"),
        device_uid=extra.get("device_uid"),
        status=status_value,
        open_tickets=open_count,
        last_ticket=_ticket_to_out(last_ticket),
        is_deleted=int(getattr(inv, "is_deleted", 0) or 0),
        deleted_at=getattr(inv, "deleted_at", None),
        deleted_by=getattr(inv, "deleted_by", None),
    )


def _write_audit(
    db: Session,
    request: Request,
    *,
    action: str,
    entity_type: str,
    entity_id: Optional[str],
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    row = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_name=_get_actor_name(request),
        actor_role=_get_actor_role(request),
        ip=_get_request_ip(request),
        user_agent=_get_user_agent(request),
        meta_json=json.dumps(meta or {}, ensure_ascii=False),
    )
    db.add(row)


def _active_inventory_query(db: Session):
    return db.query(Inventory).filter(Inventory.is_deleted == 0)


def _deleted_inventory_query(db: Session):
    return db.query(Inventory).filter(Inventory.is_deleted == 1)


def _sync_prometheus_with_db(db: Session) -> Dict[str, int]:
    try:
        return sync_inventory_to_prometheus(db)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Inventory changed but Prometheus sync failed: {exc}",
        ) from exc


# =========================================================
# CRUD
# =========================================================

@router.get("", response_model=List[InventoryOut], include_in_schema=False)
@router.get("/", response_model=List[InventoryOut])
def list_inventory(db: Session = Depends(get_db)):
    inventories = (
        _active_inventory_query(db)
        .order_by(Inventory.id.asc())
        .all()
    )
    prom_map = _fetch_prom_up_map()

    output: List[InventoryOut] = []

    for inv in inventories:
        status_final = _status_live(db, inv, prom_map)
        output.append(_inventory_to_out(db, inv, status_final))

    return output


@router.get("/deleted", response_model=List[InventoryOut])
def list_deleted_inventory(db: Session = Depends(get_db)):
    inventories = (
        _deleted_inventory_query(db)
        .order_by(Inventory.id.desc())
        .all()
    )

    output: List[InventoryOut] = []

    for inv in inventories:
        output.append(_inventory_to_out(db, inv, inv.status or "DELETED"))

    return output


@router.post("/", response_model=InventoryOut)
def create_inventory(
    payload: InventoryCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    exists = db.query(Inventory).filter_by(ip_address=payload.ip_address).first()
    if exists:
        if int(getattr(exists, "is_deleted", 0) or 0) == 1:
            raise HTTPException(
                status_code=409,
                detail="Inventory with this IP already exists in deleted records. Restore it instead.",
            )
        raise HTTPException(status_code=409, detail="Inventory with this IP already exists")

    monitoring_type, scrape_port = _default_monitoring(
        payload.device_type,
        payload.monitoring_type,
        payload.scrape_port,
    )

    inv = Inventory(
        hostname=payload.hostname,
        asset_name=payload.asset_name,
        ip_address=payload.ip_address,
        device_type=payload.device_type,
        location=payload.location,
        monitoring_type=monitoring_type,
        scrape_port=scrape_port,
        status="UNKNOWN",
        is_deleted=0,
        deleted_at=None,
        deleted_by=None,
    )

    db.add(inv)
    db.flush()

    _write_audit(
        db,
        request,
        action="inventory.created",
        entity_type="inventory",
        entity_id=str(inv.id),
        meta={
            "inventory_id": inv.id,
            "hostname": inv.hostname,
            "asset_name": inv.asset_name,
            "ip_address": inv.ip_address,
            "device_type": inv.device_type,
            "location": inv.location,
            "monitoring_type": inv.monitoring_type,
            "scrape_port": inv.scrape_port,
        },
    )

    db.commit()
    db.refresh(inv)
    _sync_prometheus_with_db(db)

    return _inventory_to_out(db, inv, inv.status)


@router.patch("/{inventory_id}/metadata", response_model=InventoryOut)
def update_inventory_metadata(
    inventory_id: int,
    payload: InventoryMetadataUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    cols = _inventory_columns(db)
    extra_before = _get_inventory_extra(db, inventory_id)

    is_agent = _is_agent_device(inv, extra_before)

    body = payload.model_dump(exclude_unset=True)
    if not body:
        raise HTTPException(status_code=400, detail="No metadata fields provided")

    allowed_common = {"asset_name", "location"}
    allowed_manual_only = {"device_type", "monitoring_type", "scrape_port"}
    allowed_sql_optional = {"room", "building"}

    allowed = set(allowed_common) | set(allowed_sql_optional)
    if not is_agent:
        allowed |= allowed_manual_only

    not_allowed = [k for k in body.keys() if k not in allowed]
    if not_allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Fields not editable for this asset: {', '.join(sorted(not_allowed))}",
        )

    if "scrape_port" in body and body["scrape_port"] is not None:
        port = body["scrape_port"]
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise HTTPException(status_code=400, detail="scrape_port must be between 1 and 65535")

    updates_model: Dict[str, Any] = {}
    updates_sql: Dict[str, Any] = {}

    if "asset_name" in body:
        updates_model["asset_name"] = _clean_optional_str(body["asset_name"])

    if "location" in body:
        updates_model["location"] = _clean_optional_str(body["location"])

    if not is_agent:
        if "device_type" in body:
            updates_model["device_type"] = _clean_optional_str(body["device_type"])
        if "monitoring_type" in body:
            updates_model["monitoring_type"] = _clean_optional_str(body["monitoring_type"])
        if "scrape_port" in body:
            updates_model["scrape_port"] = body["scrape_port"]

    if "room" in body:
        if "room" not in cols:
            raise HTTPException(
                status_code=400,
                detail="inventory.room column does not exist yet",
            )
        updates_sql["room"] = _normalize_room(body["room"])

    if "building" in body:
        if "building" not in cols:
            raise HTTPException(
                status_code=400,
                detail="inventory.building column does not exist yet",
            )
        updates_sql["building"] = _normalize_building(body["building"])

    before_state = {
        "asset_name": inv.asset_name,
        "location": inv.location,
        "device_type": inv.device_type,
        "monitoring_type": inv.monitoring_type,
        "scrape_port": inv.scrape_port,
        "room": extra_before.get("room"),
        "building": extra_before.get("building"),
    }

    for key, value in updates_model.items():
        setattr(inv, key, value)

    if updates_sql:
        assignments = ", ".join([f"{k} = :{k}" for k in updates_sql.keys()])
        params = {"inventory_id": inventory_id, **updates_sql}
        db.execute(
            text(f"UPDATE inventory SET {assignments} WHERE id = :inventory_id"),
            params,
        )

    db.flush()
    db.refresh(inv)

    extra_after = _get_inventory_extra(db, inventory_id)

    after_state = {
        "asset_name": inv.asset_name,
        "location": inv.location,
        "device_type": inv.device_type,
        "monitoring_type": inv.monitoring_type,
        "scrape_port": inv.scrape_port,
        "room": extra_after.get("room"),
        "building": extra_after.get("building"),
    }

    changed_fields = [
        key for key in sorted(after_state.keys())
        if before_state.get(key) != after_state.get(key)
    ]

    if changed_fields:
        _write_audit(
            db,
            request,
            action="inventory.metadata.updated",
            entity_type="inventory",
            entity_id=str(inventory_id),
            meta={
                "inventory_id": inventory_id,
                "changed_fields": changed_fields,
                "before": {k: before_state.get(k) for k in changed_fields},
                "after": {k: after_state.get(k) for k in changed_fields},
                "is_agent_device": is_agent,
            },
        )

    db.commit()
    db.refresh(inv)
    _sync_prometheus_with_db(db)

    status_final = _status_live(db, inv, _fetch_prom_up_map())
    return _inventory_to_out(db, inv, status_final)


@router.post("/{inventory_id}/restore", response_model=InventoryOut)
def restore_inventory(
    inventory_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    inv = db.query(Inventory).filter(Inventory.id == inventory_id).first()

    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    if int(getattr(inv, "is_deleted", 0) or 0) == 0:
        status_final = _status_live(db, inv, _fetch_prom_up_map())
        return _inventory_to_out(db, inv, status_final)

    inv.is_deleted = 0
    inv.deleted_at = None
    inv.deleted_by = None

    _write_audit(
        db,
        request,
        action="inventory.restored",
        entity_type="inventory",
        entity_id=str(inv.id),
        meta={
            "inventory_id": inv.id,
            "hostname": inv.hostname,
            "ip_address": inv.ip_address,
            "monitoring_type": inv.monitoring_type,
            "scrape_port": inv.scrape_port,
        },
    )

    db.commit()
    db.refresh(inv)
    _sync_prometheus_with_db(db)

    status_final = _status_live(db, inv, _fetch_prom_up_map())
    return _inventory_to_out(db, inv, status_final)


# =========================================================
# SUMMARY (LIVE STATUS)
# =========================================================

@router.get("/summary", response_model=List[InventorySummaryOut])
def inventory_summary(db: Session = Depends(get_db)):
    inventories = (
        _active_inventory_query(db)
        .order_by(Inventory.id.asc())
        .all()
    )
    prom_map = _fetch_prom_up_map()

    output: List[InventorySummaryOut] = []

    for inv in inventories:
        open_count = (
            db.query(Ticket)
            .filter(Ticket.inventory_id == inv.id, Ticket.status == "OPEN")
            .count()
        )

        last = (
            db.query(Ticket)
            .filter(Ticket.inventory_id == inv.id)
            .order_by(Ticket.created_at.desc())
            .first()
        )

        status_final = _status_live(db, inv, prom_map)

        output.append(
            _inventory_summary_to_out(
                db,
                inv,
                status_final,
                open_count,
                last,
            )
        )

    return output


# =========================================================
# METRICS OVERVIEW (VM + NETWORK + AGENT SAFE)
# =========================================================

@router.get("/{inventory_id}/metrics/overview")
def metrics_overview(inventory_id: int, db: Session = Depends(get_db)):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    prom = _prom_base()
    monitoring_type, scrape_port = _default_monitoring(
        inv.device_type,
        inv.monitoring_type,
        inv.scrape_port,
    )

    extra = _get_inventory_extra(db, inv.id)

    if _is_agent_device(inv, extra):
        latest = _latest_agent_metric(db, inv.id)
        status_final = _agent_status_from_last_seen(extra.get("last_seen_at"))

        return {
            "current": {
                "up": status_final == "UP",
                "cpu_pct": latest.get("cpu_pct") if latest else None,
                "mem_pct": latest.get("mem_pct") if latest else None,
                "disk_pct": latest.get("disk_pct") if latest else None,
            },
            "summary": {
                "cpu": {
                    "avg": latest.get("cpu_pct") if latest else None,
                    "max": latest.get("cpu_pct") if latest else None,
                },
                "mem": {
                    "avg": latest.get("mem_pct") if latest else None,
                    "max": latest.get("mem_pct") if latest else None,
                },
                "disk": {
                    "avg": latest.get("disk_pct") if latest else None,
                    "max": latest.get("disk_pct") if latest else None,
                },
            },
            "error": None if latest else "agent_metric_not_found",
        }

    try:
        r = requests.get(f"{prom}/api/v1/query", params={"query": "up"}, timeout=3)
        r.raise_for_status()
        result = r.json()["data"]["result"]
    except Exception:
        result = []

    instance = None
    up_val = None

    for item in result:
        inst = item["metric"].get("instance")
        if not inst:
            continue
        ip = inst.split(":")[0]
        if ip == inv.ip_address:
            if scrape_port is None or inst == f"{inv.ip_address}:{scrape_port}" or inst == inv.ip_address:
                instance = inst
                up_val = float(item["value"][1])
                break

    if not instance:
        return {
            "current": {
                "up": False,
                "cpu_pct": None,
                "mem_pct": None,
                "disk_pct": None,
            },
            "summary": {
                "cpu": {"avg": None, "max": None},
                "mem": {"avg": None, "max": None},
                "disk": {"avg": None, "max": None},
            },
            "error": "instance_not_found",
        }

    if inv.device_type == "network" or monitoring_type == "snmp":
        return {
            "current": {
                "up": True if up_val and up_val >= 1 else False,
                "cpu_pct": None,
                "mem_pct": None,
                "disk_pct": None,
            },
            "summary": {
                "cpu": {"avg": None, "max": None},
                "mem": {"avg": None, "max": None},
                "disk": {"avg": None, "max": None},
            },
            "error": None,
        }

    def q(query: str):
        try:
            r = requests.get(
                f"{prom}/api/v1/query",
                params={"query": query},
                timeout=3,
            )
            r.raise_for_status()
            data = r.json()["data"]["result"]
            if not data:
                return None
            return float(data[0]["value"][1])
        except Exception:
            return None

    cpu = q(f'rate(node_cpu_seconds_total{{mode!="idle",instance="{instance}"}}[5m]) * 100')
    mem = q(f'(1 - (node_memory_MemAvailable_bytes{{instance="{instance}"}} / node_memory_MemTotal_bytes{{instance="{instance}"}})) * 100')
    disk = q(f'(1 - (node_filesystem_avail_bytes{{fstype!="tmpfs",instance="{instance}"}} / node_filesystem_size_bytes{{fstype!="tmpfs",instance="{instance}"}})) * 100')

    return {
        "current": {
            "up": True if up_val and up_val >= 1 else False,
            "cpu_pct": cpu,
            "mem_pct": mem,
            "disk_pct": disk,
        },
        "summary": {
            "cpu": {"avg": cpu, "max": cpu},
            "mem": {"avg": mem, "max": mem},
            "disk": {"avg": disk, "max": disk},
        },
        "error": None,
    }


# =========================================================
# TICKETS
# =========================================================

@router.get("/{inventory_id}/tickets", response_model=List[TicketOut])
def get_inventory_tickets(inventory_id: int, db: Session = Depends(get_db)):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    tickets = (
        db.query(Ticket)
        .filter(Ticket.inventory_id == inventory_id)
        .order_by(Ticket.created_at.desc())
        .all()
    )

    return [_ticket_to_out(t) for t in tickets]


# =========================================================
# MUST BE LAST
# =========================================================

@router.get("/{inventory_id}", response_model=InventoryOut)
def get_inventory(inventory_id: int, db: Session = Depends(get_db)):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    status_final = _status_live(db, inv, _fetch_prom_up_map())
    return _inventory_to_out(db, inv, status_final)


# =========================================================
# NETWORK METRICS (SNMP - Grafana style)
# =========================================================

@router.get("/{inventory_id}/metrics/network")
def network_metrics(inventory_id: int, db: Session = Depends(get_db)):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    device_type = str(inv.device_type or "").lower()
    monitoring_type = str(inv.monitoring_type or "").lower()

    allowed_types = {"network", "switch", "router", "firewall", "ap", "other"}
    if device_type not in allowed_types and monitoring_type != "snmp":
        raise HTTPException(status_code=400, detail="Not a network device")

    prom = _prom_base()
    inventory_label = str(inv.id)
    instance = inv.ip_address

    def q(query: str):
        try:
            r = requests.get(
                f"{prom}/api/v1/query",
                params={"query": query},
                timeout=5,
            )
            r.raise_for_status()
            return r.json()["data"]["result"]
        except Exception:
            return []

    def query_with_fallback(by_inventory: str, by_instance: str):
        result = q(by_inventory)
        if result:
            return result
        return q(by_instance)

    rx = query_with_fallback(
        f'rate(ifHCInOctets{{inventory_id="{inventory_label}"}}[5m])',
        f'rate(ifHCInOctets{{instance="{instance}"}}[5m])',
    )
    tx = query_with_fallback(
        f'rate(ifHCOutOctets{{inventory_id="{inventory_label}"}}[5m])',
        f'rate(ifHCOutOctets{{instance="{instance}"}}[5m])',
    )
    oper = query_with_fallback(
        f'ifOperStatus{{inventory_id="{inventory_label}"}}',
        f'ifOperStatus{{instance="{instance}"}}',
    )
    admin = query_with_fallback(
        f'ifAdminStatus{{inventory_id="{inventory_label}"}}',
        f'ifAdminStatus{{instance="{instance}"}}',
    )
    in_err = query_with_fallback(
        f'ifInErrors{{inventory_id="{inventory_label}"}}',
        f'ifInErrors{{instance="{instance}"}}',
    )
    out_err = query_with_fallback(
        f'ifOutErrors{{inventory_id="{inventory_label}"}}',
        f'ifOutErrors{{instance="{instance}"}}',
    )
    in_discards = query_with_fallback(
        f'ifInDiscards{{inventory_id="{inventory_label}"}}',
        f'ifInDiscards{{instance="{instance}"}}',
    )
    out_discards = query_with_fallback(
        f'ifOutDiscards{{inventory_id="{inventory_label}"}}',
        f'ifOutDiscards{{instance="{instance}"}}',
    )
    speed = query_with_fallback(
        f'ifSpeed{{inventory_id="{inventory_label}"}}',
        f'ifSpeed{{instance="{instance}"}}',
    )

    interfaces: Dict[str, Dict[str, Any]] = {}

    def iface_name(metric: Dict[str, Any]) -> Optional[str]:
        return (
            metric.get("ifDescr")
            or metric.get("ifName")
            or metric.get("ifAlias")
            or metric.get("ifIndex")
        )

    def ensure_iface(name: str, metric: Dict[str, Any]) -> Dict[str, Any]:
        if name not in interfaces:
            interfaces[name] = {
                "interface": name,
                "if_index": metric.get("ifIndex"),
                "if_name": metric.get("ifName"),
                "if_descr": metric.get("ifDescr"),
                "if_alias": metric.get("ifAlias"),
                "rx_bps": 0.0,
                "tx_bps": 0.0,
                "oper_status": "unknown",
                "admin_status": "unknown",
                "speed_bps": 0.0,
                "in_errors": 0.0,
                "out_errors": 0.0,
                "in_discards": 0.0,
                "out_discards": 0.0,
            }
        return interfaces[name]

    for item in rx:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["rx_bps"] = float(item["value"][1])

    for item in tx:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["tx_bps"] = float(item["value"][1])

    for item in oper:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        raw = str(int(float(item["value"][1])))
        row["oper_status"] = "up" if raw == "1" else "down"

    for item in admin:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        raw = str(int(float(item["value"][1])))
        row["admin_status"] = "up" if raw == "1" else "down"

    for item in in_err:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["in_errors"] = float(item["value"][1])

    for item in out_err:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["out_errors"] = float(item["value"][1])

    for item in in_discards:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["in_discards"] = float(item["value"][1])

    for item in out_discards:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["out_discards"] = float(item["value"][1])

    for item in speed:
        metric = item.get("metric", {})
        name = iface_name(metric)
        if not name or name == "lo":
            continue
        row = ensure_iface(name, metric)
        row["speed_bps"] = float(item["value"][1])

    interface_list = sorted(
        interfaces.values(),
        key=lambda x: (str(x.get("if_index") or ""), str(x.get("interface") or "")),
    )

    total_rx = sum(i["rx_bps"] for i in interface_list)
    total_tx = sum(i["tx_bps"] for i in interface_list)
    up_count = sum(1 for i in interface_list if i["oper_status"] == "up")
    down_count = sum(1 for i in interface_list if i["oper_status"] != "up")

    return {
        "device": getattr(inv, "asset_name", None) or inv.hostname,
        "ip": inv.ip_address,
        "inventory_id": inv.id,
        "summary": {
            "total_rx_bps": total_rx,
            "total_tx_bps": total_tx,
            "interface_count": len(interface_list),
            "up_count": up_count,
            "down_count": down_count,
        },
        "interfaces": interface_list,
    }


# =========================================================
# SLA (30 days)
# =========================================================

@router.get("/{inventory_id}/sla")
def inventory_sla(inventory_id: int, db: Session = Depends(get_db)):
    inv = _active_inventory_query(db).filter_by(id=inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    extra = _get_inventory_extra(db, inv.id)

    if _is_agent_device(inv, extra):
        status_final = _agent_status_from_last_seen(extra.get("last_seen_at"))
        uptime_pct = 100.0 if status_final == "UP" else 0.0
        return {
            "hostname": inv.hostname,
            "asset_name": getattr(inv, "asset_name", None),
            "uptime_pct": uptime_pct,
            "downtime_pct": round(100 - uptime_pct, 3),
            "monitoring_type": inv.monitoring_type,
            "scrape_port": inv.scrape_port,
        }

    prom = _prom_base()
    monitoring_type, scrape_port = _default_monitoring(
        inv.device_type,
        inv.monitoring_type,
        inv.scrape_port,
    )

    if monitoring_type == "snmp":
        query_instance = inv.ip_address
    else:
        query_instance = f"{inv.ip_address}:{scrape_port or 9100}"

    try:
        r = requests.get(
            f"{prom}/api/v1/query",
            params={
                "query": f'avg_over_time(up{{instance="{query_instance}"}}[30d])'
            },
            timeout=5,
        )
        r.raise_for_status()
        data = r.json()["data"]["result"]
    except Exception:
        return {"uptime_pct": None}

    if not data:
        return {"uptime_pct": 0}

    value = float(data[0]["value"][1])
    uptime_pct = round(value * 100, 3)
    downtime_pct = round(100 - uptime_pct, 3)

    return {
        "hostname": inv.hostname,
        "asset_name": getattr(inv, "asset_name", None),
        "uptime_pct": uptime_pct,
        "downtime_pct": downtime_pct,
        "monitoring_type": monitoring_type,
        "scrape_port": scrape_port,
    }


# =========================================================
# DELETE (SOFT DELETE)
# =========================================================

@router.delete("/{inventory_id}")
def delete_inventory(
    inventory_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    inv = db.query(Inventory).filter(Inventory.id == inventory_id).first()

    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    if int(getattr(inv, "is_deleted", 0) or 0) == 1:
        return {"message": "already deleted"}

    inv.is_deleted = 1
    inv.deleted_at = datetime.utcnow()
    inv.deleted_by = _get_actor_name(request)

    _write_audit(
        db,
        request,
        action="inventory.soft_deleted",
        entity_type="inventory",
        entity_id=str(inventory_id),
        meta={
            "inventory_id": inv.id,
            "hostname": inv.hostname,
            "asset_name": inv.asset_name,
            "ip_address": inv.ip_address,
            "device_type": inv.device_type,
            "location": inv.location,
            "monitoring_type": inv.monitoring_type,
            "scrape_port": inv.scrape_port,
        },
    )

    db.commit()
    _sync_prometheus_with_db(db)

    return {"message": "soft deleted"}
