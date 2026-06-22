from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from services.audit import write_audit

router = APIRouter(prefix="/api", tags=["agent"])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def utcnow_iso() -> str:
    return utcnow().isoformat()


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = str(value).strip()
        if not v:
            return None
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def row_value(row: Any, key: str, idx: Optional[int] = None):
    try:
        if hasattr(row, "_mapping") and key in row._mapping:
            return row._mapping[key]
    except Exception:
        pass
    try:
        return getattr(row, key)
    except Exception:
        pass
    if idx is not None:
        try:
            return row[idx]
        except Exception:
            pass
    return None


def coalesce(*values):
    for v in values:
        if v is not None:
            return v
    return None


def normalize_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def normalize_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except Exception:
        return None


def normalize_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _parse_json_text(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        return {}
    except Exception:
        return {}


def _default_naming_policy() -> Dict[str, Any]:
    return {
        "mode": "room_based",
        "prefix": "CPCOM",
        "room_digits": 4,
        "sequence_digits": 2,
        "separator": "-",
        "collision_strategy": "increment",
    }


def _default_agent_alert_policy() -> Dict[str, Any]:
    return {
        "heartbeat_timeout_sec": 120,
        "metric_freshness_timeout_sec": 900,
        "cpu_warning_pct": 85,
        "cpu_critical_pct": 95,
        "memory_warning_pct": 85,
        "memory_critical_pct": 95,
        "disk_warning_pct": 90,
        "disk_critical_pct": 95,
    }


def _get_config_profile(db: Session, config_key: str) -> Dict[str, Any]:
    try:
        row = db.execute(
            text(
                """
                SELECT config_json
                FROM config_profiles
                WHERE config_key = :config_key
                  AND is_active = 1
                LIMIT 1
                """
            ),
            {"config_key": config_key},
        ).fetchone()

        if not row:
            return {}

        config_json = row_value(row, "config_json", 0)
        return _parse_json_text(config_json)
    except Exception:
        return {}


def get_naming_policy(db: Session) -> Dict[str, Any]:
    merged = dict(_default_naming_policy())
    merged.update(_get_config_profile(db, "naming_policy"))
    return merged


def get_agent_alert_policy(db: Session) -> Dict[str, Any]:
    merged = dict(_default_agent_alert_policy())
    merged.update(_get_config_profile(db, "agent_alert_policy"))
    return merged


def _naming_prefix(policy: Dict[str, Any]) -> str:
    prefix = normalize_str(policy.get("prefix"))
    return prefix or "CPCOM"


def _naming_separator(policy: Dict[str, Any]) -> str:
    separator = policy.get("separator")
    if separator is None:
        return "-"
    return str(separator)


def _naming_room_digits(policy: Dict[str, Any]) -> int:
    try:
        value = int(policy.get("room_digits", 4))
        return value if value > 0 else 4
    except Exception:
        return 4


def _naming_sequence_digits(policy: Dict[str, Any]) -> int:
    try:
        value = int(policy.get("sequence_digits", 2))
        return value if value > 0 else 2
    except Exception:
        return 2


def _naming_collision_strategy(policy: Dict[str, Any]) -> str:
    value = normalize_str(policy.get("collision_strategy"))
    return (value or "increment").lower()


def _policy_int_value(value: Any, fallback: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else fallback
    except Exception:
        return fallback


def _policy_float_value(value: Any, fallback: float) -> float:
    try:
        parsed = float(value)
        return parsed if parsed >= 0 else fallback
    except Exception:
        return fallback


def get_actor_name(
    x_operator: Optional[str] = Header(default=None, alias="X-Operator"),
) -> str:
    return (x_operator or "unknown").strip() or "unknown"


def get_actor_role(
    x_role: Optional[str] = Header(default=None, alias="X-Role"),
) -> str:
    role = (x_role or "VIEWER").strip().upper()
    return role or "VIEWER"


def payload_identity(payload: Dict[str, Any]) -> Dict[str, Any]:
    identity = payload.get("identity") if isinstance(payload.get("identity"), dict) else {}

    spec = identity.get("spec") if isinstance(identity.get("spec"), dict) else {}
    if not spec:
        spec = payload.get("spec") if isinstance(payload.get("spec"), dict) else {}

    metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}

    return {
        "device_uid": normalize_str(coalesce(identity.get("device_uid"), payload.get("device_uid"))),
        "hostname": normalize_str(coalesce(identity.get("hostname"), payload.get("hostname"))),
        "current_ip": normalize_str(coalesce(identity.get("current_ip"), payload.get("current_ip"))),
        "os_type": normalize_str(coalesce(identity.get("os_type"), payload.get("os_type"), "windows")),
        "os_version": normalize_str(coalesce(identity.get("os_version"), payload.get("os_version"))),
        "agent_version": normalize_str(coalesce(identity.get("agent_version"), payload.get("agent_version"))),
        "machine_guid": normalize_str(coalesce(identity.get("machine_guid"), payload.get("machine_guid"))),
        "bios_serial": normalize_str(coalesce(identity.get("bios_serial"), payload.get("bios_serial"))),
        "motherboard_serial": normalize_str(
            coalesce(identity.get("motherboard_serial"), payload.get("motherboard_serial"))
        ),
        "mac_primary": normalize_str(coalesce(identity.get("mac_primary"), payload.get("mac_primary"))),
        "room": normalize_str(coalesce(identity.get("room"), payload.get("room"))),
        "identity_source": normalize_str(
            coalesce(identity.get("identity_source"), payload.get("identity_source"), "device_uid")
        ),
        "manufacturer": normalize_str(coalesce(spec.get("manufacturer"), payload.get("manufacturer"))),
        "model": normalize_str(coalesce(spec.get("model"), payload.get("model"))),
        "cpu_model": normalize_str(coalesce(spec.get("cpu_model"), payload.get("cpu_model"))),
        "ram_bytes": normalize_int(coalesce(spec.get("ram_bytes"), payload.get("ram_bytes"))),
        "cpu_pct": normalize_float(coalesce(metrics.get("cpu_pct"), payload.get("cpu_pct"))),
        "mem_pct": normalize_float(coalesce(metrics.get("mem_pct"), payload.get("mem_pct"))),
        "disk_pct": normalize_float(coalesce(metrics.get("disk_pct"), payload.get("disk_pct"))),
        "boot_time": normalize_str(
            coalesce(metrics.get("boot_time"), payload.get("boot_time"), payload.get("last_boot_time"))
        ),
    }


def get_agent_up_seconds(db: Session) -> int:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("heartbeat_timeout_sec")
    if policy_value is not None:
        return _policy_int_value(policy_value, 120)

    raw = os.getenv("AGENT_UP_SECONDS", "300")
    try:
        value = int(raw)
        return value if value > 0 else 300
    except Exception:
        return 300


def get_agent_metric_fresh_seconds(db: Session) -> int:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("metric_freshness_timeout_sec")
    if policy_value is not None:
        return _policy_int_value(policy_value, 900)

    raw = os.getenv("AGENT_METRIC_FRESH_SECONDS", "900")
    try:
        value = int(raw)
        return value if value > 0 else 900
    except Exception:
        return 900


def get_agent_cpu_warn_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("cpu_warning_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 85.0)

    try:
        return float(os.getenv("AGENT_CPU_WARN_PCT", "85"))
    except Exception:
        return 85.0


def get_agent_cpu_crit_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("cpu_critical_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 95.0)

    try:
        return float(os.getenv("AGENT_CPU_CRIT_PCT", "95"))
    except Exception:
        return 95.0


def get_agent_mem_warn_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("memory_warning_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 85.0)

    try:
        return float(os.getenv("AGENT_MEM_WARN_PCT", "85"))
    except Exception:
        return 85.0


def get_agent_mem_crit_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("memory_critical_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 95.0)

    try:
        return float(os.getenv("AGENT_MEM_CRIT_PCT", "95"))
    except Exception:
        return 95.0


def get_agent_disk_warn_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("disk_warning_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 90.0)

    try:
        return float(os.getenv("AGENT_DISK_WARN_PCT", "85"))
    except Exception:
        return 85.0


def get_agent_disk_crit_pct(db: Session) -> float:
    policy = get_agent_alert_policy(db)
    policy_value = policy.get("disk_critical_pct")
    if policy_value is not None:
        return _policy_float_value(policy_value, 95.0)

    try:
        return float(os.getenv("AGENT_DISK_CRIT_PCT", "95"))
    except Exception:
        return 95.0


class DiscoveryItemOut(BaseModel):
    id: int
    hostname: str
    asset_name: Optional[str] = None
    current_ip: Optional[str] = None
    room: Optional[str] = None
    status: Optional[str] = None
    os_type: Optional[str] = None
    last_seen_at: Optional[str] = None
    is_discovered: bool


class IpHistoryOut(BaseModel):
    id: int
    ip_address: str
    first_seen_at: str
    last_seen_at: str


class HeartbeatOut(BaseModel):
    id: int
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    disk_pct: Optional[float] = None
    boot_time: Optional[str] = None
    collected_at: str


class DeviceAlertOut(BaseModel):
    id: int
    alert_key: str
    severity: str
    message: str
    status: str
    created_at: str
    resolved_at: Optional[str] = None
    meta_json: Optional[str] = None


class PendingDeviceOut(BaseModel):
    id: int
    device_uid: str
    hostname: str
    current_ip: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    cpu_model: Optional[str] = None
    ram_bytes: Optional[int] = None
    bios_serial: Optional[str] = None
    motherboard_serial: Optional[str] = None
    mac_primary: Optional[str] = None
    room: Optional[str] = None
    machine_guid: Optional[str] = None
    last_boot_time: Optional[str] = None
    cpu_pct: Optional[float] = None
    mem_pct: Optional[float] = None
    disk_pct: Optional[float] = None
    status: str
    first_seen_at: str
    last_seen_at: str
    approved_at: Optional[str] = None
    rejected_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    approved_inventory_id: Optional[int] = None


class PendingApproveIn(BaseModel):
    asset_name: Optional[str] = None
    room: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = "pc"


class PendingRejectIn(BaseModel):
    reason: Optional[str] = None


class AssetNamePreviewOut(BaseModel):
    room_input: Optional[str] = None
    normalized_room_digits: Optional[str] = None
    suggested_asset_name: Optional[str] = None
    can_generate: bool
    message: str


def ensure_pending_schema(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS pending_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_uid TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                current_ip TEXT,
                os_type TEXT,
                os_version TEXT,
                agent_version TEXT,
                machine_guid TEXT,
                bios_serial TEXT,
                motherboard_serial TEXT,
                mac_primary TEXT,
                manufacturer TEXT,
                model TEXT,
                cpu_model TEXT,
                ram_bytes INTEGER,
                room TEXT,
                identity_source TEXT,
                last_boot_time TEXT,
                cpu_pct REAL,
                mem_pct REAL,
                disk_pct REAL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                approved_at TEXT,
                rejected_at TEXT,
                rejection_reason TEXT,
                approved_inventory_id INTEGER,
                payload_json TEXT
            )
            """
        )
    )
    db.commit()


def find_inventory_by_device_uid(db: Session, device_uid: str):
    return db.execute(
        text(
            """
            SELECT id, hostname, current_ip, last_boot_time, asset_name
            FROM inventory
            WHERE device_uid = :device_uid
            LIMIT 1
            """
        ),
        {"device_uid": device_uid},
    ).fetchone()


def find_inventory_by_id(db: Session, inventory_id: int):
    return db.execute(
        text(
            """
            SELECT id
            FROM inventory
            WHERE id = :inventory_id
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchone()


def find_pending_by_device_uid(db: Session, device_uid: str):
    ensure_pending_schema(db)
    return db.execute(
        text(
            """
            SELECT *
            FROM pending_devices
            WHERE device_uid = :device_uid
            LIMIT 1
            """
        ),
        {"device_uid": device_uid},
    ).fetchone()


def find_pending_by_id(db: Session, pending_id: int):
    ensure_pending_schema(db)
    return db.execute(
        text(
            """
            SELECT *
            FROM pending_devices
            WHERE id = :pending_id
            LIMIT 1
            """
        ),
        {"pending_id": pending_id},
    ).fetchone()


def normalize_room_asset_digits(
    room: Optional[str],
    room_digits_required: int = 4,
) -> Optional[str]:
    room_text = normalize_str(room)
    if not room_text:
        return None

    digits = re.sub(r"\D", "", room_text)
    if len(digits) < room_digits_required:
        return None

    return digits[-room_digits_required:]


def generate_next_asset_name(
    db: Session,
    room: Optional[str],
    exclude_inventory_id: Optional[int] = None,
) -> Optional[str]:
    policy = get_naming_policy(db)
    room_digits_required = _naming_room_digits(policy)
    room_digits = normalize_room_asset_digits(room, room_digits_required=room_digits_required)
    if not room_digits:
        return None

    prefix_root = _naming_prefix(policy)
    separator = _naming_separator(policy)
    sequence_digits = _naming_sequence_digits(policy)
    collision_strategy = _naming_collision_strategy(policy)

    if collision_strategy != "increment":
        collision_strategy = "increment"

    prefix = f"{prefix_root}{room_digits}{separator}"

    rows = db.execute(
        text(
            """
            SELECT id, asset_name
            FROM inventory
            WHERE asset_name IS NOT NULL
              AND asset_name LIKE :prefix_like
            """
        ),
        {"prefix_like": f"{prefix}%"},
    ).fetchall()

    max_seq = 0
    for row in rows:
        inv_id = row_value(row, "id", 0)
        if exclude_inventory_id is not None and inv_id == exclude_inventory_id:
            continue

        asset_name = normalize_str(row_value(row, "asset_name", 1))
        if not asset_name:
            continue

        m = re.match(rf"^{re.escape(prefix)}(\d+)$", asset_name, flags=re.IGNORECASE)
        if not m:
            continue

        try:
            seq = int(m.group(1))
            if seq > max_seq:
                max_seq = seq
        except Exception:
            pass

    next_seq = max_seq + 1
    return f"{prefix}{next_seq:0{sequence_digits}d}"


def upsert_ip_history(db: Session, inventory_id: int, ip_address: Optional[str]) -> None:
    if not ip_address:
        return

    now = utcnow_iso()
    row = db.execute(
        text(
            """
            SELECT id
            FROM inventory_ip_history
            WHERE inventory_id = :inventory_id
              AND ip_address = :ip_address
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id, "ip_address": ip_address},
    ).fetchone()

    if row:
        db.execute(
            text(
                """
                UPDATE inventory_ip_history
                SET last_seen_at = :now
                WHERE id = :id
                """
            ),
            {"id": row_value(row, "id", 0), "now": now},
        )
    else:
        db.execute(
            text(
                """
                INSERT INTO inventory_ip_history (
                    inventory_id, ip_address, first_seen_at, last_seen_at
                )
                VALUES (
                    :inventory_id, :ip_address, :now, :now
                )
                """
            ),
            {"inventory_id": inventory_id, "ip_address": ip_address, "now": now},
        )


def insert_heartbeat(
    db: Session,
    inventory_id: int,
    cpu_pct: Optional[float],
    mem_pct: Optional[float],
    disk_pct: Optional[float],
    boot_time: Optional[str],
) -> None:
    db.execute(
        text(
            """
            INSERT INTO inventory_heartbeats (
                inventory_id, cpu_pct, mem_pct, disk_pct, boot_time, collected_at
            )
            VALUES (
                :inventory_id, :cpu_pct, :mem_pct, :disk_pct, :boot_time, :collected_at
            )
            """
        ),
        {
            "inventory_id": inventory_id,
            "cpu_pct": cpu_pct,
            "mem_pct": mem_pct,
            "disk_pct": disk_pct,
            "boot_time": boot_time,
            "collected_at": utcnow_iso(),
        },
    )


def open_or_refresh_alert(
    db: Session,
    inventory_id: int,
    alert_key: str,
    severity: str,
    message: str,
    meta: Optional[dict] = None,
) -> None:
    existing = db.execute(
        text(
            """
            SELECT id
            FROM device_alerts
            WHERE inventory_id = :inventory_id
              AND alert_key = :alert_key
              AND status = 'OPEN'
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id, "alert_key": alert_key},
    ).fetchone()

    if existing:
        db.execute(
            text(
                """
                UPDATE device_alerts
                SET severity = :severity,
                    message = :message,
                    meta_json = :meta_json
                WHERE id = :id
                """
            ),
            {
                "id": row_value(existing, "id", 0),
                "severity": severity,
                "message": message,
                "meta_json": json.dumps(meta or {}, ensure_ascii=False),
            },
        )
    else:
        db.execute(
            text(
                """
                INSERT INTO device_alerts (
                    inventory_id, alert_key, severity, message, status, meta_json, created_at
                )
                VALUES (
                    :inventory_id, :alert_key, :severity, :message, 'OPEN', :meta_json, :created_at
                )
                """
            ),
            {
                "inventory_id": inventory_id,
                "alert_key": alert_key,
                "severity": severity,
                "message": message,
                "meta_json": json.dumps(meta or {}, ensure_ascii=False),
                "created_at": utcnow_iso(),
            },
        )


def resolve_alert(db: Session, inventory_id: int, alert_key: str) -> None:
    db.execute(
        text(
            """
            UPDATE device_alerts
            SET status = 'RESOLVED',
                resolved_at = :resolved_at
            WHERE inventory_id = :inventory_id
              AND alert_key = :alert_key
              AND status = 'OPEN'
            """
        ),
        {
            "inventory_id": inventory_id,
            "alert_key": alert_key,
            "resolved_at": utcnow_iso(),
        },
    )


def resolve_alerts(db: Session, inventory_id: int, alert_keys: List[str]) -> None:
    for alert_key in alert_keys:
        resolve_alert(db, inventory_id, alert_key)


def discovery_status_from_last_seen(db: Session, last_seen_at: Optional[str]) -> str:
    dt = parse_dt(last_seen_at)
    if not dt:
        return "DOWN"
    seconds = (utcnow() - dt).total_seconds()
    return "UP" if seconds <= get_agent_up_seconds(db) else "DOWN"


def get_inventory_agent_row(db: Session, inventory_id: int):
    return db.execute(
        text(
            """
            SELECT
                id,
                hostname,
                asset_name,
                device_uid,
                current_ip,
                ip_address,
                os_type,
                room,
                location,
                last_seen_at,
                last_boot_time,
                monitoring_type,
                is_discovered
            FROM inventory
            WHERE id = :inventory_id
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchone()


def get_all_agent_inventory_rows(db: Session):
    return db.execute(
        text(
            """
            SELECT
                id,
                hostname,
                asset_name,
                device_uid,
                current_ip,
                ip_address,
                os_type,
                room,
                location,
                last_seen_at,
                last_boot_time,
                monitoring_type,
                is_discovered
            FROM inventory
            WHERE monitoring_type = 'agent'
               OR is_discovered = 1
               OR os_type = 'windows'
            ORDER BY id ASC
            """
        )
    ).fetchall()


def get_latest_heartbeat_row(db: Session, inventory_id: int):
    return db.execute(
        text(
            """
            SELECT
                id,
                cpu_pct,
                mem_pct,
                disk_pct,
                boot_time,
                collected_at
            FROM inventory_heartbeats
            WHERE inventory_id = :inventory_id
            ORDER BY collected_at DESC, id DESC
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchone()


def evaluate_metric_thresholds(
    db: Session,
    inventory_id: int,
    hostname: str,
    cpu_pct: Optional[float],
    mem_pct: Optional[float],
    disk_pct: Optional[float],
) -> Dict[str, Any]:
    opened: List[str] = []
    resolved: List[str] = []

    cpu_warn_threshold = get_agent_cpu_warn_pct(db)
    cpu_crit_threshold = get_agent_cpu_crit_pct(db)
    mem_warn_threshold = get_agent_mem_warn_pct(db)
    mem_crit_threshold = get_agent_mem_crit_pct(db)
    disk_warn_threshold = get_agent_disk_warn_pct(db)
    disk_crit_threshold = get_agent_disk_crit_pct(db)

    def handle_metric(
        warn_key: str,
        crit_key: str,
        label: str,
        metric_name: str,
        value: Optional[float],
        warn_threshold: float,
        crit_threshold: float,
    ) -> None:
        nonlocal opened, resolved

        if value is None:
            resolve_alerts(db, inventory_id, [warn_key, crit_key])
            resolved.extend([warn_key, crit_key])
            return

        if value >= crit_threshold:
            open_or_refresh_alert(
                db=db,
                inventory_id=inventory_id,
                alert_key=crit_key,
                severity="CRITICAL",
                message=f"{hostname}: {label} is {value:.1f}% (critical >= {crit_threshold:.1f}%)",
                meta={
                    "metric": metric_name,
                    "value": value,
                    "threshold": crit_threshold,
                    "warning_threshold": warn_threshold,
                    "critical_threshold": crit_threshold,
                    "policy": get_agent_alert_policy(db),
                },
            )
            resolve_alert(db, inventory_id, warn_key)
            opened.append(crit_key)
            resolved.append(warn_key)
            return

        if value >= warn_threshold:
            open_or_refresh_alert(
                db=db,
                inventory_id=inventory_id,
                alert_key=warn_key,
                severity="WARNING",
                message=f"{hostname}: {label} is {value:.1f}% (warning >= {warn_threshold:.1f}%)",
                meta={
                    "metric": metric_name,
                    "value": value,
                    "threshold": warn_threshold,
                    "warning_threshold": warn_threshold,
                    "critical_threshold": crit_threshold,
                    "policy": get_agent_alert_policy(db),
                },
            )
            resolve_alert(db, inventory_id, crit_key)
            opened.append(warn_key)
            resolved.append(crit_key)
            return

        resolve_alerts(db, inventory_id, [warn_key, crit_key])
        resolved.extend([warn_key, crit_key])

    handle_metric(
        warn_key="agent_cpu_high_warning",
        crit_key="agent_cpu_high_critical",
        label="CPU",
        metric_name="cpu",
        value=cpu_pct,
        warn_threshold=cpu_warn_threshold,
        crit_threshold=cpu_crit_threshold,
    )
    handle_metric(
        warn_key="agent_memory_high_warning",
        crit_key="agent_memory_high_critical",
        label="Memory",
        metric_name="memory",
        value=mem_pct,
        warn_threshold=mem_warn_threshold,
        crit_threshold=mem_crit_threshold,
    )
    handle_metric(
        warn_key="agent_disk_high_warning",
        crit_key="agent_disk_high_critical",
        label="Disk",
        metric_name="disk",
        value=disk_pct,
        warn_threshold=disk_warn_threshold,
        crit_threshold=disk_crit_threshold,
    )

    return {
        "opened": opened,
        "resolved": resolved,
    }


def evaluate_agent_alerts_for_inventory(db: Session, inventory_id: int) -> Dict[str, Any]:
    inv = get_inventory_agent_row(db, inventory_id)
    if not inv:
        raise HTTPException(status_code=404, detail="inventory not found")

    hostname = row_value(inv, "asset_name") or row_value(inv, "hostname") or f"agent-{inventory_id}"
    current_ip = row_value(inv, "current_ip") or row_value(inv, "ip_address")
    last_seen_at = row_value(inv, "last_seen_at")
    last_boot_time = row_value(inv, "last_boot_time")

    latest = get_latest_heartbeat_row(db, inventory_id)
    latest_cpu = row_value(latest, "cpu_pct") if latest else None
    latest_mem = row_value(latest, "mem_pct") if latest else None
    latest_disk = row_value(latest, "disk_pct") if latest else None
    latest_boot = row_value(latest, "boot_time") if latest else None
    latest_collected_at = row_value(latest, "collected_at") if latest else None

    status_now = discovery_status_from_last_seen(db, last_seen_at)

    opened: List[str] = []
    resolved: List[str] = []

    latest_metric_dt = parse_dt(latest_collected_at)
    heartbeat_timeout_sec = get_agent_up_seconds(db)
    metric_freshness_timeout_sec = get_agent_metric_fresh_seconds(db)

    if status_now == "DOWN":
        open_or_refresh_alert(
            db=db,
            inventory_id=inventory_id,
            alert_key="agent_heartbeat_lost",
            severity="CRITICAL",
            message=f"{hostname}: agent heartbeat lost",
            meta={
                "hostname": hostname,
                "current_ip": current_ip,
                "last_seen_at": last_seen_at,
                "threshold_seconds": heartbeat_timeout_sec,
                "policy": get_agent_alert_policy(db),
            },
        )
        opened.append("agent_heartbeat_lost")
    else:
        resolve_alert(db, inventory_id, "agent_heartbeat_lost")
        resolved.append("agent_heartbeat_lost")

    if status_now == "UP":
        if latest_metric_dt is None:
            open_or_refresh_alert(
                db=db,
                inventory_id=inventory_id,
                alert_key="agent_metrics_missing",
                severity="WARNING",
                message=f"{hostname}: agent is up but no metrics sample found",
                meta={
                    "hostname": hostname,
                    "current_ip": current_ip,
                    "last_seen_at": last_seen_at,
                    "threshold_seconds": metric_freshness_timeout_sec,
                    "policy": get_agent_alert_policy(db),
                },
            )
            opened.append("agent_metrics_missing")
        else:
            age_sec = (utcnow() - latest_metric_dt).total_seconds()
            if age_sec > metric_freshness_timeout_sec:
                open_or_refresh_alert(
                    db=db,
                    inventory_id=inventory_id,
                    alert_key="agent_metrics_missing",
                    severity="WARNING",
                    message=f"{hostname}: latest metrics are stale ({int(age_sec)}s old)",
                    meta={
                        "hostname": hostname,
                        "current_ip": current_ip,
                        "latest_metric_at": latest_collected_at,
                        "age_seconds": int(age_sec),
                        "threshold_seconds": metric_freshness_timeout_sec,
                        "policy": get_agent_alert_policy(db),
                    },
                )
                opened.append("agent_metrics_missing")
            else:
                resolve_alert(db, inventory_id, "agent_metrics_missing")
                resolved.append("agent_metrics_missing")
    else:
        resolve_alert(db, inventory_id, "agent_metrics_missing")
        resolved.append("agent_metrics_missing")

    metric_result = evaluate_metric_thresholds(
        db=db,
        inventory_id=inventory_id,
        hostname=hostname,
        cpu_pct=normalize_float(latest_cpu),
        mem_pct=normalize_float(latest_mem),
        disk_pct=normalize_float(latest_disk),
    )
    opened.extend(metric_result["opened"])
    resolved.extend(metric_result["resolved"])

    if latest_boot and last_boot_time and str(latest_boot) != str(last_boot_time):
        open_or_refresh_alert(
            db=db,
            inventory_id=inventory_id,
            alert_key="agent_boot_time_changed",
            severity="INFO",
            message=f"{hostname}: boot time changed (reboot detected)",
            meta={
                "hostname": hostname,
                "old_boot_time": str(last_boot_time),
                "new_boot_time": str(latest_boot),
            },
        )
        opened.append("agent_boot_time_changed")
    else:
        resolve_alert(db, inventory_id, "agent_boot_time_changed")
        resolved.append("agent_boot_time_changed")

    db.commit()

    return {
        "inventory_id": inventory_id,
        "hostname": hostname,
        "status": status_now,
        "last_seen_at": last_seen_at,
        "latest_metric_at": latest_collected_at,
        "cpu_pct": latest_cpu,
        "mem_pct": latest_mem,
        "disk_pct": latest_disk,
        "opened": sorted(set(opened)),
        "resolved": sorted(set(resolved)),
    }


def upsert_pending_device(db: Session, data: Dict[str, Any]) -> Dict[str, Any]:
    ensure_pending_schema(db)
    now = utcnow_iso()
    payload_json = json.dumps(data, ensure_ascii=False)

    existing = find_pending_by_device_uid(db, data["device_uid"])
    if existing:
        pending_id = row_value(existing, "id", 0)
        current_status = str(row_value(existing, "status") or "PENDING").upper()

        if current_status == "APPROVED":
            return {
                "pending_id": pending_id,
                "status": "APPROVED",
                "approved_inventory_id": row_value(existing, "approved_inventory_id"),
            }

        if current_status == "REJECTED":
            db.execute(
                text(
                    """
                    UPDATE pending_devices
                    SET hostname = :hostname,
                        current_ip = :current_ip,
                        os_type = :os_type,
                        os_version = :os_version,
                        agent_version = :agent_version,
                        machine_guid = :machine_guid,
                        bios_serial = :bios_serial,
                        motherboard_serial = :motherboard_serial,
                        mac_primary = :mac_primary,
                        manufacturer = :manufacturer,
                        model = :model,
                        cpu_model = :cpu_model,
                        ram_bytes = :ram_bytes,
                        room = :room,
                        identity_source = :identity_source,
                        last_boot_time = :last_boot_time,
                        cpu_pct = :cpu_pct,
                        mem_pct = :mem_pct,
                        disk_pct = :disk_pct,
                        last_seen_at = :last_seen_at,
                        payload_json = :payload_json
                    WHERE id = :id
                    """
                ),
                {
                    "id": pending_id,
                    "hostname": data["hostname"],
                    "current_ip": data["current_ip"],
                    "os_type": data["os_type"],
                    "os_version": data["os_version"],
                    "agent_version": data["agent_version"],
                    "machine_guid": data["machine_guid"],
                    "bios_serial": data["bios_serial"],
                    "motherboard_serial": data["motherboard_serial"],
                    "mac_primary": data["mac_primary"],
                    "manufacturer": data["manufacturer"],
                    "model": data["model"],
                    "cpu_model": data["cpu_model"],
                    "ram_bytes": data["ram_bytes"],
                    "room": data["room"],
                    "identity_source": data["identity_source"],
                    "last_boot_time": data["boot_time"],
                    "cpu_pct": data["cpu_pct"],
                    "mem_pct": data["mem_pct"],
                    "disk_pct": data["disk_pct"],
                    "last_seen_at": now,
                    "payload_json": payload_json,
                },
            )
            db.commit()
            return {"pending_id": pending_id, "status": "REJECTED"}

        db.execute(
            text(
                """
                UPDATE pending_devices
                SET hostname = :hostname,
                    current_ip = :current_ip,
                    os_type = :os_type,
                    os_version = :os_version,
                    agent_version = :agent_version,
                    machine_guid = :machine_guid,
                    bios_serial = :bios_serial,
                    motherboard_serial = :motherboard_serial,
                    mac_primary = :mac_primary,
                    manufacturer = :manufacturer,
                    model = :model,
                    cpu_model = :cpu_model,
                    ram_bytes = :ram_bytes,
                    room = :room,
                    identity_source = :identity_source,
                    last_boot_time = :last_boot_time,
                    cpu_pct = :cpu_pct,
                    mem_pct = :mem_pct,
                    disk_pct = :disk_pct,
                    last_seen_at = :last_seen_at,
                    payload_json = :payload_json
                WHERE id = :id
                """
            ),
            {
                "id": pending_id,
                "hostname": data["hostname"],
                "current_ip": data["current_ip"],
                "os_type": data["os_type"],
                "os_version": data["os_version"],
                "agent_version": data["agent_version"],
                "machine_guid": data["machine_guid"],
                "bios_serial": data["bios_serial"],
                "motherboard_serial": data["motherboard_serial"],
                "mac_primary": data["mac_primary"],
                "manufacturer": data["manufacturer"],
                "model": data["model"],
                "cpu_model": data["cpu_model"],
                "ram_bytes": data["ram_bytes"],
                "room": data["room"],
                "identity_source": data["identity_source"],
                "last_boot_time": data["boot_time"],
                "cpu_pct": data["cpu_pct"],
                "mem_pct": data["mem_pct"],
                "disk_pct": data["disk_pct"],
                "last_seen_at": now,
                "payload_json": payload_json,
            },
        )
        db.commit()
        return {"pending_id": pending_id, "status": "PENDING"}

    result = db.execute(
        text(
            """
            INSERT INTO pending_devices (
                device_uid,
                hostname,
                current_ip,
                os_type,
                os_version,
                agent_version,
                machine_guid,
                bios_serial,
                motherboard_serial,
                mac_primary,
                manufacturer,
                model,
                cpu_model,
                ram_bytes,
                room,
                identity_source,
                last_boot_time,
                cpu_pct,
                mem_pct,
                disk_pct,
                status,
                first_seen_at,
                last_seen_at,
                payload_json
            )
            VALUES (
                :device_uid,
                :hostname,
                :current_ip,
                :os_type,
                :os_version,
                :agent_version,
                :machine_guid,
                :bios_serial,
                :motherboard_serial,
                :mac_primary,
                :manufacturer,
                :model,
                :cpu_model,
                :ram_bytes,
                :room,
                :identity_source,
                :last_boot_time,
                :cpu_pct,
                :mem_pct,
                :disk_pct,
                'PENDING',
                :first_seen_at,
                :last_seen_at,
                :payload_json
            )
            """
        ),
        {
            "device_uid": data["device_uid"],
            "hostname": data["hostname"],
            "current_ip": data["current_ip"],
            "os_type": data["os_type"],
            "os_version": data["os_version"],
            "agent_version": data["agent_version"],
            "machine_guid": data["machine_guid"],
            "bios_serial": data["bios_serial"],
            "motherboard_serial": data["motherboard_serial"],
            "mac_primary": data["mac_primary"],
            "manufacturer": data["manufacturer"],
            "model": data["model"],
            "cpu_model": data["cpu_model"],
            "ram_bytes": data["ram_bytes"],
            "room": data["room"],
            "identity_source": data["identity_source"],
            "last_boot_time": data["boot_time"],
            "cpu_pct": data["cpu_pct"],
            "mem_pct": data["mem_pct"],
            "disk_pct": data["disk_pct"],
            "first_seen_at": now,
            "last_seen_at": now,
            "payload_json": payload_json,
        },
    )
    db.commit()
    return {"pending_id": result.lastrowid, "status": "PENDING"}


def upsert_inventory_for_approved_device(db: Session, data: Dict[str, Any]) -> Dict[str, Any]:
    existing = find_inventory_by_device_uid(db, data["device_uid"])
    now = utcnow_iso()

    previous_ip = None
    previous_boot_time = None

    if existing:
        inventory_id = row_value(existing, "id", 0)
        previous_ip = row_value(existing, "current_ip", 2)
        previous_boot_time = row_value(existing, "last_boot_time", 3)

        db.execute(
            text(
                """
                UPDATE inventory
                SET hostname = :hostname,
                    ip_address = COALESCE(:current_ip, ip_address),
                    current_ip = COALESCE(:current_ip, current_ip),
                    device_type = COALESCE(device_type, 'pc'),
                    location = COALESCE(:room, location, 'UNASSIGNED'),
                    status = 'UP',
                    monitoring_type = 'agent',
                    os_type = COALESCE(:os_type, os_type),
                    os_version = COALESCE(:os_version, os_version),
                    agent_version = COALESCE(:agent_version, agent_version),
                    machine_guid = COALESCE(:machine_guid, machine_guid),
                    bios_serial = COALESCE(:bios_serial, bios_serial),
                    motherboard_serial = COALESCE(:motherboard_serial, motherboard_serial),
                    mac_primary = COALESCE(:mac_primary, mac_primary),
                    manufacturer = COALESCE(:manufacturer, manufacturer),
                    model = COALESCE(:model, model),
                    cpu_model = COALESCE(:cpu_model, cpu_model),
                    ram_bytes = COALESCE(:ram_bytes, ram_bytes),
                    room = COALESCE(:room, room),
                    last_seen_at = :last_seen_at,
                    last_boot_time = COALESCE(:boot_time, last_boot_time),
                    identity_source = 'device_uid',
                    is_discovered = 1
                WHERE id = :inventory_id
                """
            ),
            {
                "inventory_id": inventory_id,
                "hostname": data["hostname"],
                "current_ip": data["current_ip"],
                "room": data["room"],
                "os_type": data["os_type"],
                "os_version": data["os_version"],
                "agent_version": data["agent_version"],
                "machine_guid": data["machine_guid"],
                "bios_serial": data["bios_serial"],
                "motherboard_serial": data["motherboard_serial"],
                "mac_primary": data["mac_primary"],
                "manufacturer": data["manufacturer"],
                "model": data["model"],
                "cpu_model": data["cpu_model"],
                "ram_bytes": data["ram_bytes"],
                "last_seen_at": now,
                "boot_time": data["boot_time"],
            },
        )
        created = False
    else:
        result = db.execute(
            text(
                """
                INSERT INTO inventory (
                    hostname,
                    ip_address,
                    current_ip,
                    device_type,
                    location,
                    status,
                    created_at,
                    monitoring_type,
                    scrape_port,
                    device_uid,
                    os_type,
                    os_version,
                    agent_version,
                    machine_guid,
                    bios_serial,
                    motherboard_serial,
                    mac_primary,
                    manufacturer,
                    model,
                    cpu_model,
                    ram_bytes,
                    room,
                    last_seen_at,
                    last_boot_time,
                    identity_source,
                    is_discovered
                )
                VALUES (
                    :hostname,
                    :ip_address,
                    :current_ip,
                    'pc',
                    :location,
                    'UP',
                    :created_at,
                    'agent',
                    NULL,
                    :device_uid,
                    :os_type,
                    :os_version,
                    :agent_version,
                    :machine_guid,
                    :bios_serial,
                    :motherboard_serial,
                    :mac_primary,
                    :manufacturer,
                    :model,
                    :cpu_model,
                    :ram_bytes,
                    :room,
                    :last_seen_at,
                    :last_boot_time,
                    'device_uid',
                    1
                )
                """
            ),
            {
                "hostname": data["hostname"],
                "ip_address": data["current_ip"],
                "current_ip": data["current_ip"],
                "location": data["room"] or "UNASSIGNED",
                "created_at": now,
                "device_uid": data["device_uid"],
                "os_type": data["os_type"],
                "os_version": data["os_version"],
                "agent_version": data["agent_version"],
                "machine_guid": data["machine_guid"],
                "bios_serial": data["bios_serial"],
                "motherboard_serial": data["motherboard_serial"],
                "mac_primary": data["mac_primary"],
                "manufacturer": data["manufacturer"],
                "model": data["model"],
                "cpu_model": data["cpu_model"],
                "ram_bytes": data["ram_bytes"],
                "room": data["room"],
                "last_seen_at": now,
                "last_boot_time": data["boot_time"],
            },
        )
        inventory_id = result.lastrowid
        created = True

    upsert_ip_history(db, inventory_id, data["current_ip"])

    insert_heartbeat(
        db=db,
        inventory_id=inventory_id,
        cpu_pct=data["cpu_pct"],
        mem_pct=data["mem_pct"],
        disk_pct=data["disk_pct"],
        boot_time=data["boot_time"],
    )

    if previous_ip and data["current_ip"] and previous_ip != data["current_ip"]:
        open_or_refresh_alert(
            db=db,
            inventory_id=inventory_id,
            alert_key="ip_changed",
            severity="INFO",
            message=f"{data['hostname']}: IP changed from {previous_ip} to {data['current_ip']}",
            meta={"old_ip": previous_ip, "new_ip": data["current_ip"]},
        )
    else:
        resolve_alert(db, inventory_id, "ip_changed")

    if previous_boot_time and data["boot_time"] and str(previous_boot_time) != str(data["boot_time"]):
        open_or_refresh_alert(
            db=db,
            inventory_id=inventory_id,
            alert_key="reboot_detected",
            severity="INFO",
            message=f"{data['hostname']}: reboot detected",
            meta={"old_boot_time": str(previous_boot_time), "new_boot_time": data["boot_time"]},
        )
    else:
        resolve_alert(db, inventory_id, "reboot_detected")

    db.commit()
    evaluate_agent_alerts_for_inventory(db, inventory_id)

    return {"inventory_id": inventory_id, "created": created}


@router.post("/agent/register")
def register_agent(payload: Dict[str, Any], db: Session = Depends(get_db)):
    data = payload_identity(payload)

    if not data["device_uid"]:
        raise HTTPException(status_code=422, detail="device_uid is required")
    if not data["hostname"]:
        raise HTTPException(status_code=422, detail="hostname is required")

    approved = find_inventory_by_device_uid(db, data["device_uid"])
    if approved:
        result = upsert_inventory_for_approved_device(db, data)
        return {
            "ok": True,
            "pending": False,
            "approved": True,
            "created": result["created"],
            "inventory_id": result["inventory_id"],
            "status": "UP",
        }

    pending = upsert_pending_device(db, data)
    return {
        "ok": True,
        "pending": True,
        "approved": False,
        "pending_id": pending["pending_id"],
        "status": pending["status"],
    }


@router.post("/agent/heartbeat")
def heartbeat_agent(payload: Dict[str, Any], db: Session = Depends(get_db)):
    data = payload_identity(payload)

    if not data["device_uid"]:
        raise HTTPException(status_code=422, detail="device_uid is required")
    if not data["hostname"]:
        raise HTTPException(status_code=422, detail="hostname is required")

    approved = find_inventory_by_device_uid(db, data["device_uid"])
    if approved:
        result = upsert_inventory_for_approved_device(db, data)
        return {
            "ok": True,
            "pending": False,
            "approved": True,
            "inventory_id": result["inventory_id"],
            "status": "UP",
        }

    pending = upsert_pending_device(db, data)
    return {
        "ok": True,
        "pending": True,
        "approved": False,
        "pending_id": pending["pending_id"],
        "status": pending["status"],
    }


@router.post("/agent/evaluate-alerts")
def evaluate_agent_alerts(
    inventory_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    if inventory_id is not None:
        result = evaluate_agent_alerts_for_inventory(db, inventory_id)
        return {
            "ok": True,
            "mode": "single",
            "count": 1,
            "results": [result],
        }

    rows = get_all_agent_inventory_rows(db)
    results = []
    for row in rows:
        inv_id = int(row_value(row, "id"))
        results.append(evaluate_agent_alerts_for_inventory(db, inv_id))

    return {
        "ok": True,
        "mode": "all",
        "count": len(results),
        "results": results,
    }


@router.get("/pending-devices", response_model=List[PendingDeviceOut])
def list_pending_devices(
    scope: str = Query("pending", description="pending | approved | rejected | all"),
    db: Session = Depends(get_db),
):
    ensure_pending_schema(db)
    scope_norm = str(scope or "pending").strip().lower()

    if scope_norm == "pending":
        where_clause = "WHERE status = 'PENDING'"
    elif scope_norm == "approved":
        where_clause = "WHERE status = 'APPROVED'"
    elif scope_norm == "rejected":
        where_clause = "WHERE status = 'REJECTED'"
    elif scope_norm == "all":
        where_clause = ""
    else:
        raise HTTPException(status_code=400, detail="invalid scope")

    rows = db.execute(
        text(
            f"""
            SELECT *
            FROM pending_devices
            {where_clause}
            ORDER BY
                CASE
                    WHEN status = 'APPROVED' THEN approved_at
                    WHEN status = 'REJECTED' THEN rejected_at
                    ELSE last_seen_at
                END DESC,
                id DESC
            """
        )
    ).fetchall()

    return [
        PendingDeviceOut(
            id=int(row_value(r, "id")),
            device_uid=row_value(r, "device_uid"),
            hostname=row_value(r, "hostname"),
            current_ip=row_value(r, "current_ip"),
            os_type=row_value(r, "os_type"),
            os_version=row_value(r, "os_version"),
            agent_version=row_value(r, "agent_version"),
            manufacturer=row_value(r, "manufacturer"),
            model=row_value(r, "model"),
            cpu_model=row_value(r, "cpu_model"),
            ram_bytes=row_value(r, "ram_bytes"),
            bios_serial=row_value(r, "bios_serial"),
            motherboard_serial=row_value(r, "motherboard_serial"),
            mac_primary=row_value(r, "mac_primary"),
            room=row_value(r, "room"),
            machine_guid=row_value(r, "machine_guid"),
            last_boot_time=row_value(r, "last_boot_time"),
            cpu_pct=row_value(r, "cpu_pct"),
            mem_pct=row_value(r, "mem_pct"),
            disk_pct=row_value(r, "disk_pct"),
            status=row_value(r, "status"),
            first_seen_at=row_value(r, "first_seen_at"),
            last_seen_at=row_value(r, "last_seen_at"),
            approved_at=row_value(r, "approved_at"),
            rejected_at=row_value(r, "rejected_at"),
            rejection_reason=row_value(r, "rejection_reason"),
            approved_inventory_id=row_value(r, "approved_inventory_id"),
        )
        for r in rows
    ]


@router.get("/pending-devices/asset-name-preview", response_model=AssetNamePreviewOut)
def preview_next_asset_name(
    room: Optional[str] = Query(default=None),
    exclude_inventory_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
):
    room_input = normalize_str(room)
    naming_policy = get_naming_policy(db)
    room_digits_required = _naming_room_digits(naming_policy)
    room_digits = normalize_room_asset_digits(
        room_input,
        room_digits_required=room_digits_required,
    )

    if not room_input:
        return AssetNamePreviewOut(
            room_input=None,
            normalized_room_digits=None,
            suggested_asset_name=None,
            can_generate=False,
            message="Room is required to preview the next asset name.",
        )

    if not room_digits:
        return AssetNamePreviewOut(
            room_input=room_input,
            normalized_room_digits=None,
            suggested_asset_name=None,
            can_generate=False,
            message=f"Room must contain at least {room_digits_required} digits, for example CP9422.",
        )

    suggestion = generate_next_asset_name(
        db=db,
        room=room_input,
        exclude_inventory_id=exclude_inventory_id,
    )

    if not suggestion:
        return AssetNamePreviewOut(
            room_input=room_input,
            normalized_room_digits=room_digits,
            suggested_asset_name=None,
            can_generate=False,
            message="Unable to generate a room-based asset name for this room.",
        )

    return AssetNamePreviewOut(
        room_input=room_input,
        normalized_room_digits=room_digits,
        suggested_asset_name=suggestion,
        can_generate=True,
        message="Preview generated from current inventory asset_name values.",
    )


@router.get("/pending-devices/{pending_id}", response_model=PendingDeviceOut)
def get_pending_device(pending_id: int, db: Session = Depends(get_db)):
    row = find_pending_by_id(db, pending_id)
    if not row:
        raise HTTPException(status_code=404, detail="pending device not found")

    return PendingDeviceOut(
        id=int(row_value(row, "id")),
        device_uid=row_value(row, "device_uid"),
        hostname=row_value(row, "hostname"),
        current_ip=row_value(row, "current_ip"),
        os_type=row_value(row, "os_type"),
        os_version=row_value(row, "os_version"),
        agent_version=row_value(row, "agent_version"),
        manufacturer=row_value(row, "manufacturer"),
        model=row_value(row, "model"),
        cpu_model=row_value(row, "cpu_model"),
        ram_bytes=row_value(row, "ram_bytes"),
        bios_serial=row_value(row, "bios_serial"),
        motherboard_serial=row_value(row, "motherboard_serial"),
        mac_primary=row_value(row, "mac_primary"),
        room=row_value(row, "room"),
        machine_guid=row_value(row, "machine_guid"),
        last_boot_time=row_value(row, "last_boot_time"),
        cpu_pct=row_value(row, "cpu_pct"),
        mem_pct=row_value(row, "mem_pct"),
        disk_pct=row_value(row, "disk_pct"),
        status=row_value(row, "status"),
        first_seen_at=row_value(row, "first_seen_at"),
        last_seen_at=row_value(row, "last_seen_at"),
        approved_at=row_value(row, "approved_at"),
        rejected_at=row_value(row, "rejected_at"),
        rejection_reason=row_value(row, "rejection_reason"),
        approved_inventory_id=row_value(row, "approved_inventory_id"),
    )


@router.post("/pending-devices/{pending_id}/approve")
def approve_pending_device(
    pending_id: int,
    request: Request,
    payload: Optional[PendingApproveIn] = None,
    actor_name: str = Depends(get_actor_name),
    actor_role: str = Depends(get_actor_role),
    db: Session = Depends(get_db),
):
    row = find_pending_by_id(db, pending_id)
    if not row:
        raise HTTPException(status_code=404, detail="pending device not found")

    current_status = str(row_value(row, "status") or "PENDING").upper()
    if current_status == "APPROVED":
        return {
            "ok": True,
            "pending_id": pending_id,
            "status": "APPROVED",
            "inventory_id": row_value(row, "approved_inventory_id"),
        }

    if current_status == "REJECTED":
        db.execute(
            text(
                """
                UPDATE pending_devices
                SET status = 'PENDING',
                    rejected_at = NULL,
                    rejection_reason = NULL
                WHERE id = :id
                """
            ),
            {"id": pending_id},
        )
        db.commit()
        row = find_pending_by_id(db, pending_id)

    room = normalize_str(payload.room if payload else None) or row_value(row, "room")
    location = normalize_str(payload.location if payload else None) or room or "UNASSIGNED"
    requested_asset_name = normalize_str(payload.asset_name if payload else None)
    device_type = normalize_str(payload.device_type if payload else None) or "pc"

    device_uid = row_value(row, "device_uid")
    hostname = row_value(row, "hostname")
    current_ip = row_value(row, "current_ip")

    existing_inventory = find_inventory_by_device_uid(db, device_uid)
    now = utcnow_iso()

    inventory_id = None
    current_inventory_asset_name = None
    if existing_inventory:
        inventory_id = row_value(existing_inventory, "id", 0)
        current_inventory_asset_name = normalize_str(row_value(existing_inventory, "asset_name", 4))

    final_asset_name = requested_asset_name or current_inventory_asset_name
    if not final_asset_name:
        final_asset_name = generate_next_asset_name(
            db=db,
            room=room,
            exclude_inventory_id=inventory_id,
        )

    if existing_inventory:
        inventory_id = row_value(existing_inventory, "id", 0)
        db.execute(
            text(
                """
                UPDATE inventory
                SET hostname = :hostname,
                    asset_name = COALESCE(:asset_name, asset_name),
                    ip_address = COALESCE(:current_ip, ip_address),
                    current_ip = COALESCE(:current_ip, current_ip),
                    device_type = COALESCE(:device_type, device_type),
                    location = COALESCE(:location, location),
                    status = 'UP',
                    monitoring_type = 'agent',
                    os_type = COALESCE(:os_type, os_type),
                    os_version = COALESCE(:os_version, os_version),
                    agent_version = COALESCE(:agent_version, agent_version),
                    machine_guid = COALESCE(:machine_guid, machine_guid),
                    bios_serial = COALESCE(:bios_serial, bios_serial),
                    motherboard_serial = COALESCE(:motherboard_serial, motherboard_serial),
                    mac_primary = COALESCE(:mac_primary, mac_primary),
                    manufacturer = COALESCE(:manufacturer, manufacturer),
                    model = COALESCE(:model, model),
                    cpu_model = COALESCE(:cpu_model, cpu_model),
                    ram_bytes = COALESCE(:ram_bytes, ram_bytes),
                    room = COALESCE(:room, room),
                    last_seen_at = COALESCE(:last_seen_at, last_seen_at),
                    last_boot_time = COALESCE(:last_boot_time, last_boot_time),
                    identity_source = 'device_uid',
                    is_discovered = 1
                WHERE id = :inventory_id
                """
            ),
            {
                "inventory_id": inventory_id,
                "hostname": hostname,
                "asset_name": final_asset_name,
                "current_ip": current_ip,
                "device_type": device_type,
                "location": location,
                "os_type": row_value(row, "os_type"),
                "os_version": row_value(row, "os_version"),
                "agent_version": row_value(row, "agent_version"),
                "machine_guid": row_value(row, "machine_guid"),
                "bios_serial": row_value(row, "bios_serial"),
                "motherboard_serial": row_value(row, "motherboard_serial"),
                "mac_primary": row_value(row, "mac_primary"),
                "manufacturer": row_value(row, "manufacturer"),
                "model": row_value(row, "model"),
                "cpu_model": row_value(row, "cpu_model"),
                "ram_bytes": row_value(row, "ram_bytes"),
                "room": room,
                "last_seen_at": row_value(row, "last_seen_at"),
                "last_boot_time": row_value(row, "last_boot_time"),
            },
        )
    else:
        result = db.execute(
            text(
                """
                INSERT INTO inventory (
                    hostname,
                    asset_name,
                    ip_address,
                    current_ip,
                    device_type,
                    location,
                    status,
                    created_at,
                    monitoring_type,
                    scrape_port,
                    device_uid,
                    os_type,
                    os_version,
                    agent_version,
                    machine_guid,
                    bios_serial,
                    motherboard_serial,
                    mac_primary,
                    manufacturer,
                    model,
                    cpu_model,
                    ram_bytes,
                    room,
                    last_seen_at,
                    last_boot_time,
                    identity_source,
                    is_discovered
                )
                VALUES (
                    :hostname,
                    :asset_name,
                    :ip_address,
                    :current_ip,
                    :device_type,
                    :location,
                    'UP',
                    :created_at,
                    'agent',
                    NULL,
                    :device_uid,
                    :os_type,
                    :os_version,
                    :agent_version,
                    :machine_guid,
                    :bios_serial,
                    :motherboard_serial,
                    :mac_primary,
                    :manufacturer,
                    :model,
                    :cpu_model,
                    :ram_bytes,
                    :room,
                    :last_seen_at,
                    :last_boot_time,
                    'device_uid',
                    1
                )
                """
            ),
            {
                "hostname": hostname,
                "asset_name": final_asset_name,
                "ip_address": current_ip,
                "current_ip": current_ip,
                "device_type": device_type,
                "location": location,
                "created_at": now,
                "device_uid": device_uid,
                "os_type": row_value(row, "os_type"),
                "os_version": row_value(row, "os_version"),
                "agent_version": row_value(row, "agent_version"),
                "machine_guid": row_value(row, "machine_guid"),
                "bios_serial": row_value(row, "bios_serial"),
                "motherboard_serial": row_value(row, "motherboard_serial"),
                "mac_primary": row_value(row, "mac_primary"),
                "manufacturer": row_value(row, "manufacturer"),
                "model": row_value(row, "model"),
                "cpu_model": row_value(row, "cpu_model"),
                "ram_bytes": row_value(row, "ram_bytes"),
                "room": room,
                "last_seen_at": row_value(row, "last_seen_at"),
                "last_boot_time": row_value(row, "last_boot_time"),
            },
        )
        inventory_id = result.lastrowid

    upsert_ip_history(db, inventory_id, current_ip)
    insert_heartbeat(
        db=db,
        inventory_id=inventory_id,
        cpu_pct=row_value(row, "cpu_pct"),
        mem_pct=row_value(row, "mem_pct"),
        disk_pct=row_value(row, "disk_pct"),
        boot_time=row_value(row, "last_boot_time"),
    )

    db.execute(
        text(
            """
            UPDATE pending_devices
            SET status = 'APPROVED',
                approved_at = :approved_at,
                approved_inventory_id = :inventory_id
            WHERE id = :id
            """
        ),
        {
            "id": pending_id,
            "approved_at": now,
            "inventory_id": inventory_id,
        },
    )

    write_audit(
        db,
        request=request,
        action="PENDING_DEVICE_APPROVED",
        entity_type="pending_device",
        entity_id=str(pending_id),
        actor_name=actor_name,
        actor_role=actor_role,
        meta={
            "pending_id": pending_id,
            "device_uid": device_uid,
            "hostname": hostname,
            "current_ip": current_ip,
            "inventory_id": inventory_id,
            "asset_name": final_asset_name,
            "room": room,
            "location": location,
            "device_type": device_type,
            "source": "pending_device_approval",
            "naming_policy": get_naming_policy(db),
        },
    )

    db.commit()
    evaluate_agent_alerts_for_inventory(db, inventory_id)

    return {
        "ok": True,
        "pending_id": pending_id,
        "status": "APPROVED",
        "inventory_id": inventory_id,
        "asset_name": final_asset_name,
        "room": room,
    }


@router.post("/pending-devices/{pending_id}/reject")
def reject_pending_device(
    pending_id: int,
    request: Request,
    payload: Optional[PendingRejectIn] = None,
    actor_name: str = Depends(get_actor_name),
    actor_role: str = Depends(get_actor_role),
    db: Session = Depends(get_db),
):
    row = find_pending_by_id(db, pending_id)
    if not row:
        raise HTTPException(status_code=404, detail="pending device not found")

    reason = normalize_str(payload.reason if payload else None)
    rejected_at = utcnow_iso()

    db.execute(
        text(
            """
            UPDATE pending_devices
            SET status = 'REJECTED',
                rejected_at = :rejected_at,
                rejection_reason = :reason
            WHERE id = :id
            """
        ),
        {
            "id": pending_id,
            "rejected_at": rejected_at,
            "reason": reason,
        },
    )

    write_audit(
        db,
        request=request,
        action="PENDING_DEVICE_REJECTED",
        entity_type="pending_device",
        entity_id=str(pending_id),
        actor_name=actor_name,
        actor_role=actor_role,
        meta={
            "pending_id": pending_id,
            "device_uid": row_value(row, "device_uid"),
            "hostname": row_value(row, "hostname"),
            "current_ip": row_value(row, "current_ip"),
            "reason": reason,
            "source": "pending_device_rejection",
        },
    )

    db.commit()

    return {
        "ok": True,
        "pending_id": pending_id,
        "status": "REJECTED",
    }


@router.get("/discovery", response_model=List[DiscoveryItemOut])
def list_discovery(db: Session = Depends(get_db)):
    rows = db.execute(
        text(
            """
            SELECT
                id,
                hostname,
                asset_name,
                current_ip,
                room,
                os_type,
                last_seen_at,
                is_discovered
            FROM inventory
            WHERE monitoring_type = 'agent'
               OR is_discovered = 1
               OR os_type = 'windows'
            ORDER BY
                CASE WHEN last_seen_at IS NULL THEN 1 ELSE 0 END,
                last_seen_at DESC,
                id DESC
            """
        )
    ).fetchall()

    out: List[DiscoveryItemOut] = []
    for r in rows:
        last_seen_at = row_value(r, "last_seen_at")
        out.append(
            DiscoveryItemOut(
                id=int(row_value(r, "id")),
                hostname=row_value(r, "hostname") or "-",
                asset_name=row_value(r, "asset_name"),
                current_ip=row_value(r, "current_ip"),
                room=row_value(r, "room"),
                status=discovery_status_from_last_seen(db, last_seen_at),
                os_type=row_value(r, "os_type"),
                last_seen_at=last_seen_at,
                is_discovered=bool(row_value(r, "is_discovered")),
            )
        )
    return out


@router.get("/inventory/{inventory_id}/ip-history", response_model=List[IpHistoryOut])
def get_ip_history(inventory_id: int, db: Session = Depends(get_db)):
    if not find_inventory_by_id(db, inventory_id):
        raise HTTPException(status_code=404, detail="inventory not found")

    rows = db.execute(
        text(
            """
            SELECT id, ip_address, first_seen_at, last_seen_at
            FROM inventory_ip_history
            WHERE inventory_id = :inventory_id
            ORDER BY last_seen_at DESC, id DESC
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchall()

    return [
        IpHistoryOut(
            id=int(row_value(r, "id")),
            ip_address=row_value(r, "ip_address"),
            first_seen_at=row_value(r, "first_seen_at"),
            last_seen_at=row_value(r, "last_seen_at"),
        )
        for r in rows
    ]


@router.get("/inventory/{inventory_id}/metrics", response_model=List[HeartbeatOut])
def get_metrics(inventory_id: int, db: Session = Depends(get_db)):
    if not find_inventory_by_id(db, inventory_id):
        raise HTTPException(status_code=404, detail="inventory not found")

    rows = db.execute(
        text(
            """
            SELECT id, cpu_pct, mem_pct, disk_pct, boot_time, collected_at
            FROM inventory_heartbeats
            WHERE inventory_id = :inventory_id
            ORDER BY collected_at DESC, id DESC
            LIMIT 50
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchall()

    return [
        HeartbeatOut(
            id=int(row_value(r, "id")),
            cpu_pct=row_value(r, "cpu_pct"),
            mem_pct=row_value(r, "mem_pct"),
            disk_pct=row_value(r, "disk_pct"),
            boot_time=row_value(r, "boot_time"),
            collected_at=row_value(r, "collected_at"),
        )
        for r in rows
    ]


@router.get("/inventory/{inventory_id}/alerts", response_model=List[DeviceAlertOut])
def get_alerts(inventory_id: int, db: Session = Depends(get_db)):
    if not find_inventory_by_id(db, inventory_id):
        raise HTTPException(status_code=404, detail="inventory not found")

    rows = db.execute(
        text(
            """
            SELECT id, alert_key, severity, message, status, created_at, resolved_at, meta_json
            FROM device_alerts
            WHERE inventory_id = :inventory_id
            ORDER BY
                CASE WHEN status = 'OPEN' THEN 0 ELSE 1 END,
                created_at DESC,
                id DESC
            LIMIT 100
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchall()

    return [
        DeviceAlertOut(
            id=int(row_value(r, "id")),
            alert_key=row_value(r, "alert_key"),
            severity=row_value(r, "severity"),
            message=row_value(r, "message"),
            status=row_value(r, "status"),
            created_at=row_value(r, "created_at"),
            resolved_at=row_value(r, "resolved_at"),
            meta_json=row_value(r, "meta_json"),
        )
        for r in rows
    ]


@router.get("/inventory/{inventory_id}/spec")
def get_spec(inventory_id: int, db: Session = Depends(get_db)):
    row = db.execute(
        text(
            """
            SELECT
                id,
                hostname,
                asset_name,
                device_uid,
                current_ip,
                os_type,
                os_version,
                agent_version,
                machine_guid,
                bios_serial,
                motherboard_serial,
                mac_primary,
                manufacturer,
                model,
                cpu_model,
                ram_bytes,
                room,
                last_seen_at,
                last_boot_time
            FROM inventory
            WHERE id = :inventory_id
            LIMIT 1
            """
        ),
        {"inventory_id": inventory_id},
    ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="inventory not found")

    return {
        "id": row_value(row, "id"),
        "hostname": row_value(row, "hostname"),
        "asset_name": row_value(row, "asset_name"),
        "device_uid": row_value(row, "device_uid"),
        "current_ip": row_value(row, "current_ip"),
        "os_type": row_value(row, "os_type"),
        "os_version": row_value(row, "os_version"),
        "agent_version": row_value(row, "agent_version"),
        "machine_guid": row_value(row, "machine_guid"),
        "bios_serial": row_value(row, "bios_serial"),
        "motherboard_serial": row_value(row, "motherboard_serial"),
        "mac_primary": row_value(row, "mac_primary"),
        "manufacturer": row_value(row, "manufacturer"),
        "model": row_value(row, "model"),
        "cpu_model": row_value(row, "cpu_model"),
        "ram_bytes": row_value(row, "ram_bytes"),
        "room": row_value(row, "room"),
        "last_seen_at": row_value(row, "last_seen_at"),
        "last_boot_time": row_value(row, "last_boot_time"),
    }
