import json
import os
from typing import Dict, List

from sqlalchemy.orm import Session

from models import Inventory

FILE_SD_DIR = "/etc/prometheus/file_sd"
NODE_TARGET_FILE = os.path.join(FILE_SD_DIR, "node_exporter_targets.json")
SNMP_TARGET_FILE = os.path.join(FILE_SD_DIR, "snmp_targets.json")


def _ensure_file_sd_dir() -> None:
    os.makedirs(FILE_SD_DIR, exist_ok=True)


def _safe_str(value) -> str:
    if value is None:
        return ""
    return str(value)


def _atomic_write_json(path: str, data: List[Dict]) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def _build_node_targets(db: Session) -> List[Dict]:
    servers = (
        db.query(Inventory)
        .filter(Inventory.device_type == "server")
        .filter(Inventory.is_deleted == 0)
        .all()
    )

    targets: List[Dict] = []

    for s in servers:
        if not s.ip_address:
            continue

        monitoring_type = _safe_str(getattr(s, "monitoring_type", "")).lower()
        if monitoring_type and monitoring_type != "node_exporter":
            continue

        port = s.scrape_port or 9100

        targets.append(
            {
                "targets": [f"{s.ip_address}:{port}"],
                "labels": {
                    "inventory_id": _safe_str(s.id),
                    "hostname": _safe_str(s.hostname),
                    "asset_name": _safe_str(getattr(s, "asset_name", "")),
                    "ip_address": _safe_str(s.ip_address),
                    "device_type": _safe_str(s.device_type),
                    "location": _safe_str(getattr(s, "location", "")),
                    "room": _safe_str(getattr(s, "room", "")),
                    "building": _safe_str(getattr(s, "building", "")),
                    "monitoring_type": _safe_str(getattr(s, "monitoring_type", "node_exporter")),
                    "os_type": _safe_str(getattr(s, "os_type", "")),
                },
            }
        )

    return targets


def _build_snmp_targets(db: Session) -> List[Dict]:
    devices = (
        db.query(Inventory)
        .filter(Inventory.is_deleted == 0)
        .filter(Inventory.monitoring_type == "snmp")
        .all()
    )

    targets: List[Dict] = []

    for d in devices:
        if not d.ip_address:
            continue

        targets.append(
            {
                "targets": [d.ip_address],
                "labels": {
                    "inventory_id": _safe_str(d.id),
                    "hostname": _safe_str(d.hostname),
                    "asset_name": _safe_str(getattr(d, "asset_name", "")),
                    "ip_address": _safe_str(d.ip_address),
                    "device_type": _safe_str(d.device_type),
                    "location": _safe_str(getattr(d, "location", "")),
                    "room": _safe_str(getattr(d, "room", "")),
                    "building": _safe_str(getattr(d, "building", "")),
                    "monitoring_type": _safe_str(getattr(d, "monitoring_type", "snmp")),
                },
            }
        )

    return targets


def generate_node_targets(db: Session) -> int:
    _ensure_file_sd_dir()
    targets = _build_node_targets(db)
    _atomic_write_json(NODE_TARGET_FILE, targets)
    return len(targets)


def generate_snmp_targets(db: Session) -> int:
    _ensure_file_sd_dir()
    targets = _build_snmp_targets(db)
    _atomic_write_json(SNMP_TARGET_FILE, targets)
    return len(targets)


def sync_inventory_to_prometheus(db: Session) -> Dict[str, int]:
    """
    ใช้ชื่อ function นี้ให้ตรงกับ inventory.py

    ตอนนี้รองรับ:
    - server / node_exporter -> node_exporter_targets.json
    - monitoring_type=snmp -> snmp_targets.json
    """
    node_count = generate_node_targets(db)
    snmp_count = generate_snmp_targets(db)

    return {
        "node_exporter": node_count,
        "snmp": snmp_count,
    }
