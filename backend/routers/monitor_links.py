from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db

router = APIRouter(prefix="/api/monitor-links", tags=["monitor-links"])


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s or None


def _normalize_name(value: Optional[str]) -> Optional[str]:
    s = _clean(value)
    if not s:
        return None
    s = s.upper()
    s = s.replace("_", "-")
    s = re.sub(r"\s+", "", s)
    return s or None


def _name_variants(value: Optional[str]) -> List[str]:
    base = _normalize_name(value)
    if not base:
        return []

    variants: Set[str] = {base}

    m = re.match(r"^([A-Z]+)(\d{4})-(\d{1,3})$", base)
    if m:
        prefix = m.group(1)
        room_digits = m.group(2)
        seq_raw = m.group(3)

        try:
            seq_int = int(seq_raw)
            variants.add(f"{prefix}{room_digits}-{seq_int}")
            variants.add(f"{prefix}{room_digits}-{seq_int:02d}")
            variants.add(f"{prefix}{room_digits}-{seq_int:03d}")
        except Exception:
            pass

    return [v for v in variants if v]


def _monitoring_ui_base() -> str:
    return (os.getenv("MONITORING_UI_BASE") or "http://10.198.210.97:3000").rstrip("/")


def _inventory_columns(db: Session) -> set[str]:
    rows = db.execute(text("PRAGMA table_info(inventory)")).mappings().all()
    return {str(r["name"]) for r in rows}


def _fetch_inventory_rows(db: Session) -> List[Dict[str, Any]]:
    cols = _inventory_columns(db)

    wanted = [
        "id",
        "hostname",
        "asset_name",
        "device_type",
        "monitoring_type",
        "os_type",
        "device_uid",
        "current_ip",
    ]
    actual = [c for c in wanted if c in cols]

    if "id" not in actual:
        raise HTTPException(status_code=500, detail="inventory table missing id column")

    sql = f"""
        SELECT {", ".join(actual)}
        FROM inventory
        ORDER BY id ASC
    """

    return [dict(r) for r in db.execute(text(sql)).mappings().all()]


def _target_kind(row: Dict[str, Any]) -> str:
    device_type = str(row.get("device_type") or "").strip().lower()
    monitoring_type = str(row.get("monitoring_type") or "").strip().lower()
    os_type = str(row.get("os_type") or "").strip().lower()

    if (
        monitoring_type == "agent"
        or device_type in ("pc", "windows_pc")
        or os_type == "windows"
    ):
        return "discovery"

    return "node"


def _score_row(
    row: Dict[str, Any],
    asset_name_variants: List[str],
    hostname_variants: List[str],
    device_uid: Optional[str],
    current_ip: Optional[str],
) -> int:
    row_asset = _normalize_name(row.get("asset_name"))
    row_host = _normalize_name(row.get("hostname"))
    row_uid = _clean(row.get("device_uid"))
    row_ip = _clean(row.get("current_ip"))

    score = 0

    if device_uid and row_uid and row_uid == device_uid:
        score = max(score, 100)

    if current_ip and row_ip and row_ip == current_ip:
        score = max(score, 80)

    if row_asset and row_asset in asset_name_variants:
        score = max(score, 90)

    if row_host and row_host in hostname_variants:
        score = max(score, 70)

    # fallback: บางเคส maintenance ส่ง Device Name มา แต่ monitoring เก็บใน hostname
    if row_host and row_host in asset_name_variants:
        score = max(score, 65)

    # fallback: บางเคส maintenance ส่ง hostname มา แต่ monitoring เก็บใน asset_name
    if row_asset and row_asset in hostname_variants:
        score = max(score, 60)

    return score


@router.get("/resolve")
def resolve_monitoring_link(
    asset_name: Optional[str] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    device_uid: Optional[str] = Query(default=None),
    current_ip: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    asset_name_variants = _name_variants(asset_name)
    hostname_variants = _name_variants(hostname)

    clean_uid = _clean(device_uid)
    clean_ip = _clean(current_ip)

    if not asset_name_variants and not hostname_variants and not clean_uid and not clean_ip:
        raise HTTPException(
            status_code=400,
            detail="At least one of asset_name, hostname, device_uid, current_ip is required",
        )

    rows = _fetch_inventory_rows(db)

    best_row: Optional[Dict[str, Any]] = None
    best_score = -1

    for row in rows:
        score = _score_row(
            row=row,
            asset_name_variants=asset_name_variants,
            hostname_variants=hostname_variants,
            device_uid=clean_uid,
            current_ip=clean_ip,
        )
        if score > best_score:
            best_score = score
            best_row = row

    if not best_row or best_score <= 0:
        raise HTTPException(
            status_code=404,
            detail={
                "message": "Monitoring device not found",
                "searched": {
                    "asset_name": asset_name,
                    "hostname": hostname,
                    "device_uid": clean_uid,
                    "current_ip": clean_ip,
                },
            },
        )

    target_kind = _target_kind(best_row)
    target_id = int(best_row["id"])
    target_path = f"/discovery/{target_id}" if target_kind == "discovery" else f"/nodes/{target_id}"

    matched_by = "unknown"
    normalized_asset = _normalize_name(best_row.get("asset_name"))
    normalized_host = _normalize_name(best_row.get("hostname"))

    if clean_uid and _clean(best_row.get("device_uid")) == clean_uid:
        matched_by = "device_uid"
    elif clean_ip and _clean(best_row.get("current_ip")) == clean_ip:
        matched_by = "current_ip"
    elif normalized_asset and normalized_asset in asset_name_variants:
        matched_by = "asset_name"
    elif normalized_host and normalized_host in hostname_variants:
        matched_by = "hostname"
    elif normalized_host and normalized_host in asset_name_variants:
        matched_by = "hostname_from_asset_name"
    elif normalized_asset and normalized_asset in hostname_variants:
        matched_by = "asset_name_from_hostname"

    return {
        "found": True,
        "target_kind": target_kind,
        "target_id": target_id,
        "target_path": target_path,
        "monitoring_url": f"{_monitoring_ui_base()}{target_path}",
        "matched_by": matched_by,
        "matched_value": {
            "asset_name": best_row.get("asset_name"),
            "hostname": best_row.get("hostname"),
            "device_uid": best_row.get("device_uid"),
            "current_ip": best_row.get("current_ip"),
        },
        "searched": {
            "asset_name": asset_name,
            "hostname": hostname,
            "device_uid": clean_uid,
            "current_ip": clean_ip,
            "asset_name_variants": asset_name_variants,
            "hostname_variants": hostname_variants,
        },
    }
