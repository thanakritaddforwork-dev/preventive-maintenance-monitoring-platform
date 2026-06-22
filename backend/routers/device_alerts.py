from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db

router = APIRouter(prefix="/api/device-alerts", tags=["device-alerts"])


class DeviceAlertListItemOut(BaseModel):
    id: int
    inventory_id: int
    hostname: Optional[str] = None
    asset_name: Optional[str] = None
    room: Optional[str] = None
    current_ip: Optional[str] = None

    alert_key: str
    severity: str
    message: str
    status: str
    created_at: str
    resolved_at: Optional[str] = None
    meta_json: Optional[str] = None


@router.get("", response_model=List[DeviceAlertListItemOut])
def list_device_alerts(
    status: Optional[str] = Query(default=None, description="OPEN | RESOLVED"),
    severity: Optional[str] = Query(default=None, description="INFO | WARNING | CRITICAL | HIGH"),
    inventory_id: Optional[int] = Query(default=None),
    q: Optional[str] = Query(default=None, description="search hostname / asset_name / room / alert_key / message"),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    where_parts = []
    params = {"limit": limit}

    if status:
        where_parts.append("UPPER(da.status) = :status")
        params["status"] = str(status).strip().upper()

    if severity:
        where_parts.append("UPPER(da.severity) = :severity")
        params["severity"] = str(severity).strip().upper()

    if inventory_id is not None:
        where_parts.append("da.inventory_id = :inventory_id")
        params["inventory_id"] = inventory_id

    q_norm = (q or "").strip()
    if q_norm:
        where_parts.append(
            """
            (
                LOWER(COALESCE(i.hostname, '')) LIKE :q
                OR LOWER(COALESCE(i.asset_name, '')) LIKE :q
                OR LOWER(COALESCE(i.room, '')) LIKE :q
                OR LOWER(COALESCE(da.alert_key, '')) LIKE :q
                OR LOWER(COALESCE(da.message, '')) LIKE :q
            )
            """
        )
        params["q"] = f"%{q_norm.lower()}%"

    where_sql = ""
    if where_parts:
        where_sql = "WHERE " + " AND ".join(where_parts)

    rows = db.execute(
        text(
            f"""
            SELECT
                da.id,
                da.inventory_id,
                i.hostname,
                i.asset_name,
                i.room,
                i.current_ip,
                da.alert_key,
                da.severity,
                da.message,
                da.status,
                da.created_at,
                da.resolved_at,
                da.meta_json
            FROM device_alerts da
            LEFT JOIN inventory i
              ON i.id = da.inventory_id
            {where_sql}
            ORDER BY
                CASE WHEN UPPER(da.status) = 'OPEN' THEN 0 ELSE 1 END,
                CASE
                    WHEN UPPER(da.severity) = 'CRITICAL' THEN 0
                    WHEN UPPER(da.severity) = 'HIGH' THEN 1
                    WHEN UPPER(da.severity) = 'WARNING' THEN 2
                    ELSE 3
                END,
                da.created_at DESC,
                da.id DESC
            LIMIT :limit
            """
        ),
        params,
    ).mappings().all()

    return [
        DeviceAlertListItemOut(
            id=int(row["id"]),
            inventory_id=int(row["inventory_id"]),
            hostname=row["hostname"],
            asset_name=row["asset_name"],
            room=row["room"],
            current_ip=row["current_ip"],
            alert_key=row["alert_key"],
            severity=row["severity"],
            message=row["message"],
            status=row["status"],
            created_at=str(row["created_at"]),
            resolved_at=str(row["resolved_at"]) if row["resolved_at"] is not None else None,
            meta_json=row["meta_json"],
        )
        for row in rows
    ]
