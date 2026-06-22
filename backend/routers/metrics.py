from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional, List
import os
import time
import requests

from database import get_db
from models import Inventory

router = APIRouter(prefix="/api/metrics", tags=["Metrics"])

# =========================
# Prometheus config
# =========================
PROM_URL = os.getenv("PROM_URL", "http://127.0.0.1:9090")

# =========================
# Prometheus helpers
# =========================
def prom_query(query: str, ts: Optional[float] = None) -> Dict[str, Any]:
    params = {"query": query}
    if ts is not None:
        params["time"] = ts
    r = requests.get(f"{PROM_URL}/api/v1/query", params=params, timeout=8)
    r.raise_for_status()
    return r.json()


def prom_query_range(query: str, start: float, end: float, step: str) -> Dict[str, Any]:
    params = {
        "query": query,
        "start": start,
        "end": end,
        "step": step,
    }
    r = requests.get(f"{PROM_URL}/api/v1/query_range", params=params, timeout=12)
    r.raise_for_status()
    return r.json()


def prom_value(resp: Dict[str, Any]) -> Optional[float]:
    """
    Extract single numeric value from Prometheus instant query
    """
    try:
        return float(resp["data"]["result"][0]["value"][1])
    except Exception:
        return None


def prom_series_points(resp: Dict[str, Any]) -> List[Dict[str, float]]:
    """
    Convert range query result -> [{ts, value}]
    """
    try:
        values = resp["data"]["result"][0]["values"]
        return [{"ts": int(ts), "value": float(v)} for ts, v in values]
    except Exception:
        return []


def series_stats(points: List[Dict[str, float]]) -> Dict[str, Optional[float]]:
    if not points:
        return {"avg": None, "max": None}
    vals = [p["value"] for p in points]
    return {
        "avg": sum(vals) / len(vals),
        "max": max(vals),
    }


# =========================
# API
# =========================
@router.get("/node/{inventory_id}/overview")
def node_overview(
    inventory_id: int,
    range_minutes: int = Query(60, ge=5, le=24 * 60),
    step: str = Query("30s"),
    db: Session = Depends(get_db),
):
    """
    Overview metrics for a node (by inventory_id)

    Returns:
    - current: up / cpu / mem / disk (number | null)
    - series: time-series for charts
    - summary: avg / max for DeepDive
    """
    inv = db.query(Inventory).filter(Inventory.id == inventory_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Inventory not found")

    inst = f"{inv.ip_address}:9100"

    now = time.time()
    start = now - range_minutes * 60

    try:
        # =========================
        # PromQL
        # =========================
        up_q = f'up{{instance="{inst}"}}'

        cpu_q = (
            f'(1 - avg(rate(node_cpu_seconds_total{{mode="idle",instance="{inst}"}}[5m]))) * 100'
        )

        mem_q = (
            f'(1 - (node_memory_MemAvailable_bytes{{instance="{inst}"}} '
            f'/ node_memory_MemTotal_bytes{{instance="{inst}"}})) * 100'
        )

        disk_q = (
            f'(1 - (node_filesystem_free_bytes{{mountpoint="/",fstype!~"tmpfs|overlay",instance="{inst}"}} '
            f'/ node_filesystem_size_bytes{{mountpoint="/",fstype!~"tmpfs|overlay",instance="{inst}"}})) * 100'
        )

        # =========================
        # Instant values
        # =========================
        up = prom_value(prom_query(up_q))
        cpu = prom_value(prom_query(cpu_q))
        mem = prom_value(prom_query(mem_q))
        disk = prom_value(prom_query(disk_q))

        # =========================
        # Range series
        # =========================
        cpu_points = prom_series_points(
            prom_query_range(cpu_q, start, now, step)
        )
        mem_points = prom_series_points(
            prom_query_range(mem_q, start, now, step)
        )
        disk_points = prom_series_points(
            prom_query_range(disk_q, start, now, step)
        )

        return {
            "inventory": {
                "id": inv.id,
                "hostname": inv.hostname,
                "ip_address": inv.ip_address,
                "location": getattr(inv, "location", None),
                "status": inv.status,
            },
            "prometheus": {
                "base": PROM_URL,
                "instance": inst,
            },
            "current": {
                "up": up,
                "cpu_pct": cpu,
                "mem_pct": mem,
                "disk_pct": disk,
            },
            "series": {
                "cpu_pct": cpu_points,
                "mem_pct": mem_points,
                "disk_pct": disk_points,
            },
            "summary": {
                "cpu": series_stats(cpu_points),
                "mem": series_stats(mem_points),
                "disk": series_stats(disk_points),
            },
        }

    except requests.RequestException as e:
        raise HTTPException(
            status_code=502,
            detail=f"Prometheus request failed: {e}",
        )
