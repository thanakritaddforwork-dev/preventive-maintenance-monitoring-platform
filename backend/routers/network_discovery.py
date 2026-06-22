from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from database import get_db
from utils.network_scan import scan_network

router = APIRouter(prefix="/api/network", tags=["network-discovery"])


@router.get("/scan")
def network_scan_route(subnet: str = Query(default="10.198.210.0/24")):
    result = scan_network(subnet=subnet)
    return {
        "count": len(result["devices"]),
        "devices": result["devices"],
        "ok": result["ok"],
        "returncode": result["returncode"],
        "stderr": result["stderr"],
    }


@router.post("/sync")
def network_sync_route(
    subnet: str = Query(default="10.198.210.0/24"),
    room: str = Query(default="DISCOVERY"),
    db: Session = Depends(get_db),
):
    result = scan_network(subnet=subnet)

    if not result["ok"]:
        return {
            "ok": False,
            "message": "scan failed",
            "returncode": result["returncode"],
            "stderr": result["stderr"],
            "count": 0,
            "inserted": 0,
            "existing": 0,
            "devices": [],
        }

    inserted = 0
    existing = 0
    synced_devices = []

    for dev in result["devices"]:
        ip = dev["ip"]
        mac = dev["mac"]
        vendor = dev["vendor"]

        row = db.execute(
            text(
                """
                SELECT id, hostname, current_ip, mac_primary
                FROM inventory
                WHERE mac_primary = :mac
                   OR current_ip = :ip
                LIMIT 1
                """
            ),
            {"mac": mac, "ip": ip},
        ).fetchone()

        if row:
            db.execute(
                text(
                    """
                    UPDATE inventory
                    SET current_ip = :ip,
                        mac_primary = COALESCE(mac_primary, :mac),
                        manufacturer = COALESCE(manufacturer, :vendor),
                        room = COALESCE(room, :room),
                        is_discovered = 1,
                        identity_source = COALESCE(identity_source, 'network_scan')
                    WHERE id = :id
                    """
                ),
                {
                    "id": row[0],
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "room": room,
                },
            )
            existing += 1
            synced_devices.append(
                {
                    "id": row[0],
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "action": "updated",
                }
            )
        else:
            hostname = f"DISCOVERED-{ip.replace('.', '-')}"
            db.execute(
                text(
                    """
                    INSERT INTO inventory (
                        hostname,
                        ip_address,
                        current_ip,
                        device_type,
                        monitoring_type,
                        location,
                        room,
                        os_type,
                        mac_primary,
                        manufacturer,
                        is_discovered,
                        identity_source
                    )
                    VALUES (
                        :hostname,
                        :ip,
                        :ip,
                        'unknown',
                        'discovered',
                        'Network Discovery',
                        :room,
                        'unknown',
                        :mac,
                        :vendor,
                        1,
                        'network_scan'
                    )
                    """
                ),
                {
                    "hostname": hostname,
                    "ip": ip,
                    "room": room,
                    "mac": mac,
                    "vendor": vendor,
                },
            )

            new_id = db.execute(text("SELECT last_insert_rowid()")).scalar()
            inserted += 1
            synced_devices.append(
                {
                    "id": new_id,
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "action": "inserted",
                }
            )

    db.commit()

    return {
        "ok": True,
        "message": "network sync completed",
        "count": len(result["devices"]),
        "inserted": inserted,
        "existing": existing,
        "devices": synced_devices,
    }
