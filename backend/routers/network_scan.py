from fastapi import APIRouter, Query
import subprocess
import re

router = APIRouter(prefix="/network-scan", tags=["network-scan"])


@router.get("/subnet")
def scan_subnet(base_ip: str = Query(...)):
    """
    ใช้ nmap scan subnet เช่น 10.198.200.0/24
    """

    try:
        subnet = f"{base_ip}.0/24"

        result = subprocess.run(
            ["nmap", "-sn", subnet],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout

        # 🔥 ดึง IP จาก output
        ips = re.findall(r"Nmap scan report for ([0-9\.]+)", output)

        devices = [
            {"ip": ip, "status": "UP"}
            for ip in ips
        ]

        return {
            "ok": True,
            "devices": devices
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e)
        }
