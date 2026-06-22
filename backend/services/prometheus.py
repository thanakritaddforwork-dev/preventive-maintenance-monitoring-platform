import os
import requests

PROM_BASE = os.getenv("PROMETHEUS_BASE", "http://127.0.0.1:9090")

def is_alert_firing(instance: str) -> bool:
    """
    Check if alert is still firing for instance
    Fail-safe: ถ้า error → ถือว่ายัง firing (ไม่ auto resolve)
    """
    try:
        r = requests.get(
            f"{PROM_BASE}/api/v1/alerts",
            timeout=3,
        )
        r.raise_for_status()
        data = r.json()

        alerts = data.get("data", {}).get("alerts", [])
        for a in alerts:
            labels = a.get("labels", {})
            if labels.get("instance") == instance and a.get("state") == "firing":
                return True

        return False

    except Exception as e:
        # ❗ fail-safe: ถ้า prom ล่ม อย่า auto resolve
        return True
