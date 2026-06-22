import re
import subprocess
from typing import Any

ARP_SCAN_BIN = "/usr/sbin/arp-scan"
SUDO_BIN = "/usr/bin/sudo"


def scan_network(subnet: str = "10.198.210.0/24") -> dict[str, Any]:
    cmd = [SUDO_BIN, "-n", ARP_SCAN_BIN, subnet]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    devices: list[dict[str, str]] = []

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()

        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f:]{17})\s+(.+)$",
            line,
        )
        if match:
            devices.append(
                {
                    "ip": match.group(1),
                    "mac": match.group(2).lower(),
                    "vendor": match.group(3).strip(),
                }
            )

    return {
        "ok": result.returncode == 0,
        "returncode": result.returncode,
        "stderr": result.stderr.strip(),
        "devices": devices,
    }
