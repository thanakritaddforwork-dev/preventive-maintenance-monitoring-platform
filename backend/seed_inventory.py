# seed_inventory.py
from database import SessionLocal
from models import Inventory

db = SessionLocal()

nodes = [
    {
        "hostname": "vm-base",
        "ip_address": "192.168.87.130",
        "device_type": "monitoring",
        "location": "DC-1",
        "status": "UP",
    },
    {
        "hostname": "vm-node-01",
        "ip_address": "192.168.87.131",
        "device_type": "vm",
        "location": "DC-1",
        "status": "UP",
    },
    {
        "hostname": "vm-node-02",
        "ip_address": "192.168.87.132",
        "device_type": "vm",
        "location": "DC-1",
        "status": "UP",
    },
    {
        "hostname": "vm-node-03",
        "ip_address": "192.168.87.133",
        "device_type": "vm",
        "location": "DC-1",
        "status": "UP",
    },
]

for n in nodes:
    exists = (
        db.query(Inventory)
        .filter(Inventory.ip_address == n["ip_address"])
        .first()
    )
    if not exists:
        db.add(Inventory(**n))

db.commit()
db.close()

print("Inventory seeded successfully")
