from fastapi import APIRouter, Query, Depends
from pysnmp.hlapi import *
from sqlalchemy.orm import Session

from database import get_db
from models import Inventory

router = APIRouter()

COMMUNITY = "public"
PORT_COUNT = 24


# =========================
# GET SNMP TABLE
# =========================
def get_snmp_data(ip, oid):
    result = {}

    try:
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(COMMUNITY, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False):

            if errorIndication:
                print("SNMP ERROR:", errorIndication)
                break

            elif errorStatus:
                print("SNMP ERROR:", errorStatus.prettyPrint())
                break

            else:
                for varBind in varBinds:
                    oid_str, value = varBind
                    index = int(str(oid_str).split('.')[-1])

                    try:
                        result[index] = int(value)
                    except:
                        result[index] = 2

    except Exception as e:
        print("SNMP FATAL ERROR:", e)

    return result


# =========================
# PORT STATUS
# =========================
def get_ports_raw(ip):
    oper_status = get_snmp_data(ip, "1.3.6.1.2.1.2.2.1.8")

    ports = []

    for i in range(1, PORT_COUNT + 1):
        status_raw = oper_status.get(i, 2)
        status = "UP" if status_raw == 1 else "DOWN"

        ports.append({
            "port": f"Gi1/0/{i}",
            "status": status,
            "index": i
        })

    return ports


# =========================
# MAC TABLE
# =========================
def get_mac_table(ip):
    mac_to_port = {}

    try:
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(COMMUNITY, mpModel=1),
                UdpTransportTarget((ip, 161), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.17.4.3.1.2')),
                lexicographicMode=False):

            if errorIndication or errorStatus:
                break

            for varBind in varBinds:
                oid, value = varBind

                mac = ".".join(oid.prettyPrint().split('.')[-6:])
                port = int(value)

                mac_to_port[port] = mac

    except Exception as e:
        print("MAC TABLE ERROR:", e)

    return mac_to_port


# =========================
# OLD API
# =========================
@router.get("/switch/ports")
def get_ports(ip: str = Query(...)):
    return get_ports_raw(ip)


# =========================
# NEW API (ports + device)
# =========================
@router.get("/switch/ports-with-device")
def get_ports_with_device(ip: str = Query(...), db: Session = Depends(get_db)):

    ports = get_ports_raw(ip)
    mac_table = get_mac_table(ip)

    result = []

    for p in ports:
        index = p["index"]
        mac = mac_table.get(index)

        device = None

        if mac:
            device = db.query(Inventory).filter(
                Inventory.mac_primary.like(f"%{mac}%")
            ).first()

        result.append({
            "port": p["port"],
            "status": p["status"],
            "device": {
                "id": device.id,
                "hostname": device.hostname,
                "ip": device.current_ip
            } if device else None
        })

    return result
