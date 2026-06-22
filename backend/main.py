import os
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

import models
from database import engine

# =========================
# Routers Import (FIX)
# =========================
from routers.audit import router as audit_router
from routers.inventory import router as inventory_router
from routers.tickets import router as tickets_router
from routers.ticket_maintenance import router as ticket_maintenance_router
from routers.metrics import router as metrics_router
from routers.alerts import router as alerts_router
from routers import inventory_rooms
from routers.rooms_kpi import router as rooms_kpi_router
from routers.topology import router as topology_router
from routers import sla
from routers.agent import router as agent_router
from routers.network_discovery import router as network_discovery_router
from routers.config import router as config_router
from routers.device_alerts import router as device_alerts_router
from routers.monitor_links import router as monitor_links_router
from routers.racks import router as racks_router

# 🔥 FIX สำคัญ (ตัวนี้ต้องแก้แบบนี้เท่านั้น)
from routers.snmp_ports import router as snmp_ports_router

# config rooms
from routers import config_rooms
from routers.network_scan import router as network_scan_router
from routers.port_audit import router as port_audit_router
from routers.port_audits import router as port_audits_router

# =========================
# ENV
# =========================
ENV = os.getenv("APP_ENV") or os.getenv("ENV", "development")

# =========================
# Logging
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)

logger = logging.getLogger("pm-backend")
logger.info(f"Starting PM Backend in ENV={ENV}")

# =========================
# DB INIT
# =========================
logger.info("Creating database tables if not exist...")
models.Base.metadata.create_all(bind=engine)

# =========================
# App
# =========================
app = FastAPI(title="PM Backend API")

# =========================
# CORS
# =========================
cors_env = os.getenv("CORS_ORIGINS", "")
env_origins = [x.strip() for x in cors_env.split(",") if x.strip()]

origins = list(
    dict.fromkeys(
        env_origins
        + [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://10.198.200.97:3000",
            "http://10.198.210.97:3000",
            "http://localhost:4000",
            "http://127.0.0.1:4000",
            "http://10.198.200.97:4000",
            "http://10.198.210.97:4000",
        ]
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Health Check
# =========================
@app.get("/healthz")
@app.get("/api/health")
def healthz():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        logger.error(f"DB health check failed: {e}")
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "env": ENV,
        "database": db_ok,
    }


@app.get("/api/health")
def api_health():
    return healthz()


# =========================
# Routers
# =========================
app.include_router(audit_router)
app.include_router(inventory_router)
app.include_router(tickets_router)
app.include_router(ticket_maintenance_router)
app.include_router(metrics_router)
app.include_router(alerts_router)
app.include_router(inventory_rooms.router)
app.include_router(rooms_kpi_router)
app.include_router(topology_router)
app.include_router(sla.router)
app.include_router(agent_router)
app.include_router(network_discovery_router)
app.include_router(config_router)
app.include_router(device_alerts_router)
app.include_router(monitor_links_router)

# config rooms
app.include_router(config_rooms.router)

# 🔥 SNMP PORTS (ตัวสำคัญ)
app.include_router(snmp_ports_router, prefix="/api")
app.include_router(racks_router, prefix="/api")
app.include_router(network_scan_router, prefix="/api")
app.include_router(port_audit_router, prefix="/api")
app.include_router(port_audits_router)

