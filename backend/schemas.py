from typing import Optional, List, Literal, Any, Dict
from datetime import datetime, date

from pydantic import BaseModel, Field
from pydantic import ConfigDict


# =========================================================
# Tickets
# =========================================================

class TicketCommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ticket_id: int
    message: str
    created_at: Optional[datetime] = None


class TicketActionIn(BaseModel):
    action: Literal["ack", "resolve"] | None = None
    owner: Optional[str] = None
    comment: Optional[str] = None


class TicketMaintenanceLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ticket_id: int
    maintenance_ticket_id: Optional[int] = None
    maintenance_url: Optional[str] = None
    maintenance_status: str
    maintenance_api_base: Optional[str] = None
    error_message: Optional[str] = None
    sent_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    sent_by: Optional[str] = None
    sent_role: Optional[str] = None


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_name: str
    instance: str

    severity: str = Field(default="unknown")
    status: str

    resolve_source: Optional[str] = None
    owner: Optional[str] = None
    acknowledged_at: Optional[datetime] = None

    inventory_id: Optional[int] = None
    created_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    comments: List[TicketCommentOut] = []


class TicketSLAOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_name: str
    instance: str
    status: str
    duration_seconds: Optional[int] = None


# =========================================================
# KPI
# =========================================================

class TicketKPITrendOut(BaseModel):
    date: date
    total_resolved: int
    auto_resolved: int
    manual_resolved: int
    auto_resolve_pct: float
    mttr_auto_seconds: Optional[int]
    mttr_manual_seconds: Optional[int]


# =========================================================
# Inventory
# =========================================================

class InventoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    asset_name: Optional[str] = None
    ip_address: str
    current_ip: Optional[str] = None

    device_type: Optional[str] = None
    location: Optional[str] = None
    room: Optional[str] = None
    building: Optional[str] = None

    monitoring_type: Optional[str] = None
    scrape_port: Optional[int] = None

    os_type: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = None

    device_uid: Optional[str] = None
    machine_guid: Optional[str] = None
    bios_serial: Optional[str] = None
    motherboard_serial: Optional[str] = None
    mac_primary: Optional[str] = None

    manufacturer: Optional[str] = None
    model: Optional[str] = None
    cpu_model: Optional[str] = None
    ram_bytes: Optional[int] = None

    last_seen_at: Optional[datetime] = None
    last_boot_time: Optional[datetime] = None
    identity_source: Optional[str] = None
    is_discovered: Optional[int] = None

    status: str
    created_at: Optional[datetime] = None

    is_deleted: int = 0
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None


class InventorySummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    asset_name: Optional[str] = None
    ip_address: str
    current_ip: Optional[str] = None

    device_type: Optional[str] = None
    location: Optional[str] = None
    room: Optional[str] = None
    building: Optional[str] = None

    monitoring_type: Optional[str] = None
    scrape_port: Optional[int] = None

    os_type: Optional[str] = None
    device_uid: Optional[str] = None

    status: str
    open_tickets: int = 0
    last_ticket: Optional[TicketOut] = None

    is_deleted: int = 0
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None


class InventoryCreate(BaseModel):
    hostname: str
    asset_name: Optional[str] = None
    ip_address: str
    device_type: Optional[str] = None
    location: Optional[str] = None

    monitoring_type: Optional[str] = None
    scrape_port: Optional[int] = None


class InventoryMetadataUpdate(BaseModel):
    asset_name: Optional[str] = None
    room: Optional[str] = None
    building: Optional[str] = None
    location: Optional[str] = None
    device_type: Optional[str] = None
    monitoring_type: Optional[str] = None
    scrape_port: Optional[int] = None


class InventoryRestoreIn(BaseModel):
    restore: bool = True


# =========================================================
# Config Center
# =========================================================

ConfigKey = Literal[
    "naming_policy",
    "approval_policy",
    "sla_policy",
    "agent_alert_policy",
    "ui_policy",
]


class ConfigEntryOut(BaseModel):
    config_key: ConfigKey
    config_json: Dict[str, Any]
    version: int
    is_active: bool
    source: Literal["db", "default"]
    updated_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    updated_role: Optional[str] = None


class ConfigCollectionOut(BaseModel):
    items: List[ConfigEntryOut]


class ConfigUpdateIn(BaseModel):
    config_json: Dict[str, Any]
    reason: Optional[str] = None
