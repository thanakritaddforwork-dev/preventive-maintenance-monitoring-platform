from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base


# =========================
# INVENTORY
# =========================
class Inventory(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True)
    asset_name = Column(Text, nullable=True, index=True)
    ip_address = Column(String, unique=True, index=True)

    device_type = Column(String, nullable=True)
    location = Column(String, nullable=True)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

    monitoring_type = Column(Text, nullable=True)
    scrape_port = Column(Integer, nullable=True)

    device_uid = Column(Text, nullable=True)
    current_ip = Column(Text, nullable=True)

    os_type = Column(Text, nullable=True)
    os_version = Column(Text, nullable=True)
    agent_version = Column(Text, nullable=True)

    machine_guid = Column(Text, nullable=True)
    bios_serial = Column(Text, nullable=True)
    motherboard_serial = Column(Text, nullable=True)
    mac_primary = Column(Text, nullable=True)

    manufacturer = Column(Text, nullable=True)
    model = Column(Text, nullable=True)
    cpu_model = Column(Text, nullable=True)
    ram_bytes = Column(BigInteger, nullable=True)

    room = Column(Text, nullable=True, index=True)
    building = Column(Text, nullable=True)

    last_seen_at = Column(DateTime, nullable=True)
    last_boot_time = Column(DateTime, nullable=True)

    identity_source = Column(Text, nullable=True)
    is_discovered = Column(Integer, default=0, nullable=True, index=True)

    is_deleted = Column(Integer, default=0, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Text, nullable=True)

    tickets = relationship("Ticket", back_populates="inventory")


# =========================
# ROOMS
# =========================
class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    racks = relationship("Rack", back_populates="room")


# =========================
# RACKS (🔥 FIX แล้ว)
# =========================
class Rack(Base):
    __tablename__ = "racks"

    id = Column(Integer, primary_key=True, index=True)
    room_name = Column(String, ForeignKey("rooms.name"), index=True)
    rack_number = Column(Integer, index=True)

    # 🔥 ตัวสำคัญ (เก็บ IP ต่อ rack)
    switch_ip = Column(String, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    room = relationship("Room", back_populates="racks")


# =========================
# TICKETS
# =========================
class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)

    alert_name = Column(String)
    instance = Column(String)
    severity = Column(String)

    fingerprint = Column(String, index=True, nullable=True)
    starts_at = Column(DateTime, nullable=True)
    ends_at = Column(DateTime, nullable=True)

    status = Column(String, default="OPEN")
    resolve_source = Column(String, nullable=True)

    owner = Column(String, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    inventory_id = Column(Integer, ForeignKey("inventory.id"))
    inventory = relationship("Inventory", back_populates="tickets")

    comments = relationship(
        "TicketComment",
        back_populates="ticket",
        cascade="all, delete-orphan"
    )

    maintenance_link = relationship(
        "TicketMaintenanceLink",
        back_populates="ticket",
        uselist=False,
        cascade="all, delete-orphan",
    )


class TicketComment(Base):
    __tablename__ = "ticket_comments"

    id = Column(Integer, primary_key=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"))

    author = Column(String)
    message = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    ticket = relationship("Ticket", back_populates="comments")


class TicketMaintenanceLink(Base):
    __tablename__ = "ticket_maintenance_links"

    id = Column(Integer, primary_key=True, index=True)
    ticket_id = Column(Integer, ForeignKey("tickets.id"), unique=True, index=True, nullable=False)

    maintenance_ticket_id = Column(Integer, nullable=True, index=True)
    maintenance_url = Column(String, nullable=True)
    maintenance_status = Column(String, default="PENDING", nullable=False, index=True)

    maintenance_api_base = Column(String, nullable=True)
    request_payload_json = Column(Text, nullable=True)
    response_payload_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    sent_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    sent_by = Column(String, nullable=True)
    sent_role = Column(String, nullable=True)

    ticket = relationship("Ticket", back_populates="maintenance_link")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    action = Column(String, index=True)
    entity_type = Column(String, index=True)
    entity_id = Column(String, nullable=True, index=True)

    actor_name = Column(String, index=True)
    actor_role = Column(String, index=True)

    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    meta_json = Column(String, nullable=True)


class SLASnapshot(Base):
    __tablename__ = "sla_snapshots"

    id = Column(Integer, primary_key=True)
    inventory_id = Column(Integer, index=True)
    uptime_percent = Column(Float)
    period_days = Column(Integer, default=30)
    created_at = Column(DateTime, default=datetime.utcnow)


class ConfigProfile(Base):
    __tablename__ = "config_profiles"

    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String, unique=True, index=True, nullable=False)
    config_json = Column(Text, nullable=False)
    version = Column(Integer, default=1, nullable=False)
    is_active = Column(Integer, default=1, nullable=False)

    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_by = Column(String, nullable=True)
    updated_role = Column(String, nullable=True)


class ConfigHistory(Base):
    __tablename__ = "config_history"

    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String, index=True, nullable=False)

    old_json = Column(Text, nullable=True)
    new_json = Column(Text, nullable=False)

    version = Column(Integer, nullable=False)
    change_reason = Column(String, nullable=True)

    changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    changed_by = Column(String, nullable=True)
    changed_role = Column(String, nullable=True)

# =========================
# PORT AUDIT (🔥 NEW)
# =========================
class PortAudit(Base):
    __tablename__ = "port_audits"

    id = Column(Integer, primary_key=True, index=True)

    room = Column(String, index=True)
    rack = Column(Integer, index=True)
    switch_ip = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    items = relationship("PortAuditItem", back_populates="audit")


class PortAuditItem(Base):
    __tablename__ = "port_audit_items"

    id = Column(Integer, primary_key=True)

    audit_id = Column(Integer, ForeignKey("port_audits.id"))
    port = Column(String)
    status = Column(String)

    audit = relationship("PortAudit", back_populates="items")

