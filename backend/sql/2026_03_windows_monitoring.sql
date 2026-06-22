PRAGMA foreign_keys = OFF;
BEGIN TRANSACTION;

ALTER TABLE inventory ADD COLUMN device_uid TEXT;
ALTER TABLE inventory ADD COLUMN current_ip TEXT;
ALTER TABLE inventory ADD COLUMN os_type TEXT;
ALTER TABLE inventory ADD COLUMN os_version TEXT;
ALTER TABLE inventory ADD COLUMN agent_version TEXT;
ALTER TABLE inventory ADD COLUMN machine_guid TEXT;
ALTER TABLE inventory ADD COLUMN bios_serial TEXT;
ALTER TABLE inventory ADD COLUMN motherboard_serial TEXT;
ALTER TABLE inventory ADD COLUMN mac_primary TEXT;
ALTER TABLE inventory ADD COLUMN manufacturer TEXT;
ALTER TABLE inventory ADD COLUMN model TEXT;
ALTER TABLE inventory ADD COLUMN cpu_model TEXT;
ALTER TABLE inventory ADD COLUMN ram_bytes BIGINT;
ALTER TABLE inventory ADD COLUMN room TEXT;
ALTER TABLE inventory ADD COLUMN last_seen_at DATETIME;
ALTER TABLE inventory ADD COLUMN last_boot_time DATETIME;
ALTER TABLE inventory ADD COLUMN identity_source TEXT;
ALTER TABLE inventory ADD COLUMN is_discovered INTEGER DEFAULT 0;

UPDATE inventory
SET current_ip = ip_address
WHERE current_ip IS NULL AND ip_address IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_inventory_device_uid
ON inventory(device_uid)
WHERE device_uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_inventory_machine_guid ON inventory(machine_guid);
CREATE INDEX IF NOT EXISTS idx_inventory_bios_serial ON inventory(bios_serial);
CREATE INDEX IF NOT EXISTS idx_inventory_mac_primary ON inventory(mac_primary);
CREATE INDEX IF NOT EXISTS idx_inventory_current_ip ON inventory(current_ip);
CREATE INDEX IF NOT EXISTS idx_inventory_last_seen_at ON inventory(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_inventory_room ON inventory(room);
CREATE INDEX IF NOT EXISTS idx_inventory_is_discovered ON inventory(is_discovered);

CREATE TABLE IF NOT EXISTS inventory_ip_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inventory_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen_at DATETIME NOT NULL,
    last_seen_at DATETIME NOT NULL,
    UNIQUE(inventory_id, ip_address),
    FOREIGN KEY(inventory_id) REFERENCES inventory(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inventory_ip_history_inventory_id
ON inventory_ip_history(inventory_id);

CREATE INDEX IF NOT EXISTS idx_inventory_ip_history_ip_address
ON inventory_ip_history(ip_address);

CREATE TABLE IF NOT EXISTS inventory_heartbeats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inventory_id INTEGER NOT NULL,
    cpu_pct REAL,
    mem_pct REAL,
    disk_pct REAL,
    boot_time DATETIME,
    collected_at DATETIME NOT NULL,
    FOREIGN KEY(inventory_id) REFERENCES inventory(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_inventory_heartbeats_inventory_id
ON inventory_heartbeats(inventory_id);

CREATE INDEX IF NOT EXISTS idx_inventory_heartbeats_collected_at
ON inventory_heartbeats(collected_at);

CREATE TABLE IF NOT EXISTS device_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    inventory_id INTEGER NOT NULL,
    alert_key TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    meta_json TEXT,
    created_at DATETIME NOT NULL,
    resolved_at DATETIME,
    FOREIGN KEY(inventory_id) REFERENCES inventory(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_device_alerts_inventory_id
ON device_alerts(inventory_id);

CREATE INDEX IF NOT EXISTS idx_device_alerts_status
ON device_alerts(status);

CREATE INDEX IF NOT EXISTS idx_device_alerts_alert_key
ON device_alerts(alert_key);

COMMIT;
PRAGMA foreign_keys = ON;
