import json
from datetime import datetime
from typing import Any, Dict, Optional, Literal, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models import ConfigProfile, ConfigHistory
from schemas import ConfigCollectionOut, ConfigEntryOut, ConfigUpdateIn
from services.audit import write_audit

router = APIRouter(prefix="/api/config", tags=["Config"])

AllowedConfigKey = Literal[
    "naming_policy",
    "approval_policy",
    "sla_policy",
    "agent_alert_policy",
    "ui_policy",
]

ALLOWED_CONFIG_KEYS = {
    "naming_policy",
    "approval_policy",
    "sla_policy",
    "agent_alert_policy",
    "ui_policy",
}


def _now_utc_naive() -> datetime:
    return datetime.utcnow()


def _get_actor_name(request: Request) -> str:
    return request.headers.get("X-Operator", "unknown")


def _get_actor_role(request: Request) -> str:
    return request.headers.get("X-Role", "VIEWER").upper()


def _require_admin(request: Request) -> None:
    role = _get_actor_role(request)
    if role != "ADMIN":
        raise HTTPException(status_code=403, detail="ADMIN role required")


def _default_configs() -> Dict[str, Dict[str, Any]]:
    return {
        "naming_policy": {
            "mode": "room_based",
            "prefix": "CPCOM",
            "room_digits": 4,
            "sequence_digits": 2,
            "separator": "-",
            "collision_strategy": "increment",
        },
        "approval_policy": {
            "require_room": True,
            "require_device_type": True,
            "allow_manual_asset_name": True,
            "auto_name_when_empty": True,
        },
        "sla_policy": {
            "default_target": 99.0,
            "room_override_enabled": False,
            "missing_data_treatment": "degrade",
            "incident_weighting": "standard",
        },
        "agent_alert_policy": {
            "heartbeat_timeout_sec": 120,
            "cpu_warning_pct": 85,
            "cpu_critical_pct": 95,
            "memory_warning_pct": 85,
            "memory_critical_pct": 95,
            "disk_warning_pct": 90,
            "disk_critical_pct": 95,
        },
        "ui_policy": {
            "inventory_auto_refresh_sec": 30,
            "discovery_auto_refresh_sec": 30,
            "pending_auto_refresh_sec": 20,
            "reports_default_days": 30,
        },
    }


def get_default_config(config_key: str) -> Dict[str, Any]:
    defaults = _default_configs()
    if config_key not in defaults:
        raise KeyError(config_key)
    return defaults[config_key]


def _parse_json_text(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    except Exception:
        return {}


def _serialize_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def _as_config_entry(
    *,
    config_key: str,
    config_json: Dict[str, Any],
    version: int,
    is_active: bool,
    source: str,
    updated_at: Optional[datetime],
    updated_by: Optional[str],
    updated_role: Optional[str],
) -> ConfigEntryOut:
    return ConfigEntryOut(
        config_key=cast(AllowedConfigKey, config_key),
        config_json=config_json,
        version=version,
        is_active=is_active,
        source=source,  # type: ignore[arg-type]
        updated_at=updated_at,
        updated_by=updated_by,
        updated_role=updated_role,
    )


def get_effective_config_entry(db: Session, config_key: str) -> ConfigEntryOut:
    if config_key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(status_code=404, detail="Unknown config key")

    row = (
        db.query(ConfigProfile)
        .filter(ConfigProfile.config_key == config_key)
        .first()
    )

    if row:
        return _as_config_entry(
            config_key=config_key,
            config_json=_parse_json_text(row.config_json),
            version=row.version or 1,
            is_active=bool(row.is_active),
            source="db",
            updated_at=row.updated_at,
            updated_by=row.updated_by,
            updated_role=row.updated_role,
        )

    return _as_config_entry(
        config_key=config_key,
        config_json=get_default_config(config_key),
        version=1,
        is_active=True,
        source="default",
        updated_at=None,
        updated_by=None,
        updated_role=None,
    )


@router.get("", response_model=ConfigCollectionOut)
def list_configs(db: Session = Depends(get_db)):
    items = [
        get_effective_config_entry(db, config_key)
        for config_key in sorted(ALLOWED_CONFIG_KEYS)
    ]
    return ConfigCollectionOut(items=items)


@router.get("/{config_key}", response_model=ConfigEntryOut)
def get_config(config_key: str, db: Session = Depends(get_db)):
    return get_effective_config_entry(db, config_key)


@router.put("/{config_key}", response_model=ConfigEntryOut)
def put_config(
    config_key: str,
    payload: ConfigUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
):
    if config_key not in ALLOWED_CONFIG_KEYS:
        raise HTTPException(status_code=404, detail="Unknown config key")

    _require_admin(request)

    actor_name = _get_actor_name(request)
    actor_role = _get_actor_role(request)

    existing = (
        db.query(ConfigProfile)
        .filter(ConfigProfile.config_key == config_key)
        .first()
    )

    previous_json: Optional[Dict[str, Any]] = None
    previous_version = 0

    if existing:
        previous_json = _parse_json_text(existing.config_json)
        previous_version = existing.version or 1

        existing.config_json = _serialize_json(payload.config_json)
        existing.version = previous_version + 1
        existing.is_active = 1
        existing.updated_at = _now_utc_naive()
        existing.updated_by = actor_name
        existing.updated_role = actor_role

        profile = existing
        action = "CONFIG_UPDATED"
    else:
        profile = ConfigProfile(
            config_key=config_key,
            config_json=_serialize_json(payload.config_json),
            version=1,
            is_active=1,
            updated_at=_now_utc_naive(),
            updated_by=actor_name,
            updated_role=actor_role,
        )
        db.add(profile)
        action = "CONFIG_CREATED"

    db.flush()

    history = ConfigHistory(
        config_key=config_key,
        old_json=_serialize_json(previous_json) if previous_json is not None else None,
        new_json=_serialize_json(payload.config_json),
        version=profile.version,
        change_reason=payload.reason,
        changed_at=_now_utc_naive(),
        changed_by=actor_name,
        changed_role=actor_role,
    )
    db.add(history)

    write_audit(
        db,
        request=request,
        action=action,
        entity_type="config",
        entity_id=config_key,
        actor_name=actor_name,
        actor_role=actor_role,
        meta={
            "config_key": config_key,
            "version": profile.version,
            "reason": payload.reason,
            "source": "config_center",
            "before": previous_json,
            "after": payload.config_json,
        },
    )

    db.commit()
    db.refresh(profile)

    return _as_config_entry(
        config_key=config_key,
        config_json=_parse_json_text(profile.config_json),
        version=profile.version or 1,
        is_active=bool(profile.is_active),
        source="db",
        updated_at=profile.updated_at,
        updated_by=profile.updated_by,
        updated_role=profile.updated_role,
    )
