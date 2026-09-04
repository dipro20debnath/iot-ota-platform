"""
Devices API Router
===================

FastAPI router exposing REST endpoints for device management:

* **Register** — enrol a new IoT device on the platform.
* **List** — query all devices with optional status / type filters.
* **Detail** — retrieve a single device by ID.
* **Heartbeat** — accept device heartbeat payloads.
* **Groups** — create and list device groups, assign devices to groups.
* **Fleet stats** — aggregate statistics across the fleet.
* **Decommission** — revoke and retire a device.

All endpoints are mounted under the ``/api/devices`` prefix.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.ota.device_registry import DeviceRegistry

logger = logging.getLogger(__name__)

# ── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"],
)

# ── Module-Level Singleton ───────────────────────────────────────────────────

_registry = DeviceRegistry()


# ── Request / Response Schemas ───────────────────────────────────────────────


class RegisterDeviceRequest(BaseModel):
    """Payload for registering a new device."""

    name: str = Field(..., min_length=1, max_length=128, description="Device name.")
    device_type: str = Field(..., min_length=1, max_length=64, description="Hardware type.")
    firmware_version: Optional[str] = Field(default=None, max_length=32, description="Installed firmware version.")
    ip_address: Optional[str] = Field(default=None, description="IP address of the device.")
    group_name: Optional[str] = Field(default=None, description="Group to assign the device to.")
    metadata: Optional[dict[str, Any]] = Field(default=None, description="Arbitrary metadata.")


class HeartbeatRequest(BaseModel):
    """Payload for a device heartbeat."""

    device_id: str = Field(..., description="Reporting device identifier.")
    firmware_version: str = Field(..., min_length=1, max_length=32, description="Running firmware version.")
    status: str = Field(..., description="Self-reported device status.")
    ip_address: Optional[str] = Field(default=None, description="Source IP address.")


class CreateGroupRequest(BaseModel):
    """Payload for creating a device group."""

    name: str = Field(..., min_length=1, max_length=128, description="Group name.")
    description: str = Field(default="", max_length=512, description="Group description.")


class AssignGroupRequest(BaseModel):
    """Payload for assigning a device to a group."""

    group_name: str = Field(..., min_length=1, description="Target group name.")


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/register")
async def register_device(body: RegisterDeviceRequest) -> dict[str, Any]:
    """Register a new IoT device on the platform.

    Returns
    -------
    dict
        JSON containing ``status``, ``message``, and the ``device`` record.
    """
    device = _registry.register_device(
        name=body.name,
        device_type=body.device_type,
        firmware_version=body.firmware_version,
        ip_address=body.ip_address,
        group_name=body.group_name,
        metadata=body.metadata,
    )
    return {
        "status": "success",
        "message": f"Device '{body.name}' registered successfully.",
        "device": device,
    }


@router.get("/list")
async def list_devices(
    status: Optional[str] = Query(default=None, description="Filter by device status."),
    device_type: Optional[str] = Query(default=None, description="Filter by device type."),
) -> dict[str, Any]:
    """List all registered devices with optional filtering.

    Returns
    -------
    dict
        JSON containing ``status``, ``count``, and the ``devices`` list.
    """
    devices = _registry.list_devices(status=status, device_type=device_type)
    return {
        "status": "success",
        "count": len(devices),
        "devices": devices,
    }


@router.get("/stats")
async def fleet_stats() -> dict[str, Any]:
    """Return aggregate fleet statistics.

    Returns
    -------
    dict
        JSON containing ``status`` and the ``stats`` payload.
    """
    stats = _registry.get_fleet_stats()
    return {
        "status": "success",
        "stats": stats,
    }


@router.get("/{device_id}")
async def get_device(device_id: str) -> dict[str, Any]:
    """Retrieve a single device by its unique identifier.

    Raises
    ------
    HTTPException
        404 if the device does not exist.

    Returns
    -------
    dict
        JSON containing ``status`` and the ``device`` record.
    """
    device = _registry.get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return {
        "status": "success",
        "device": device,
    }


@router.post("/heartbeat")
async def heartbeat(body: HeartbeatRequest) -> dict[str, Any]:
    """Accept a heartbeat from a device.

    Raises
    ------
    HTTPException
        404 if the device is not registered.

    Returns
    -------
    dict
        JSON containing ``status``, ``message``, and the updated ``device``.
    """
    device = _registry.process_heartbeat(
        device_id=body.device_id,
        firmware_version=body.firmware_version,
        status=body.status,
        ip_address=body.ip_address,
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    return {
        "status": "success",
        "message": "Heartbeat processed.",
        "device": device,
    }


@router.post("/groups")
async def create_group(body: CreateGroupRequest) -> dict[str, Any]:
    """Create a new device group.

    Returns
    -------
    dict
        JSON containing ``status``, ``message``, and the ``group`` record.
    """
    group = _registry.create_group(name=body.name, description=body.description)
    return {
        "status": "success",
        "message": f"Group '{body.name}' created.",
        "group": group,
    }


@router.get("/groups/list")
async def list_groups() -> dict[str, Any]:
    """List all device groups.

    Returns
    -------
    dict
        JSON containing ``status``, ``count``, and the ``groups`` list.
    """
    groups = _registry.list_groups()
    return {
        "status": "success",
        "count": len(groups),
        "groups": groups,
    }


@router.post("/{device_id}/group")
async def assign_device_to_group(
    device_id: str,
    body: AssignGroupRequest,
) -> dict[str, Any]:
    """Assign a device to a named group.

    Raises
    ------
    HTTPException
        404 if the device does not exist.

    Returns
    -------
    dict
        JSON containing ``status`` and ``message``.
    """
    success = _registry.assign_device_to_group(device_id, body.group_name)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found.")
    return {
        "status": "success",
        "message": f"Device assigned to group '{body.group_name}'.",
    }


@router.post("/{device_id}/decommission")
async def decommission_device(device_id: str) -> dict[str, Any]:
    """Decommission (revoke) a device.

    Raises
    ------
    HTTPException
        404 if the device does not exist.

    Returns
    -------
    dict
        JSON containing ``status`` and ``message``.
    """
    success = _registry.decommission_device(device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found.")
    return {
        "status": "success",
        "message": f"Device '{device_id}' decommissioned.",
    }
