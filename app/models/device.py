"""
Device Models
=============

Pydantic schemas representing IoT devices, device groups, and heartbeat
payloads used across the OTA platform.

Each device progresses through a well-defined lifecycle captured by
:class:`DeviceStatus`:

    REGISTERED → ACTIVE → UPDATING → ACTIVE
                                    ↘ UPDATE_FAILED
    Any state  → INACTIVE
    Any state  → REVOKED
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class DeviceStatus(StrEnum):
    """Lifecycle status of an IoT device on the platform.

    Members
    -------
    REGISTERED
        Device has been enrolled but has not yet sent its first heartbeat.
    ACTIVE
        Device is online and operating normally.
    UPDATING
        Device is currently receiving / applying a firmware update.
    UPDATE_FAILED
        The most recent firmware update did not complete successfully.
    INACTIVE
        Device has been manually or automatically marked offline.
    REVOKED
        Device certificate has been revoked; it can no longer authenticate.
    """

    REGISTERED = "registered"
    ACTIVE = "active"
    UPDATING = "updating"
    UPDATE_FAILED = "update_failed"
    INACTIVE = "inactive"
    REVOKED = "revoked"


# ── Models ───────────────────────────────────────────────────────────────────


class DeviceGroup(BaseModel):
    """Logical grouping of IoT devices (e.g. by location or fleet).

    Groups enable batch firmware roll-outs and collective policy management.

    Attributes
    ----------
    group_id : UUID
        Unique identifier for the group (auto-generated).
    name : str
        Human-readable group name.
    description : str
        Optional longer description of the group's purpose.
    created_at : datetime
        UTC timestamp when the group was created.
    """

    group_id: UUID = Field(default_factory=uuid4, description="Unique group identifier.")
    name: str = Field(..., min_length=1, max_length=128, description="Human-readable group name.")
    description: str = Field(default="", max_length=512, description="Purpose or notes for this group.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of group creation.",
    )


class Device(BaseModel):
    """Representation of a single IoT device managed by the platform.

    Attributes
    ----------
    device_id : UUID
        Globally unique device identifier (auto-generated).
    name : str
        Friendly display name for the device.
    device_type : str
        Hardware or product-line identifier (e.g. ``"sensor-v2"``).
    group_id : UUID | None
        Optional reference to a :class:`DeviceGroup`.
    firmware_version : str | None
        Currently installed firmware version string.
    status : DeviceStatus
        Current lifecycle status.
    certificate_id : str | None
        Identifier of the X.509 certificate bound to this device.
    ip_address : str | None
        Last-known IP address of the device.
    last_heartbeat : datetime | None
        UTC timestamp of the most recent heartbeat received.
    registered_at : datetime
        UTC timestamp when the device was first enrolled.
    metadata : dict[str, Any]
        Arbitrary key-value metadata attached to the device.
    """

    device_id: UUID = Field(default_factory=uuid4, description="Unique device identifier.")
    name: str = Field(..., min_length=1, max_length=128, description="Friendly device name.")
    device_type: str = Field(..., min_length=1, max_length=64, description="Hardware / product-line type.")
    group_id: Optional[UUID] = Field(default=None, description="Optional DeviceGroup reference.")
    firmware_version: Optional[str] = Field(default=None, max_length=32, description="Installed firmware version.")
    status: DeviceStatus = Field(default=DeviceStatus.REGISTERED, description="Current lifecycle status.")
    certificate_id: Optional[str] = Field(default=None, description="Bound X.509 certificate ID.")
    ip_address: Optional[str] = Field(default=None, description="Last-known IP address.")
    last_heartbeat: Optional[datetime] = Field(default=None, description="Last heartbeat timestamp (UTC).")
    registered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of device registration.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary device metadata.")


class DeviceHeartbeat(BaseModel):
    """Payload sent by a device to report its current state.

    The platform uses heartbeats to track connectivity, detect stale devices,
    and verify that firmware updates have been applied successfully.

    Attributes
    ----------
    device_id : UUID
        Identifier of the reporting device.
    firmware_version : str
        Firmware version currently running on the device.
    status : DeviceStatus
        Self-reported lifecycle status.
    ip_address : str | None
        Network address the heartbeat was sent from.
    timestamp : datetime
        UTC timestamp when the heartbeat was generated on the device.
    system_info : dict[str, Any]
        Optional system telemetry (CPU temp, free RAM, etc.).
    """

    device_id: UUID = Field(..., description="Reporting device's identifier.")
    firmware_version: str = Field(..., min_length=1, max_length=32, description="Running firmware version.")
    status: DeviceStatus = Field(..., description="Self-reported device status.")
    ip_address: Optional[str] = Field(default=None, description="Source IP address.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of heartbeat generation.",
    )
    system_info: dict[str, Any] = Field(default_factory=dict, description="Optional system telemetry data.")
