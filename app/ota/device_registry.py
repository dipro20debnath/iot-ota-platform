"""
Device Registry
================

Central registry for managing IoT device lifecycle, group membership,
and fleet-level statistics within the OTA platform.

The :class:`DeviceRegistry` orchestrates device CRUD operations via the
persistent :class:`~app.db.sqlite_store.SQLiteStore`, while keeping
lightweight device groups in an in-memory dictionary for rapid access.

Usage::

    from app.ota.device_registry import DeviceRegistry

    registry = DeviceRegistry()
    device = registry.register_device(
        name="temp-sensor-01",
        device_type="sensor-v2",
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from app.db.store import get_store
from app.models.device import DeviceStatus

logger = logging.getLogger(__name__)


class DeviceRegistry:
    """Manages device registration, heartbeat processing, grouping, and stats.

    Groups are stored in-memory as a ``dict[str, dict]`` keyed by
    ``group_id``.  All device records are persisted through the
    :func:`~app.db.store.get_store` singleton.
    """

    def __init__(self) -> None:
        """Initialise the registry with an empty group store."""
        self._groups: dict[str, dict[str, Any]] = {}
        logger.info("DeviceRegistry initialised.")

    # ------------------------------------------------------------------
    # Device CRUD
    # ------------------------------------------------------------------

    def register_device(
        self,
        name: str,
        device_type: str,
        *,
        firmware_version: Optional[str] = None,
        ip_address: Optional[str] = None,
        group_name: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Register a new device on the platform.

        The device is persisted with status
        :attr:`~app.models.device.DeviceStatus.REGISTERED` and a newly
        generated ``device_id``.

        Args:
            name: Human-readable device name.
            device_type: Hardware / product-line identifier.
            firmware_version: Currently installed firmware version.
            ip_address: Initial IP address of the device.
            group_name: Optional group to assign the device to.
            metadata: Arbitrary key-value metadata.

        Returns
        -------
        dict
            The persisted device record.
        """
        store = get_store()
        device_id = str(uuid4())

        device_data: dict[str, Any] = {
            "device_id": device_id,
            "name": name,
            "device_type": device_type,
            "firmware_version": firmware_version,
            "status": DeviceStatus.REGISTERED.value,
            "ip_address": ip_address,
            "group_name": group_name,
            "metadata": metadata or {},
        }

        saved = store.save_device(device_data)
        logger.info(
            "Device registered – device_id=%s, name=%s, type=%s",
            device_id, name, device_type,
        )
        return saved

    def get_device(self, device_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a single device by its unique identifier.

        Args:
            device_id: The UUID of the device to look up.

        Returns
        -------
        dict or None
            The device record, or ``None`` if no matching device exists.
        """
        return get_store().get_device(device_id)

    def list_devices(
        self,
        *,
        status: Optional[str] = None,
        device_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return all devices, optionally filtered by status or type.

        Args:
            status: Filter by :class:`~app.models.device.DeviceStatus` value.
            device_type: Filter by hardware type string.

        Returns
        -------
        list[dict]
            Matching device records ordered by registration date (newest first).
        """
        return get_store().list_devices(status=status, device_type=device_type)

    def update_device_status(
        self,
        device_id: str,
        status: str,
    ) -> bool:
        """Change the lifecycle status of a device.

        Args:
            device_id: The device to update.
            status: New :class:`~app.models.device.DeviceStatus` value.

        Returns
        -------
        bool
            ``True`` if the device was found and updated.
        """
        updated = get_store().update_device(device_id, {"status": status})
        if updated:
            logger.info(
                "Device status updated – device_id=%s, status=%s",
                device_id, status,
            )
        return updated

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def process_heartbeat(
        self,
        device_id: str,
        firmware_version: str,
        status: str,
        *,
        ip_address: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Process an incoming heartbeat from a device.

        Updates ``last_heartbeat``, ``firmware_version``, ``status``, and
        optionally ``ip_address`` on the device record.

        Args:
            device_id: Reporting device identifier.
            firmware_version: Firmware version running on the device.
            status: Self-reported device status.
            ip_address: Source IP address of the heartbeat.

        Returns
        -------
        dict or None
            The updated device record, or ``None`` if *device_id* is not
            registered.
        """
        store = get_store()
        device = store.get_device(device_id)
        if device is None:
            logger.warning("Heartbeat from unknown device – device_id=%s", device_id)
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        updates: dict[str, Any] = {
            "last_heartbeat": now_iso,
            "firmware_version": firmware_version,
            "status": status,
        }
        if ip_address is not None:
            updates["ip_address"] = ip_address

        store.update_device(device_id, updates)
        logger.info("Heartbeat processed – device_id=%s", device_id)
        return store.get_device(device_id)

    # ------------------------------------------------------------------
    # Group management (in-memory)
    # ------------------------------------------------------------------

    def create_group(
        self,
        name: str,
        description: str = "",
    ) -> dict[str, Any]:
        """Create a new device group.

        Groups are stored in-memory and identified by a generated UUID.

        Args:
            name: Human-readable group name.
            description: Optional longer description.

        Returns
        -------
        dict
            The newly created group record.
        """
        group_id = str(uuid4())
        now_iso = datetime.now(timezone.utc).isoformat()

        group: dict[str, Any] = {
            "group_id": group_id,
            "name": name,
            "description": description,
            "created_at": now_iso,
            "device_count": 0,
        }
        self._groups[group_id] = group
        logger.info("Group created – group_id=%s, name=%s", group_id, name)
        return group

    def get_group(self, group_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a group by its identifier.

        Args:
            group_id: The UUID of the group.

        Returns
        -------
        dict or None
            The group record, or ``None`` if it does not exist.
        """
        return self._groups.get(group_id)

    def list_groups(self) -> list[dict[str, Any]]:
        """Return all registered device groups.

        Returns
        -------
        list[dict]
            Every group currently stored in the registry.
        """
        return list(self._groups.values())

    def assign_device_to_group(
        self,
        device_id: str,
        group_name: str,
    ) -> bool:
        """Assign a device to a named group.

        Updates the ``group_name`` column on the device record.

        Args:
            device_id: The device to assign.
            group_name: Target group name.

        Returns
        -------
        bool
            ``True`` if the device was found and updated.
        """
        store = get_store()
        device = store.get_device(device_id)
        if device is None:
            logger.warning(
                "Cannot assign unknown device to group – device_id=%s",
                device_id,
            )
            return False

        updated = store.update_device(device_id, {"group_name": group_name})
        if updated:
            logger.info(
                "Device assigned to group – device_id=%s, group=%s",
                device_id, group_name,
            )
        return updated

    # ------------------------------------------------------------------
    # Fleet statistics
    # ------------------------------------------------------------------

    def get_fleet_stats(self) -> dict[str, Any]:
        """Compute aggregate fleet statistics.

        Queries all devices and computes total count, per-status
        breakdown, device-type breakdown, and group count.

        Returns
        -------
        dict
            A dictionary containing ``total_devices``, ``by_status``,
            ``by_type``, and ``total_groups``.
        """
        devices = get_store().list_devices()

        by_status: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for d in devices:
            st = d.get("status", "unknown")
            by_status[st] = by_status.get(st, 0) + 1

            dt = d.get("device_type", "unknown")
            by_type[dt] = by_type.get(dt, 0) + 1

        return {
            "total_devices": len(devices),
            "by_status": by_status,
            "by_type": by_type,
            "total_groups": len(self._groups),
        }

    # ------------------------------------------------------------------
    # Decommission
    # ------------------------------------------------------------------

    def decommission_device(self, device_id: str) -> bool:
        """Mark a device as revoked, effectively decommissioning it.

        Sets the device status to
        :attr:`~app.models.device.DeviceStatus.REVOKED`.

        Args:
            device_id: The device to decommission.

        Returns
        -------
        bool
            ``True`` if the device was found and decommissioned.
        """
        store = get_store()
        device = store.get_device(device_id)
        if device is None:
            logger.warning(
                "Cannot decommission unknown device – device_id=%s",
                device_id,
            )
            return False

        updated = store.update_device(
            device_id, {"status": DeviceStatus.REVOKED.value},
        )
        if updated:
            logger.info("Device decommissioned – device_id=%s", device_id)
        return updated
