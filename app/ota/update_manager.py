"""
OTA Update Manager
===================

Orchestrates firmware deployments to IoT devices.

The :class:`UpdateManager` acts as the central coordinator for the OTA update
lifecycle — from checking whether a device has an available update, through
creating and tracking deployments, to final completion or cancellation.

It delegates persistence to :func:`~app.db.store.get_store` and version
comparison to :class:`~app.firmware.versioning.SemanticVersion`.

Usage::

    from app.ota.update_manager import UpdateManager

    mgr = UpdateManager()
    result = mgr.check_for_update("device-001")
    deployment = mgr.create_deployment("fw-abc", "device-001")
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from app.db.store import get_store
from app.firmware.versioning import SemanticVersion

logger = logging.getLogger(__name__)


class UpdateManager:
    """Orchestrates OTA firmware deployments to IoT devices.

    All state is persisted via the platform's :class:`~app.db.sqlite_store.SQLiteStore`.
    The manager enforces version-ordering rules (no downgrades by default)
    and tracks deployment statistics.

    Parameters
    ----------
    allow_downgrade : bool
        When ``False`` (the default), :meth:`check_for_update` will not
        suggest firmware whose version is lower than the device's current
        version.
    """

    def __init__(self, allow_downgrade: bool = False) -> None:
        self._allow_downgrade = allow_downgrade
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Update checking
    # ------------------------------------------------------------------

    def check_for_update(self, device_id: str) -> dict[str, Any]:
        """Check whether a newer firmware is available for a device.

        The method looks up the device's ``device_type`` and
        ``firmware_version``, then queries published firmware for the same
        device type.  The highest-versioned published firmware that is
        newer than the device's current version (according to SemVer) is
        returned as the recommended update.

        Parameters
        ----------
        device_id : str
            Unique identifier of the device to check.

        Returns
        -------
        dict
            Keys:

            * ``update_available`` (bool)
            * ``device_id`` (str)
            * ``current_version`` (str | None)
            * ``latest_firmware`` (dict | None) — the recommended firmware
              record if an update is available.

        Raises
        ------
        ValueError
            If *device_id* does not exist in the database.
        """
        store = get_store()
        device = store.get_device(device_id)
        if device is None:
            raise ValueError(f"Device not found: {device_id}")

        current_version = device.get("firmware_version")
        device_type = device.get("device_type", "generic")

        # Fetch all published firmware for this device type.
        firmware_list = store.list_firmware(
            status="published", device_type=device_type,
        )
        if not firmware_list:
            self._logger.debug(
                "No published firmware for device_type=%s", device_type,
            )
            return {
                "update_available": False,
                "device_id": device_id,
                "current_version": current_version,
                "latest_firmware": None,
            }

        # Sort by semantic version (descending) and pick the highest.
        firmware_list.sort(
            key=lambda fw: SemanticVersion(fw["version"]),
            reverse=True,
        )
        latest = firmware_list[0]

        # If the device has no version yet, any published firmware is an update.
        if current_version is None:
            self._logger.info(
                "Device %s has no firmware — update available: %s",
                device_id, latest["version"],
            )
            return {
                "update_available": True,
                "device_id": device_id,
                "current_version": None,
                "latest_firmware": latest,
            }

        # Compare versions.
        try:
            current_sv = SemanticVersion(current_version)
            latest_sv = SemanticVersion(latest["version"])
        except ValueError:
            self._logger.warning(
                "Invalid version string(s) — current=%s, latest=%s",
                current_version, latest["version"],
            )
            return {
                "update_available": False,
                "device_id": device_id,
                "current_version": current_version,
                "latest_firmware": None,
            }

        if latest_sv > current_sv:
            self._logger.info(
                "Update available for device %s: %s → %s",
                device_id, current_version, latest["version"],
            )
            return {
                "update_available": True,
                "device_id": device_id,
                "current_version": current_version,
                "latest_firmware": latest,
            }

        self._logger.debug(
            "Device %s already on latest version %s", device_id, current_version,
        )
        return {
            "update_available": False,
            "device_id": device_id,
            "current_version": current_version,
            "latest_firmware": None,
        }

    # ------------------------------------------------------------------
    # Deployment CRUD
    # ------------------------------------------------------------------

    def create_deployment(
        self,
        firmware_id: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Create a new deployment record in *pending* status.

        Parameters
        ----------
        firmware_id : str
            The firmware to deploy.
        device_id : str
            The target device.

        Returns
        -------
        dict
            The saved deployment record.

        Raises
        ------
        ValueError
            If the firmware or device does not exist.
        """
        store = get_store()

        firmware = store.get_firmware(firmware_id)
        if firmware is None:
            raise ValueError(f"Firmware not found: {firmware_id}")

        device = store.get_device(device_id)
        if device is None:
            raise ValueError(f"Device not found: {device_id}")

        deployment_id = str(uuid4())
        deployment = store.save_deployment({
            "deployment_id": deployment_id,
            "firmware_id": firmware_id,
            "device_id": device_id,
            "status": "pending",
        })
        self._logger.info(
            "Deployment created — id=%s, firmware=%s, device=%s",
            deployment_id, firmware_id, device_id,
        )
        return deployment

    def start_deployment(self, deployment_id: str) -> dict[str, Any]:
        """Transition a deployment to *in_progress* and mark the device as
        *updating*.

        Parameters
        ----------
        deployment_id : str
            The deployment to start.

        Returns
        -------
        dict
            The updated deployment record.

        Raises
        ------
        ValueError
            If the deployment does not exist or is not in *pending* status.
        """
        store = get_store()
        deployment = store.get_deployment(deployment_id)
        if deployment is None:
            raise ValueError(f"Deployment not found: {deployment_id}")
        if deployment["status"] != "pending":
            raise ValueError(
                f"Cannot start deployment in '{deployment['status']}' status"
            )

        store.update_deployment_status(deployment_id, "in_progress")
        store.update_device(deployment["device_id"], {"status": "updating"})

        self._logger.info("Deployment started — id=%s", deployment_id)
        return store.get_deployment(deployment_id)  # type: ignore[return-value]

    def complete_deployment(self, deployment_id: str) -> dict[str, Any]:
        """Mark a deployment as *completed* and update the device's firmware
        version and status.

        Parameters
        ----------
        deployment_id : str
            The deployment to complete.

        Returns
        -------
        dict
            The updated deployment record.

        Raises
        ------
        ValueError
            If the deployment does not exist or is not in *in_progress*
            status.
        """
        store = get_store()
        deployment = store.get_deployment(deployment_id)
        if deployment is None:
            raise ValueError(f"Deployment not found: {deployment_id}")
        if deployment["status"] != "in_progress":
            raise ValueError(
                f"Cannot complete deployment in '{deployment['status']}' status"
            )

        store.update_deployment_status(deployment_id, "completed")

        # Update device firmware version and status.
        firmware = store.get_firmware(deployment["firmware_id"])
        updates: dict[str, Any] = {"status": "active"}
        if firmware:
            updates["firmware_version"] = firmware["version"]
        store.update_device(deployment["device_id"], updates)

        self._logger.info("Deployment completed — id=%s", deployment_id)
        return store.get_deployment(deployment_id)  # type: ignore[return-value]

    def cancel_deployment(
        self,
        deployment_id: str,
        reason: str = "Cancelled by operator",
    ) -> dict[str, Any]:
        """Cancel a deployment and optionally restore the device to *active*.

        Only deployments in *pending* or *in_progress* status can be
        cancelled.

        Parameters
        ----------
        deployment_id : str
            The deployment to cancel.
        reason : str
            Human-readable cancellation reason recorded as the error
            message.

        Returns
        -------
        dict
            The updated deployment record.

        Raises
        ------
        ValueError
            If the deployment does not exist or has already reached a
            terminal state.
        """
        store = get_store()
        deployment = store.get_deployment(deployment_id)
        if deployment is None:
            raise ValueError(f"Deployment not found: {deployment_id}")
        if deployment["status"] not in ("pending", "in_progress"):
            raise ValueError(
                f"Cannot cancel deployment in '{deployment['status']}' status"
            )

        store.update_deployment_status(
            deployment_id, "failed", error_message=reason,
        )
        store.update_device(deployment["device_id"], {"status": "active"})

        self._logger.info(
            "Deployment cancelled — id=%s, reason=%s", deployment_id, reason,
        )
        return store.get_deployment(deployment_id)  # type: ignore[return-value]

    def get_deployment(self, deployment_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a single deployment record.

        Parameters
        ----------
        deployment_id : str
            The unique deployment identifier.

        Returns
        -------
        dict or None
        """
        return get_store().get_deployment(deployment_id)

    def list_deployments(
        self,
        device_id: Optional[str] = None,
        firmware_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List deployments with optional filtering.

        Parameters
        ----------
        device_id : str, optional
            Filter by target device.
        firmware_id : str, optional
            Filter by firmware image.

        Returns
        -------
        list[dict]
        """
        return get_store().list_deployments(
            device_id=device_id, firmware_id=firmware_id,
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_deployment_stats(self) -> dict[str, Any]:
        """Aggregate deployment statistics across all statuses.

        Returns
        -------
        dict
            Keys: ``total``, ``pending``, ``in_progress``, ``completed``,
            ``failed``.
        """
        deployments = get_store().list_deployments()
        stats: dict[str, int] = {
            "total": len(deployments),
            "pending": 0,
            "in_progress": 0,
            "completed": 0,
            "failed": 0,
        }
        for d in deployments:
            status = d.get("status", "pending")
            if status in stats:
                stats[status] += 1
        return stats

    # ------------------------------------------------------------------
    # Group deployment
    # ------------------------------------------------------------------

    def deploy_to_group(
        self,
        firmware_id: str,
        group_name: str,
    ) -> list[dict[str, Any]]:
        """Create deployments for all devices in a named group.

        Parameters
        ----------
        firmware_id : str
            The firmware to deploy.
        group_name : str
            The device group name to target.

        Returns
        -------
        list[dict]
            List of created deployment records (one per device).

        Raises
        ------
        ValueError
            If the firmware does not exist or no devices belong to the
            specified group.
        """
        store = get_store()

        firmware = store.get_firmware(firmware_id)
        if firmware is None:
            raise ValueError(f"Firmware not found: {firmware_id}")

        # list_devices doesn't support group_name filtering natively,
        # so we filter in-memory.
        all_devices = store.list_devices()
        group_devices = [
            d for d in all_devices
            if d.get("group_name") == group_name
        ]

        if not group_devices:
            raise ValueError(
                f"No devices found in group '{group_name}'"
            )

        deployments: list[dict[str, Any]] = []
        for device in group_devices:
            dep = self.create_deployment(firmware_id, device["device_id"])
            deployments.append(dep)

        self._logger.info(
            "Group deployment created — firmware=%s, group=%s, count=%d",
            firmware_id, group_name, len(deployments),
        )
        return deployments
