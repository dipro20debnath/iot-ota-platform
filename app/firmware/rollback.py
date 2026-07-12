"""
Firmware Rollback Management
=============================

Manages firmware rollback policies and operations for the IoT OTA Platform.

A *rollback* is a deliberate downgrade from a higher firmware version to a
previously known-good version.  The :class:`RollbackManager` enforces safety
checks before permitting a rollback and maintains an in-memory audit trail
of all rollback events.

Key responsibilities:

* **Eligibility checks** — verify the target version exists in binary
  storage and is actually a downgrade relative to the current version.
* **Execution** — retrieve the target firmware binary, record the rollback
  event in the internal history, and return a success/failure result.
* **Cleanup** — delegate to :class:`~app.firmware.storage.FirmwareStorage`
  to prune old firmware versions that exceed the retention limit.

Usage::

    from app.firmware.storage import FirmwareStorage
    from app.firmware.versioning import VersionManager
    from app.firmware.rollback import RollbackManager

    storage = FirmwareStorage("./firmware_store")
    vm = VersionManager(allow_downgrade=True)
    rm = RollbackManager(storage, vm, keep_previous=5)

    check = rm.can_rollback("fw-001", "2.0.0", "1.5.0")
    if check["allowed"]:
        result = rm.execute_rollback("fw-001", "2.0.0", "1.5.0")
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from app.firmware.storage import FirmwareStorage
from app.firmware.versioning import SemanticVersion, VersionManager

logger = logging.getLogger(__name__)


class RollbackManager:
    """Manages firmware rollback policies and operations.

    Maintains an ordered history of rollback events and delegates binary
    retrieval and cleanup to :class:`FirmwareStorage`.

    Parameters
    ----------
    storage : FirmwareStorage
        The firmware binary storage backend.
    version_manager : VersionManager or None
        Version policy engine.  A default ``VersionManager`` is created
        when *None* is supplied.
    keep_previous : int
        Number of previous firmware versions to retain during cleanup.
    """

    def __init__(
        self,
        storage: FirmwareStorage,
        version_manager: Optional[VersionManager] = None,
        keep_previous: int = 5,
    ) -> None:
        """Initialise the RollbackManager.

        Args:
            storage: Firmware binary storage backend.
            version_manager: Optional version policy engine.
            keep_previous: Number of previous versions to keep.
        """
        self._storage: FirmwareStorage = storage
        self._version_manager: VersionManager = (
            version_manager if version_manager is not None else VersionManager()
        )
        self._keep_previous: int = keep_previous
        self._rollback_history: list[dict] = []
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._logger.info(
            "RollbackManager initialised – keep_previous=%d", keep_previous
        )

    # ------------------------------------------------------------------
    # Eligibility check
    # ------------------------------------------------------------------

    def can_rollback(
        self,
        firmware_id: str,
        current_version: str,
        target_version: str,
        device_type: str = "generic",
    ) -> dict:
        """Check if a rollback from *current_version* to *target_version* is allowed.

        Three conditions must be met:

        1. Both version strings must be valid semantic versions.
        2. The *target_version* must be strictly **lower** than the
           *current_version* (i.e. it is actually a downgrade).
        3. The target firmware binary must exist in storage.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        current_version : str
            The version currently running on the device.
        target_version : str
            The version the device wants to roll back to.
        device_type : str
            Device family (default ``'generic'``).

        Returns
        -------
        dict
            A result dictionary with keys:

            * ``allowed`` (bool)
            * ``reason`` (str) — human-readable explanation.
            * ``current_version`` (str)
            * ``target_version`` (str)
            * ``firmware_id`` (str)
        """
        result_base: dict = {
            "firmware_id": firmware_id,
            "current_version": current_version,
            "target_version": target_version,
        }

        # --- Validate semantic version strings ---
        try:
            current_sv = SemanticVersion(current_version)
        except ValueError:
            self._logger.warning(
                "Invalid current version '%s' for rollback check.", current_version
            )
            return {
                **result_base,
                "allowed": False,
                "reason": (
                    f"Current version '{current_version}' is not a valid "
                    "semantic version."
                ),
            }

        try:
            target_sv = SemanticVersion(target_version)
        except ValueError:
            self._logger.warning(
                "Invalid target version '%s' for rollback check.", target_version
            )
            return {
                **result_base,
                "allowed": False,
                "reason": (
                    f"Target version '{target_version}' is not a valid "
                    "semantic version."
                ),
            }

        # --- Target must be lower than current ---
        if target_sv >= current_sv:
            self._logger.info(
                "Rollback denied: target %s >= current %s.", target_sv, current_sv
            )
            return {
                **result_base,
                "allowed": False,
                "reason": (
                    f"Target version '{target_version}' is not lower than "
                    f"current version '{current_version}'. Rollback requires "
                    "a downgrade."
                ),
            }

        # --- Target firmware must exist in storage ---
        if not self._storage.firmware_exists(firmware_id, target_version, device_type):
            self._logger.info(
                "Rollback denied: firmware %s v%s not found in storage.",
                firmware_id,
                target_version,
            )
            return {
                **result_base,
                "allowed": False,
                "reason": (
                    f"Target firmware '{firmware_id}' version "
                    f"'{target_version}' does not exist in storage."
                ),
            }

        self._logger.info(
            "Rollback allowed: %s → %s for firmware %s.",
            current_version,
            target_version,
            firmware_id,
        )
        return {
            **result_base,
            "allowed": True,
            "reason": (
                f"Rollback from '{current_version}' to '{target_version}' "
                "is permitted."
            ),
        }

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute_rollback(
        self,
        firmware_id: str,
        current_version: str,
        target_version: str,
        device_type: str = "generic",
        device_id: Optional[str] = None,
    ) -> dict:
        """Execute a rollback operation.

        Steps:

        1. Verify rollback eligibility via :meth:`can_rollback`.
        2. Retrieve the target firmware binary from storage.
        3. Record the rollback event in the internal history list.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        current_version : str
            The version currently running.
        target_version : str
            The version to roll back to.
        device_type : str
            Device family (default ``'generic'``).
        device_id : str or None
            Optional identifier of the specific device being rolled back.

        Returns
        -------
        dict
            A result dictionary with keys:

            * ``success`` (bool)
            * ``firmware_id`` (str)
            * ``rolled_back_from`` (str)
            * ``rolled_back_to`` (str)
            * ``device_id`` (str or None)
            * ``timestamp`` (str) — ISO 8601 UTC timestamp.
            * ``error`` (str) — present only when ``success`` is *False*.
        """
        timestamp: str = datetime.now(timezone.utc).isoformat()

        # --- Step 1: Check eligibility ---
        check: dict = self.can_rollback(
            firmware_id, current_version, target_version, device_type
        )
        if not check["allowed"]:
            self._logger.warning(
                "Rollback execution blocked: %s", check["reason"]
            )
            return {
                "success": False,
                "firmware_id": firmware_id,
                "rolled_back_from": current_version,
                "rolled_back_to": target_version,
                "device_id": device_id,
                "timestamp": timestamp,
                "error": check["reason"],
            }

        # --- Step 2: Verify binary is retrievable ---
        firmware_data: bytes | None = self._storage.get_firmware(
            firmware_id, target_version, device_type
        )
        if firmware_data is None:
            error_msg = (
                f"Firmware binary for '{firmware_id}' v{target_version} "
                "could not be retrieved from storage."
            )
            self._logger.error(error_msg)
            return {
                "success": False,
                "firmware_id": firmware_id,
                "rolled_back_from": current_version,
                "rolled_back_to": target_version,
                "device_id": device_id,
                "timestamp": timestamp,
                "error": error_msg,
            }

        # --- Step 3: Record rollback event ---
        event: dict = {
            "firmware_id": firmware_id,
            "rolled_back_from": current_version,
            "rolled_back_to": target_version,
            "device_type": device_type,
            "device_id": device_id,
            "timestamp": timestamp,
            "firmware_size_bytes": len(firmware_data),
        }
        self._rollback_history.append(event)

        self._logger.info(
            "Rollback executed: %s v%s → v%s (device=%s).",
            firmware_id,
            current_version,
            target_version,
            device_id or "N/A",
        )

        return {
            "success": True,
            "firmware_id": firmware_id,
            "rolled_back_from": current_version,
            "rolled_back_to": target_version,
            "device_id": device_id,
            "timestamp": timestamp,
        }

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_rollback_history(
        self, firmware_id: Optional[str] = None
    ) -> list[dict]:
        """Return the recorded rollback history.

        Parameters
        ----------
        firmware_id : str or None
            When supplied, only events for that firmware ID are returned.

        Returns
        -------
        list[dict]
            A list of rollback event dictionaries, most recent first.
        """
        if firmware_id is None:
            return list(reversed(self._rollback_history))

        return [
            event
            for event in reversed(self._rollback_history)
            if event["firmware_id"] == firmware_id
        ]

    # ------------------------------------------------------------------
    # Available rollback versions
    # ------------------------------------------------------------------

    def get_available_rollback_versions(
        self,
        firmware_id: str,
        current_version: str,
        device_type: str = "generic",
    ) -> list[str]:
        """Get versions available as rollback targets.

        Scans the firmware storage for all versions of *firmware_id* and
        returns those that are strictly lower than *current_version*,
        sorted in **descending** order (highest available rollback target
        first).

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        current_version : str
            The version currently running on the device.
        device_type : str
            Device family (default ``'generic'``).

        Returns
        -------
        list[str]
            Version strings eligible for rollback, sorted descending.
        """
        try:
            current_sv = SemanticVersion(current_version)
        except ValueError:
            self._logger.warning(
                "Invalid current version '%s'; cannot determine rollback "
                "targets.",
                current_version,
            )
            return []

        # Get all stored firmware entries for the given device type
        all_stored: list[dict] = self._storage.list_firmware(device_type)

        candidates: list[SemanticVersion] = []
        for entry in all_stored:
            if entry.get("firmware_id") != firmware_id:
                continue
            version_str: str = entry.get("version", "")
            try:
                sv = SemanticVersion(version_str)
            except ValueError:
                continue
            if sv < current_sv:
                candidates.append(sv)

        # Sort descending (highest first)
        candidates.sort(reverse=True)
        return [str(v) for v in candidates]

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_rollback_limit(self, limit: int) -> None:
        """Set the maximum number of previous firmware versions to retain.

        Parameters
        ----------
        limit : int
            The new retention limit.  Must be ≥ 1.

        Raises
        ------
        ValueError
            If *limit* is less than 1.
        """
        if limit < 1:
            raise ValueError("Rollback limit must be at least 1.")
        self._keep_previous = limit
        self._logger.info("Rollback limit set to %d.", limit)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_old_versions(
        self,
        firmware_id: str,
        device_type: str = "generic",
    ) -> list[str]:
        """Clean up old firmware versions beyond the retention limit.

        Delegates to
        :meth:`~app.firmware.storage.FirmwareStorage.cleanup_old_versions`,
        passing the configured ``keep_previous`` count.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        device_type : str
            Device family (default ``'generic'``).

        Returns
        -------
        list[str]
            Version strings that were deleted.
        """
        deleted: list[str] = self._storage.cleanup_old_versions(
            firmware_id=firmware_id,
            device_type=device_type,
            keep_count=self._keep_previous,
        )
        if deleted:
            self._logger.info(
                "Cleaned up %d old version(s) for firmware %s: %s",
                len(deleted),
                firmware_id,
                ", ".join(deleted),
            )
        return deleted
