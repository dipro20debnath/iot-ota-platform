"""
Deployment Tracker — Staged Rollouts
======================================

Provides :class:`DeploymentTracker` for managing **staged (phased) rollouts**
of firmware updates across device groups.

A staged rollout divides a population of devices into sequential stages
(e.g. 10% → 25% → 50% → 100%).  Each stage must be explicitly advanced
after the operator has verified that the previous batch completed without
issues.

Rollout state is stored **in-memory** — it is not persisted to the database.
Individual per-device deployments are still created via
:class:`~app.ota.update_manager.UpdateManager` and *are* persisted.

Usage::

    from app.ota.deployment import DeploymentTracker

    tracker = DeploymentTracker()
    rollout = tracker.create_staged_rollout(
        firmware_id="fw-001",
        device_ids=["d1", "d2", "d3", "d4", "d5"],
        stages=[20, 60, 100],
    )
    stage_devices = tracker.get_current_stage_devices(rollout["rollout_id"])
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class DeploymentTracker:
    """Manages staged (phased) firmware rollouts.

    Rollout metadata is stored in an in-memory dictionary keyed by
    ``rollout_id``.  Each rollout record tracks:

    * The firmware being deployed (``firmware_id``).
    * The full list of target ``device_ids``.
    * The ``stages`` — a list of cumulative-percentage thresholds.
    * The ``current_stage`` index (0-based).
    * Per-stage device assignments.
    * Overall ``status`` (``active``, ``completed``, ``cancelled``).
    """

    def __init__(self) -> None:
        self._rollouts: dict[str, dict[str, Any]] = {}
        self._logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )

    # ------------------------------------------------------------------
    # Rollout creation
    # ------------------------------------------------------------------

    def create_staged_rollout(
        self,
        firmware_id: str,
        device_ids: list[str],
        stages: list[int],
    ) -> dict[str, Any]:
        """Create a new staged rollout.

        Parameters
        ----------
        firmware_id : str
            Firmware image to deploy.
        device_ids : list[str]
            Full list of target device identifiers.
        stages : list[int]
            Cumulative percentage thresholds for each stage, in ascending
            order.  The last element should be ``100``.

            Example: ``[10, 50, 100]`` means stage 0 covers 10% of
            devices, stage 1 covers an additional 40% (up to 50%), and
            stage 2 covers the remaining 50%.

        Returns
        -------
        dict
            The newly created rollout record.

        Raises
        ------
        ValueError
            If *stages* is empty or *device_ids* is empty.
        """
        if not stages:
            raise ValueError("At least one stage percentage is required")
        if not device_ids:
            raise ValueError("At least one device is required")

        rollout_id = str(uuid4())
        total = len(device_ids)

        # Pre-compute which devices belong to each stage.
        stage_assignments: list[list[str]] = []
        prev_count = 0
        for pct in stages:
            target_count = math.ceil(total * pct / 100)
            target_count = min(target_count, total)  # clamp
            stage_assignments.append(device_ids[prev_count:target_count])
            prev_count = target_count

        rollout: dict[str, Any] = {
            "rollout_id": rollout_id,
            "firmware_id": firmware_id,
            "device_ids": list(device_ids),
            "stages": list(stages),
            "stage_assignments": stage_assignments,
            "current_stage": 0,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None,
        }
        self._rollouts[rollout_id] = rollout

        self._logger.info(
            "Staged rollout created — id=%s, firmware=%s, devices=%d, stages=%s",
            rollout_id, firmware_id, total, stages,
        )
        return dict(rollout)

    # ------------------------------------------------------------------
    # Stage advancement
    # ------------------------------------------------------------------

    def advance_stage(self, rollout_id: str) -> dict[str, Any]:
        """Advance the rollout to the next stage.

        If the current stage is the last one, the rollout's status is set
        to ``completed``.

        Parameters
        ----------
        rollout_id : str
            Identifier of the rollout to advance.

        Returns
        -------
        dict
            The updated rollout record.

        Raises
        ------
        ValueError
            If the rollout does not exist or is not in ``active`` status.
        """
        rollout = self._rollouts.get(rollout_id)
        if rollout is None:
            raise ValueError(f"Rollout not found: {rollout_id}")
        if rollout["status"] != "active":
            raise ValueError(
                f"Cannot advance rollout in '{rollout['status']}' status"
            )

        next_stage = rollout["current_stage"] + 1
        if next_stage >= len(rollout["stages"]):
            rollout["status"] = "completed"
            rollout["completed_at"] = datetime.now(timezone.utc).isoformat()
            self._logger.info("Rollout completed — id=%s", rollout_id)
        else:
            rollout["current_stage"] = next_stage
            self._logger.info(
                "Rollout advanced — id=%s, stage=%d/%d",
                rollout_id, next_stage, len(rollout["stages"]),
            )

        return dict(rollout)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_rollout(self, rollout_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a rollout record by its identifier.

        Parameters
        ----------
        rollout_id : str

        Returns
        -------
        dict or None
        """
        rollout = self._rollouts.get(rollout_id)
        return dict(rollout) if rollout else None

    def get_current_stage_devices(self, rollout_id: str) -> list[str]:
        """Get the device IDs assigned to the rollout's current stage.

        Parameters
        ----------
        rollout_id : str

        Returns
        -------
        list[str]
            Device identifiers for the current stage.

        Raises
        ------
        ValueError
            If the rollout does not exist.
        """
        rollout = self._rollouts.get(rollout_id)
        if rollout is None:
            raise ValueError(f"Rollout not found: {rollout_id}")

        idx = rollout["current_stage"]
        assignments = rollout["stage_assignments"]
        if idx < len(assignments):
            return list(assignments[idx])
        return []

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def cancel_rollout(
        self,
        rollout_id: str,
        reason: str = "Cancelled by operator",
    ) -> dict[str, Any]:
        """Cancel an active rollout.

        Parameters
        ----------
        rollout_id : str
            The rollout to cancel.
        reason : str
            Human-readable cancellation reason.

        Returns
        -------
        dict
            The updated rollout record.

        Raises
        ------
        ValueError
            If the rollout does not exist or is not ``active``.
        """
        rollout = self._rollouts.get(rollout_id)
        if rollout is None:
            raise ValueError(f"Rollout not found: {rollout_id}")
        if rollout["status"] != "active":
            raise ValueError(
                f"Cannot cancel rollout in '{rollout['status']}' status"
            )

        rollout["status"] = "cancelled"
        rollout["cancel_reason"] = reason
        rollout["completed_at"] = datetime.now(timezone.utc).isoformat()

        self._logger.info(
            "Rollout cancelled — id=%s, reason=%s", rollout_id, reason,
        )
        return dict(rollout)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_rollout_summary(self, rollout_id: str) -> dict[str, Any]:
        """Return a human-readable summary of the rollout's progress.

        Parameters
        ----------
        rollout_id : str

        Returns
        -------
        dict
            Keys: ``rollout_id``, ``firmware_id``, ``status``,
            ``total_devices``, ``current_stage``, ``total_stages``,
            ``devices_in_current_stage``, ``stages_detail``.

        Raises
        ------
        ValueError
            If the rollout does not exist.
        """
        rollout = self._rollouts.get(rollout_id)
        if rollout is None:
            raise ValueError(f"Rollout not found: {rollout_id}")

        stages_detail: list[dict[str, Any]] = []
        for i, pct in enumerate(rollout["stages"]):
            devices = rollout["stage_assignments"][i] if i < len(
                rollout["stage_assignments"]
            ) else []
            stages_detail.append({
                "stage": i,
                "percentage": pct,
                "device_count": len(devices),
                "devices": devices,
            })

        current_devices = self.get_current_stage_devices(rollout_id)

        return {
            "rollout_id": rollout_id,
            "firmware_id": rollout["firmware_id"],
            "status": rollout["status"],
            "total_devices": len(rollout["device_ids"]),
            "current_stage": rollout["current_stage"],
            "total_stages": len(rollout["stages"]),
            "devices_in_current_stage": len(current_devices),
            "stages_detail": stages_detail,
        }
