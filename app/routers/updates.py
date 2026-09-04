"""
OTA Updates API Router
=======================

FastAPI router exposing REST endpoints for Over-the-Air firmware update
management:

* **Update check** — query whether a device has an available update.
* **Deployments** — create, start, complete, cancel, list, and inspect
  individual firmware deployments.
* **Staged rollouts** — create, advance, cancel, and summarise phased
  rollouts that progressively deploy firmware to groups of devices.
* **Statistics** — aggregate deployment counts by status.

All endpoints are mounted under the ``/api/updates`` prefix.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.ota.update_manager import UpdateManager
from app.ota.deployment import DeploymentTracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/updates", tags=["OTA Updates"])

# ── Module-level singletons ──────────────────────────────────────────────────

_update_manager = UpdateManager()
_deployment_tracker = DeploymentTracker()


# ── Request / Response Schemas ───────────────────────────────────────────────


class CreateDeploymentRequest(BaseModel):
    """Body for creating a new deployment."""
    firmware_id: str = Field(..., description="Firmware image to deploy.")
    device_id: str = Field(..., description="Target device identifier.")


class StartDeploymentRequest(BaseModel):
    """Body for starting a deployment (empty — ID comes from the path)."""


class CancelDeploymentRequest(BaseModel):
    """Body for cancelling a deployment."""
    reason: str = Field(
        default="Cancelled by operator",
        description="Human-readable cancellation reason.",
    )


class DeployToGroupRequest(BaseModel):
    """Body for deploying firmware to a device group."""
    firmware_id: str = Field(..., description="Firmware image to deploy.")
    group_name: str = Field(..., description="Target device group name.")


class CreateRolloutRequest(BaseModel):
    """Body for creating a staged rollout."""
    firmware_id: str = Field(..., description="Firmware image to deploy.")
    device_ids: list[str] = Field(..., description="Target device identifiers.")
    stages: list[int] = Field(
        ...,
        description=(
            "Cumulative percentage thresholds for each stage "
            "(e.g. [10, 50, 100])."
        ),
    )


class CancelRolloutRequest(BaseModel):
    """Body for cancelling a staged rollout."""
    reason: str = Field(
        default="Cancelled by operator",
        description="Human-readable cancellation reason.",
    )


# ── Update Check ─────────────────────────────────────────────────────────────


@router.get("/check/{device_id}")
async def check_for_update(device_id: str) -> dict[str, Any]:
    """Check whether a firmware update is available for a device.

    Returns
    -------
    dict
        ``update_available``, ``device_id``, ``current_version``, and
        ``latest_firmware`` (if available).
    """
    try:
        return _update_manager.check_for_update(device_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ── Deployment CRUD ──────────────────────────────────────────────────────────


@router.post("/deployments")
async def create_deployment(body: CreateDeploymentRequest) -> dict[str, Any]:
    """Create a new firmware deployment for a single device.

    Returns the saved deployment record with status ``pending``.
    """
    try:
        return _update_manager.create_deployment(
            body.firmware_id, body.device_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/deployments")
async def list_deployments(
    device_id: Optional[str] = Query(default=None),
    firmware_id: Optional[str] = Query(default=None),
) -> list[dict[str, Any]]:
    """List deployments, optionally filtered by device or firmware."""
    return _update_manager.list_deployments(
        device_id=device_id, firmware_id=firmware_id,
    )


@router.get("/deployments/{deployment_id}")
async def get_deployment(deployment_id: str) -> dict[str, Any]:
    """Retrieve a single deployment by its identifier."""
    dep = _update_manager.get_deployment(deployment_id)
    if dep is None:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return dep


@router.post("/deployments/{deployment_id}/start")
async def start_deployment(deployment_id: str) -> dict[str, Any]:
    """Transition a deployment from *pending* to *in_progress*."""
    try:
        return _update_manager.start_deployment(deployment_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/deployments/{deployment_id}/complete")
async def complete_deployment(deployment_id: str) -> dict[str, Any]:
    """Mark a deployment as *completed* and update the device's firmware."""
    try:
        return _update_manager.complete_deployment(deployment_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/deployments/{deployment_id}/cancel")
async def cancel_deployment(
    deployment_id: str,
    body: CancelDeploymentRequest = CancelDeploymentRequest(),
) -> dict[str, Any]:
    """Cancel a deployment that is *pending* or *in_progress*."""
    try:
        return _update_manager.cancel_deployment(
            deployment_id, reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Group Deployment ─────────────────────────────────────────────────────────


@router.post("/deploy-group")
async def deploy_to_group(body: DeployToGroupRequest) -> dict[str, Any]:
    """Create deployments for all devices in a named group.

    Returns a summary containing the list of created deployments.
    """
    try:
        deployments = _update_manager.deploy_to_group(
            body.firmware_id, body.group_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "firmware_id": body.firmware_id,
        "group_name": body.group_name,
        "deployments_created": len(deployments),
        "deployments": deployments,
    }


# ── Staged Rollouts ──────────────────────────────────────────────────────────


@router.post("/rollouts")
async def create_rollout(body: CreateRolloutRequest) -> dict[str, Any]:
    """Create a new staged rollout."""
    try:
        return _deployment_tracker.create_staged_rollout(
            firmware_id=body.firmware_id,
            device_ids=body.device_ids,
            stages=body.stages,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/rollouts/{rollout_id}")
async def get_rollout(rollout_id: str) -> dict[str, Any]:
    """Retrieve a staged rollout record."""
    rollout = _deployment_tracker.get_rollout(rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail="Rollout not found")
    return rollout


@router.post("/rollouts/{rollout_id}/advance")
async def advance_rollout(rollout_id: str) -> dict[str, Any]:
    """Advance a staged rollout to the next stage."""
    try:
        return _deployment_tracker.advance_stage(rollout_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/rollouts/{rollout_id}/cancel")
async def cancel_rollout(
    rollout_id: str,
    body: CancelRolloutRequest = CancelRolloutRequest(),
) -> dict[str, Any]:
    """Cancel an active staged rollout."""
    try:
        return _deployment_tracker.cancel_rollout(
            rollout_id, reason=body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/rollouts/{rollout_id}/summary")
async def rollout_summary(rollout_id: str) -> dict[str, Any]:
    """Get a human-readable summary of a staged rollout's progress."""
    try:
        return _deployment_tracker.get_rollout_summary(rollout_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ── Statistics ───────────────────────────────────────────────────────────────


@router.get("/stats")
async def deployment_stats() -> dict[str, Any]:
    """Return aggregate deployment statistics."""
    return _update_manager.get_deployment_stats()
