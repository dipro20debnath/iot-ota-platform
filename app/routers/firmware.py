"""
Firmware API Router
====================

FastAPI router exposing REST endpoints for the firmware lifecycle:

* **Upload** — accept firmware binaries via multipart form upload.
* **List / Detail** — query firmware metadata from the database.
* **Download** — stream firmware binaries to clients.
* **Sign** — cryptographically sign a firmware binary with the platform PKI.
* **Manifest** — generate a JSON manifest for a signed firmware.
* **Publish / Deprecate** — manage firmware lifecycle status.
* **Rollback** — execute version rollbacks with policy enforcement.
* **Upgrade check** — verify whether a version transition is permitted.
* **Storage stats** — aggregate statistics on binary storage usage.

All endpoints are mounted under the ``/api/firmware`` prefix.
"""

from __future__ import annotations

import hashlib
import io
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.db.store import get_store
from app.firmware.rollback import RollbackManager
from app.firmware.storage import FirmwareStorage
from app.firmware.versioning import SemanticVersion, VersionManager
from app.signing.manifest import FirmwareManifest
from app.signing.signer import FirmwareSigner

logger = logging.getLogger(__name__)

# ── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/api/firmware",
    tags=["Firmware"],
)

# ── Module-Level Singletons ─────────────────────────────────────────────────

_firmware_storage: FirmwareStorage = FirmwareStorage(
    store_dir=str(settings.FIRMWARE_STORE_DIR),
    max_size_mb=settings.MAX_FIRMWARE_SIZE_MB,
)

_version_manager: VersionManager = VersionManager(allow_downgrade=False)

_rollback_manager: RollbackManager = RollbackManager(
    storage=_firmware_storage,
    version_manager=_version_manager,
    keep_previous=settings.KEEP_PREVIOUS_VERSIONS,
)

# ── Pydantic Models ─────────────────────────────────────────────────────────


class FirmwareUploadResponse(BaseModel):
    """Response returned after a successful firmware upload."""

    firmware_id: str = Field(..., description="Unique firmware identifier.")
    version: str = Field(..., description="Semantic version string.")
    name: str = Field(..., description="Human-readable firmware name.")
    device_type: str = Field(..., description="Target device type.")
    file_hash_sha256: str = Field(..., description="SHA-256 hash of the binary.")
    file_size_bytes: int = Field(..., description="Size of the binary in bytes.")
    status: str = Field(..., description="Lifecycle status.")
    created_at: str = Field(..., description="ISO 8601 creation timestamp.")


class FirmwareListItem(BaseModel):
    """Abbreviated firmware record for list endpoints."""

    firmware_id: str
    version: str
    name: str
    status: str
    target_device_type: Optional[str] = None
    file_size_bytes: Optional[int] = None
    created_at: Optional[str] = None


class FirmwareDetailResponse(BaseModel):
    """Full firmware record returned by detail endpoints."""

    firmware_id: str
    version: str
    name: str
    description: Optional[str] = None
    file_hash_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    signature: Optional[str] = None
    signer_cert_id: Optional[str] = None
    status: Optional[str] = None
    target_device_type: Optional[str] = None
    min_version: Optional[str] = None
    release_notes: Optional[str] = None
    created_at: Optional[str] = None
    published_at: Optional[str] = None


class SignFirmwareRequest(BaseModel):
    """Request body for signing a firmware binary."""

    firmware_id: str = Field(..., description="ID of the firmware to sign.")


class RollbackRequest(BaseModel):
    """Request body for executing a firmware rollback."""

    firmware_id: str = Field(..., description="Firmware product-line ID.")
    current_version: str = Field(..., description="Currently installed version.")
    target_version: str = Field(..., description="Version to roll back to.")
    device_type: str = Field("generic", description="Device family.")
    device_id: Optional[str] = Field(None, description="Specific device ID.")


class RollbackResponse(BaseModel):
    """Response returned after a rollback operation."""

    success: bool
    rolled_back_from: str
    rolled_back_to: str
    device_id: Optional[str] = None
    timestamp: str


class VersionCheckRequest(BaseModel):
    """Request body for checking an upgrade/downgrade path."""

    firmware_id: str
    current_version: str
    target_version: str


class VersionCheckResponse(BaseModel):
    """Response for version compatibility checks."""

    allowed: bool
    upgrade_type: str
    reason: str
    current: str
    target: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/upload", response_model=FirmwareUploadResponse)
async def upload_firmware(
    file: UploadFile = File(..., description="Firmware binary file."),
    name: str = Form(..., description="Human-readable firmware name."),
    version: str = Form(..., description="Semantic version (e.g. '1.2.3')."),
    device_type: str = Form("generic", description="Target device type."),
    description: str = Form("", description="Firmware description."),
    release_notes: str = Form("", description="Release notes."),
    min_version: Optional[str] = Form(None, description="Minimum required version."),
) -> FirmwareUploadResponse:
    """Upload a new firmware binary.

    Accepts a multipart form upload containing the firmware file and its
    metadata.  The binary is validated, stored on disk via
    :class:`FirmwareStorage`, and its metadata is persisted to the
    database.

    Raises
    ------
    HTTPException 400
        If the version string is not valid semantic versioning or the
        firmware exceeds the size limit.
    HTTPException 409
        If the same firmware version already exists in storage.
    HTTPException 500
        On unexpected internal errors.
    """
    # --- Validate semantic version ---
    if not SemanticVersion.is_valid(version):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid semantic version: '{version}'. "
            "Expected format: MAJOR.MINOR.PATCH[-prerelease][+build]",
        )

    # --- Read file bytes ---
    try:
        firmware_data: bytes = await file.read()
    except Exception as exc:
        logger.error("Failed to read uploaded file: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to read uploaded file.")

    if not firmware_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # --- Generate firmware ID ---
    firmware_id: str = str(uuid4())

    # --- Save to binary storage ---
    try:
        storage_result: dict = _firmware_storage.save_firmware(
            firmware_data=firmware_data,
            firmware_id=firmware_id,
            version=version,
            device_type=device_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except FileExistsError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:
        logger.error("Firmware storage error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to store firmware binary.")

    # --- Persist metadata to DB ---
    try:
        db_record: dict[str, Any] = get_store().save_firmware(
            {
                "firmware_id": firmware_id,
                "version": version,
                "name": name,
                "description": description,
                "file_hash_sha256": storage_result["file_hash_sha256"],
                "file_size_bytes": storage_result["file_size_bytes"],
                "status": "draft",
                "target_device_type": device_type,
                "min_version": min_version,
                "release_notes": release_notes,
            }
        )
    except Exception as exc:
        logger.error("Database error saving firmware metadata: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to save firmware metadata to database."
        )

    # --- Register version ---
    try:
        _version_manager.register_version(firmware_id, version)
    except ValueError:
        pass  # Already validated above

    logger.info(
        "Firmware uploaded – id=%s, version=%s, name=%s",
        firmware_id,
        version,
        name,
    )

    return FirmwareUploadResponse(
        firmware_id=firmware_id,
        version=version,
        name=name,
        device_type=device_type,
        file_hash_sha256=storage_result["file_hash_sha256"],
        file_size_bytes=storage_result["file_size_bytes"],
        status="draft",
        created_at=db_record.get("created_at", datetime.now(timezone.utc).isoformat()),
    )


@router.get("/list", response_model=list[FirmwareListItem])
async def list_firmware(
    status: Optional[str] = Query(None, description="Filter by status."),
    device_type: Optional[str] = Query(None, description="Filter by device type."),
) -> list[FirmwareListItem]:
    """List firmware with optional status and device-type filters.

    Queries the database and returns abbreviated firmware records.
    """
    try:
        records: list[dict[str, Any]] = get_store().list_firmware(
            status=status, device_type=device_type
        )
    except Exception as exc:
        logger.error("Database error listing firmware: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to list firmware.")

    return [
        FirmwareListItem(
            firmware_id=r["firmware_id"],
            version=r["version"],
            name=r["name"],
            status=r.get("status", "draft"),
            target_device_type=r.get("target_device_type"),
            file_size_bytes=r.get("file_size_bytes"),
            created_at=r.get("created_at"),
        )
        for r in records
    ]


@router.get("/rollback-history")
async def rollback_history(
    firmware_id: Optional[str] = Query(None, description="Filter by firmware ID."),
) -> list[dict]:
    """Retrieve the rollback event history.

    Returns all recorded rollback events, optionally filtered by firmware
    ID.  Events are sorted most-recent-first.
    """
    return _rollback_manager.get_rollback_history(firmware_id)


@router.get("/storage-stats")
async def storage_stats() -> dict:
    """Return aggregate storage statistics.

    Provides the total number of stored firmware files, their combined
    size in bytes, and the list of device types encountered.
    """
    try:
        return _firmware_storage.get_storage_stats()
    except Exception as exc:
        logger.error("Error computing storage stats: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve storage statistics."
        )


@router.get("/{firmware_id}", response_model=FirmwareDetailResponse)
async def get_firmware_details(firmware_id: str) -> FirmwareDetailResponse:
    """Get detailed metadata for a specific firmware ID.

    Raises
    ------
    HTTPException 404
        If no firmware record matches the given ID.
    """
    record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Firmware '{firmware_id}' not found.",
        )

    return FirmwareDetailResponse(**record)


@router.get("/{firmware_id}/download")
async def download_firmware(firmware_id: str) -> StreamingResponse:
    """Download a firmware binary as an octet-stream.

    The response includes a ``Content-Disposition`` header so that
    clients save the file with a meaningful name.

    Raises
    ------
    HTTPException 404
        If the firmware ID is not found in the database or the binary
        is missing from storage.
    """
    record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"Firmware '{firmware_id}' not found."
        )

    version: str = record["version"]
    device_type: str = record.get("target_device_type", "generic")

    firmware_data: bytes | None = _firmware_storage.get_firmware(
        firmware_id, version, device_type
    )
    if firmware_data is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Firmware binary for '{firmware_id}' v{version} not found "
                "in storage."
            ),
        )

    filename: str = f"{record.get('name', firmware_id)}-{version}.bin"

    return StreamingResponse(
        content=io.BytesIO(firmware_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{firmware_id}/manifest")
async def get_firmware_manifest(firmware_id: str) -> dict:
    """Generate and return a JSON manifest for a firmware binary.

    The firmware must be in ``'signed'`` or ``'published'`` status.

    Raises
    ------
    HTTPException 404
        If the firmware ID is not found.
    HTTPException 400
        If the firmware has not been signed yet.
    """
    record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"Firmware '{firmware_id}' not found."
        )

    status: str = record.get("status", "draft")
    if status not in ("signed", "published"):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Firmware must be 'signed' or 'published' to generate a "
                f"manifest.  Current status: '{status}'."
            ),
        )

    # Build manifest from stored metadata (no re-signing needed)
    manifest: dict[str, Any] = {
        "manifest_version": "1.0",
        "firmware_id": firmware_id,
        "version": record["version"],
        "name": record["name"],
        "target_device_type": record.get("target_device_type", "generic"),
        "file_hash_sha256": record.get("file_hash_sha256"),
        "file_size_bytes": record.get("file_size_bytes"),
        "signature": record.get("signature"),
        "signing_algorithm": "RSA-PSS",
        "signer_cert_id": record.get("signer_cert_id"),
        "release_notes": record.get("release_notes", ""),
        "min_version": record.get("min_version"),
        "status": status,
        "created_at": record.get("created_at"),
        "published_at": record.get("published_at"),
    }

    # Compute manifest hash for integrity
    import json

    hashable: dict[str, Any] = {
        k: v for k, v in manifest.items() if k != "manifest_hash"
    }
    canonical: str = json.dumps(hashable, sort_keys=True)
    manifest["manifest_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return manifest


@router.post("/sign")
async def sign_firmware(request: SignFirmwareRequest) -> dict:
    """Cryptographically sign a firmware binary.

    Loads the signing certificate and private key from the platform PKI,
    signs the firmware binary, and updates the database record with the
    digital signature and ``'signed'`` status.

    Raises
    ------
    HTTPException 404
        If the firmware ID is not found.
    HTTPException 400
        If the PKI infrastructure is not initialised (no signing cert).
    HTTPException 500
        On unexpected signing errors.
    """
    record: dict[str, Any] | None = get_store().get_firmware(request.firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Firmware '{request.firmware_id}' not found.",
        )

    version: str = record["version"]
    device_type: str = record.get("target_device_type", "generic")

    # --- Load firmware binary ---
    firmware_data: bytes | None = _firmware_storage.get_firmware(
        request.firmware_id, version, device_type
    )
    if firmware_data is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Firmware binary for '{request.firmware_id}' v{version} "
                "not found in storage."
            ),
        )

    # --- Load signing cert & key from PKI ---
    try:
        from app.pki.ca import CertificateAuthority
        from app.pki.key_manager import KeyManager

        pki_dir = str(settings.PKI_DATA_DIR)
        km = KeyManager(pki_dir)
        ca = CertificateAuthority(pki_dir, key_manager=km)

        signing_cert_path = settings.PKI_DATA_DIR / "certs" / "signing_cert.pem"
        signing_key_path = settings.PKI_DATA_DIR / "keys" / "signing_key.pem"

        if not signing_cert_path.exists() or not signing_key_path.exists():
            raise HTTPException(
                status_code=400,
                detail=(
                    "Signing certificate or key not found.  Please create a "
                    "Root CA and issue a signing certificate via the PKI "
                    "endpoints first (POST /api/pki/ca/root, then "
                    "POST /api/pki/certificates/signing)."
                ),
            )

        signing_cert = ca.load_certificate(str(signing_cert_path))
        signing_key = km.load_private_key(str(signing_key_path))
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to load signing credentials: %s", exc)
        raise HTTPException(
            status_code=400,
            detail=(
                f"Failed to load signing credentials: {exc}.  "
                "Ensure PKI infrastructure is initialised."
            ),
        )

    # --- Sign the firmware ---
    try:
        signer = FirmwareSigner()
        signer.load_signing_key(signing_key)
        signer.load_signing_certificate(signing_cert)
        sign_result: dict = signer.sign_firmware(firmware_data)
    except Exception as exc:
        logger.error("Firmware signing failed: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Firmware signing failed: {exc}"
        )

    # --- Generate manifest (for the manifest hash) ---
    try:
        manifest_mgr = FirmwareManifest()
        manifest_mgr.set_signer(signer)
        manifest: dict = manifest_mgr.generate_manifest(
            firmware_data=firmware_data,
            version=version,
            name=record["name"],
            target_device_type=device_type,
            release_notes=record.get("release_notes", ""),
            min_version=record.get("min_version"),
            firmware_id=request.firmware_id,
        )
    except Exception as exc:
        logger.error("Manifest generation failed: %s", exc)
        # Non-fatal — signing still succeeded
        manifest = {}

    # --- Update DB ---
    store = get_store()
    # Update status to 'signed'
    store.update_firmware_status(request.firmware_id, "signed")

    # Store signature in DB via raw SQL update
    try:
        conn = store._get_connection()
        conn.execute(
            "UPDATE firmware SET signature = ?, signer_cert_id = ? "
            "WHERE firmware_id = ?",
            (
                sign_result["signature"],
                sign_result.get("signer_fingerprint"),
                request.firmware_id,
            ),
        )
        conn.commit()
    except Exception as exc:
        logger.error("Failed to update firmware signature in DB: %s", exc)

    # --- Return updated record ---
    updated_record: dict[str, Any] | None = store.get_firmware(request.firmware_id)
    if updated_record is None:
        updated_record = dict(record)
        updated_record["status"] = "signed"
        updated_record["signature"] = sign_result["signature"]

    return updated_record


@router.post("/publish/{firmware_id}")
async def publish_firmware(firmware_id: str) -> dict:
    """Publish a firmware version, making it available for OTA distribution.

    Sets the firmware status to ``'published'`` and records the
    publication timestamp.

    Raises
    ------
    HTTPException 404
        If the firmware ID is not found.
    """
    record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"Firmware '{firmware_id}' not found."
        )

    updated: bool = get_store().update_firmware_status(firmware_id, "published")
    if not updated:
        raise HTTPException(
            status_code=500, detail="Failed to update firmware status."
        )

    updated_record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    return updated_record or {**record, "status": "published"}


@router.post("/rollback", response_model=RollbackResponse)
async def execute_rollback(request: RollbackRequest) -> RollbackResponse:
    """Execute a firmware rollback operation.

    Validates the rollback eligibility and, if permitted, records the
    rollback event.

    Raises
    ------
    HTTPException 400
        If the rollback is not permitted (e.g. target version does not
        exist or is not a downgrade).
    """
    result: dict = _rollback_manager.execute_rollback(
        firmware_id=request.firmware_id,
        current_version=request.current_version,
        target_version=request.target_version,
        device_type=request.device_type,
        device_id=request.device_id,
    )

    if not result["success"]:
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Rollback failed."),
        )

    return RollbackResponse(
        success=True,
        rolled_back_from=result["rolled_back_from"],
        rolled_back_to=result["rolled_back_to"],
        device_id=result.get("device_id"),
        timestamp=result["timestamp"],
    )


@router.post("/check-upgrade", response_model=VersionCheckResponse)
async def check_upgrade(request: VersionCheckRequest) -> VersionCheckResponse:
    """Check whether a version transition is permitted.

    Uses the platform's :class:`VersionManager` to evaluate upgrade /
    downgrade policies.

    Raises
    ------
    HTTPException 400
        If either version string is not a valid semantic version.
    """
    try:
        result: dict = _version_manager.check_upgrade_policy(
            firmware_id=request.firmware_id,
            current_version=request.current_version,
            target_version=request.target_version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return VersionCheckResponse(
        allowed=result["allowed"],
        upgrade_type=result["upgrade_type"],
        reason=result["reason"],
        current=result["current"],
        target=result["target"],
    )


@router.post("/deprecate/{firmware_id}")
async def deprecate_firmware(firmware_id: str) -> dict:
    """Deprecate a firmware version.

    Sets the firmware status to ``'deprecated'``, indicating that it
    should no longer be deployed to new devices.

    Raises
    ------
    HTTPException 404
        If the firmware ID is not found.
    """
    record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    if record is None:
        raise HTTPException(
            status_code=404, detail=f"Firmware '{firmware_id}' not found."
        )

    updated: bool = get_store().update_firmware_status(firmware_id, "deprecated")
    if not updated:
        raise HTTPException(
            status_code=500, detail="Failed to deprecate firmware."
        )

    updated_record: dict[str, Any] | None = get_store().get_firmware(firmware_id)
    return updated_record or {**record, "status": "deprecated"}
