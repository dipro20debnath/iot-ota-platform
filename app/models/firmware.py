"""
Firmware Models
===============

Pydantic schemas for firmware versioning, metadata, and the signed
manifest that devices use to verify authenticity before applying an update.

Firmware lifecycle managed by :class:`FirmwareStatus`:

    DRAFT → SIGNED → PUBLISHED → DEPRECATED
                                ↘ RECALLED
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class FirmwareStatus(StrEnum):
    """Publishing lifecycle of a firmware version.

    Members
    -------
    DRAFT
        Firmware binary has been uploaded but not yet signed.
    SIGNED
        Firmware has been cryptographically signed but not published.
    PUBLISHED
        Firmware is available for OTA delivery to devices.
    DEPRECATED
        Firmware is superseded; devices should upgrade away from it.
    RECALLED
        Firmware has been pulled due to a critical defect or vulnerability.
    """

    DRAFT = "draft"
    SIGNED = "signed"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    RECALLED = "recalled"


# ── Models ───────────────────────────────────────────────────────────────────


class FirmwareVersion(BaseModel):
    """Complete metadata record for a single firmware release.

    This model captures everything about a firmware binary *except* the
    binary itself, which lives on disk under ``FIRMWARE_STORE_DIR``.

    Attributes
    ----------
    firmware_id : UUID
        Globally unique firmware identifier (auto-generated).
    version : str
        Semantic version string (e.g. ``"1.2.3"``).
    name : str
        Human-readable firmware name / title.
    description : str
        Longer description of the firmware release.
    file_hash_sha256 : str | None
        SHA-256 hex-digest of the firmware binary.
    file_size_bytes : int | None
        Size of the firmware binary in bytes.
    signature : str | None
        Base-64-encoded cryptographic signature of the binary hash.
    signer_cert_id : str | None
        Certificate ID of the key used to sign this firmware.
    status : FirmwareStatus
        Current publishing lifecycle status.
    target_device_type : str
        Device type this firmware is intended for (e.g. ``"sensor-v2"``).
    min_version : str | None
        Minimum firmware version required to upgrade from (delta safety).
    release_notes : str
        Markdown-formatted release notes shown to operators.
    created_at : datetime
        UTC timestamp when the firmware record was created.
    published_at : datetime | None
        UTC timestamp when the firmware was published for OTA delivery.
    """

    firmware_id: UUID = Field(default_factory=uuid4, description="Unique firmware identifier.")
    version: str = Field(..., min_length=1, max_length=32, description="Semantic version string.")
    name: str = Field(..., min_length=1, max_length=128, description="Firmware display name.")
    description: str = Field(default="", max_length=1024, description="Firmware description.")
    file_hash_sha256: Optional[str] = Field(default=None, description="SHA-256 hex-digest of the binary.")
    file_size_bytes: Optional[int] = Field(default=None, ge=0, description="Binary size in bytes.")
    signature: Optional[str] = Field(default=None, description="Base-64 encoded cryptographic signature.")
    signer_cert_id: Optional[str] = Field(default=None, description="Signing certificate ID.")
    status: FirmwareStatus = Field(default=FirmwareStatus.DRAFT, description="Publishing lifecycle status.")
    target_device_type: str = Field(
        default="generic", max_length=64, description="Target hardware / product-line type."
    )
    min_version: Optional[str] = Field(
        default=None, max_length=32, description="Minimum version required to upgrade from."
    )
    release_notes: str = Field(default="", max_length=4096, description="Markdown release notes.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of record creation.",
    )
    published_at: Optional[datetime] = Field(default=None, description="UTC timestamp of publication.")


class FirmwareManifest(BaseModel):
    """Signed manifest delivered to a device before an OTA update.

    The device uses the manifest to:

    1. Verify the firmware's integrity via ``file_hash_sha256``.
    2. Authenticate the publisher via ``signature`` and ``signer_certificate``.
    3. Locate the download endpoint via ``download_url``.

    Attributes
    ----------
    firmware_id : UUID
        Reference to the :class:`FirmwareVersion` this manifest describes.
    version : str
        Firmware version string (mirrors ``FirmwareVersion.version``).
    name : str
        Firmware name (mirrors ``FirmwareVersion.name``).
    target_device_type : str
        Device type the firmware targets.
    file_hash_sha256 : str
        SHA-256 hex-digest the device must verify after download.
    file_size_bytes : int
        Expected binary size; used for pre-allocation on constrained devices.
    signature : str
        Base-64-encoded signature over the firmware hash.
    signer_certificate : str
        PEM-encoded X.509 certificate of the signing key.
    manifest_signature : str | None
        Optional signature over the manifest itself for extra integrity.
    created_at : datetime
        UTC timestamp when the manifest was generated.
    download_url : str | None
        URL from which the device should fetch the firmware binary.
    """

    firmware_id: UUID = Field(..., description="Parent FirmwareVersion identifier.")
    version: str = Field(..., min_length=1, max_length=32, description="Firmware version string.")
    name: str = Field(..., min_length=1, max_length=128, description="Firmware display name.")
    target_device_type: str = Field(..., max_length=64, description="Target device type.")
    file_hash_sha256: str = Field(..., description="SHA-256 hex-digest of the binary.")
    file_size_bytes: int = Field(..., ge=0, description="Binary size in bytes.")
    signature: str = Field(..., description="Base-64 encoded firmware signature.")
    signer_certificate: str = Field(..., description="PEM-encoded signer X.509 certificate.")
    manifest_signature: Optional[str] = Field(
        default=None, description="Optional signature over the manifest payload."
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of manifest generation.",
    )
    download_url: Optional[str] = Field(default=None, description="Firmware binary download URL.")
