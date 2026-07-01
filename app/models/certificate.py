"""
Certificate & Key-Pair Models
==============================

Pydantic schemas for X.509 certificate metadata and asymmetric key-pair
information used by the platform's Public Key Infrastructure (PKI).

The PKI hierarchy typically looks like::

    Root CA (self-signed, RSA-4096)
      └── Signing Key (issues firmware signatures)
      └── Device Certificate (per-device identity)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class CertificateType(StrEnum):
    """Role a certificate plays within the PKI hierarchy.

    Members
    -------
    ROOT_CA
        Self-signed root Certificate Authority.
    INTERMEDIATE_CA
        CA signed by the root, used to limit blast-radius of key compromise.
    DEVICE
        End-entity certificate bound to a single IoT device.
    SIGNING
        Certificate whose private key is used to sign firmware binaries.
    """

    ROOT_CA = "root_ca"
    INTERMEDIATE_CA = "intermediate_ca"
    DEVICE = "device"
    SIGNING = "signing"


class CertificateStatus(StrEnum):
    """Lifecycle status of an X.509 certificate.

    Members
    -------
    ACTIVE
        Certificate is within its validity window and has not been revoked.
    EXPIRED
        Certificate's ``notAfter`` date has passed.
    REVOKED
        Certificate has been explicitly revoked (e.g. key compromise).
    PENDING
        Certificate Signing Request (CSR) has been submitted but not yet
        approved and issued.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


class KeyAlgorithm(StrEnum):
    """Asymmetric key algorithm and size used for key generation.

    Members
    -------
    RSA_2048
        RSA with a 2048-bit modulus.
    RSA_4096
        RSA with a 4096-bit modulus (recommended for CA keys).
    ECDSA_P256
        Elliptic Curve DSA on the NIST P-256 curve.
    ECDSA_P384
        Elliptic Curve DSA on the NIST P-384 curve.
    """

    RSA_2048 = "rsa_2048"
    RSA_4096 = "rsa_4096"
    ECDSA_P256 = "ecdsa_p256"
    ECDSA_P384 = "ecdsa_p384"


# ── Models ───────────────────────────────────────────────────────────────────


class CertificateInfo(BaseModel):
    """Metadata record for an X.509 certificate managed by the platform.

    This model does **not** store the raw PEM data — that lives on disk
    under ``PKI_DATA_DIR``.  It stores only the searchable / displayable
    metadata.

    Attributes
    ----------
    cert_id : UUID
        Platform-internal unique certificate identifier.
    serial_number : str
        Certificate serial number (hex string as issued by the CA).
    subject_cn : str
        Subject Common Name (e.g. ``"iot-device-00af"``).
    issuer_cn : str
        Issuer Common Name (e.g. ``"IoT OTA Root CA"``).
    cert_type : CertificateType
        Role within the PKI hierarchy.
    status : CertificateStatus
        Current lifecycle status.
    algorithm : KeyAlgorithm
        Key algorithm used by the certificate's public key.
    not_before : datetime
        Start of the certificate's validity window (UTC).
    not_after : datetime
        End of the certificate's validity window (UTC).
    fingerprint_sha256 : str
        SHA-256 fingerprint of the DER-encoded certificate.
    parent_cert_id : str | None
        ``cert_id`` of the issuing certificate (``None`` for self-signed).
    revoked_at : datetime | None
        UTC timestamp of revocation, if applicable.
    revocation_reason : str | None
        Human-readable reason for revocation.
    created_at : datetime
        UTC timestamp when this record was created on the platform.
    """

    cert_id: UUID = Field(default_factory=uuid4, description="Platform-internal certificate ID.")
    serial_number: str = Field(..., description="Certificate serial number (hex).")
    subject_cn: str = Field(..., min_length=1, max_length=256, description="Subject Common Name.")
    issuer_cn: str = Field(..., min_length=1, max_length=256, description="Issuer Common Name.")
    cert_type: CertificateType = Field(..., description="Role within the PKI hierarchy.")
    status: CertificateStatus = Field(
        default=CertificateStatus.ACTIVE, description="Certificate lifecycle status."
    )
    algorithm: KeyAlgorithm = Field(..., description="Public-key algorithm.")
    not_before: datetime = Field(..., description="Validity start (UTC).")
    not_after: datetime = Field(..., description="Validity end (UTC).")
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint of DER-encoded cert.")
    parent_cert_id: Optional[str] = Field(
        default=None, description="Issuing certificate's cert_id (None for self-signed roots)."
    )
    revoked_at: Optional[datetime] = Field(default=None, description="UTC revocation timestamp.")
    revocation_reason: Optional[str] = Field(
        default=None, max_length=512, description="Revocation reason."
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of record creation.",
    )


class KeyPairInfo(BaseModel):
    """Metadata record for an asymmetric key-pair stored by the platform.

    Private key material is **never** serialised into this model — it
    exists only on disk (ideally in an HSM-backed store).

    Attributes
    ----------
    key_id : UUID
        Platform-internal unique key identifier.
    algorithm : KeyAlgorithm
        Key algorithm (e.g. RSA-4096 or ECDSA-P256).
    key_size : int
        Key size in bits (e.g. 2048, 4096 for RSA; 256, 384 for EC).
    cert_id : str | None
        Identifier of the certificate bound to this key-pair.
    fingerprint : str
        SHA-256 fingerprint of the public key.
    created_at : datetime
        UTC timestamp when the key-pair was generated.
    """

    key_id: UUID = Field(default_factory=uuid4, description="Unique key-pair identifier.")
    algorithm: KeyAlgorithm = Field(..., description="Key algorithm.")
    key_size: int = Field(..., gt=0, description="Key size in bits.")
    cert_id: Optional[str] = Field(default=None, description="Bound certificate ID.")
    fingerprint: str = Field(..., description="SHA-256 fingerprint of the public key.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of key generation.",
    )
