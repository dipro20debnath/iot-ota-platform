"""
PKI API Router
===============

FastAPI router exposing the Public Key Infrastructure endpoints for the
IoT OTA Platform.

Endpoints cover the full certificate lifecycle:

* **Root CA creation** — bootstrap the PKI trust anchor.
* **Intermediate CA creation** — add a subordinate CA for operational
  signing.
* **Device certificate issuance** — bind an identity to an IoT device.
* **Signing certificate issuance** — produce a code-signing certificate
  for firmware packages.
* **Certificate listing & retrieval** — query the certificate inventory.
* **Revocation** — mark a certificate as revoked.
* **Chain inspection & validation** — walk and verify the trust chain.
* **Platform statistics** — aggregate counts across all tables.

All endpoints return JSON and use Pydantic models for request / response
validation.  Certificate operations are backed by
:class:`~app.pki.ca.CertificateAuthority` and persisted via
:class:`~app.db.sqlite_store.SQLiteStore`.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import settings
from app.db.store import get_store
from app.pki.ca import CertificateAuthority
from app.pki.chain_validator import ChainValidator

logger = logging.getLogger(__name__)

# ── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/pki", tags=["PKI"])

# ── Module-level singletons ──────────────────────────────────────────────────

_ca = CertificateAuthority(pki_data_dir=str(settings.PKI_DATA_DIR))
_validator = ChainValidator()


# ══════════════════════════════════════════════════════════════════════════════
# Request / Response models
# ══════════════════════════════════════════════════════════════════════════════


class CreateCARequest(BaseModel):
    """Request body for creating a Root or Intermediate CA.

    Attributes
    ----------
    common_name : str
        Subject Common Name for the CA certificate.
    organization : str
        Subject Organization name.
    country : str
        ISO 3166-1 alpha-2 country code.
    validity_days : int
        Certificate lifetime in days.
    key_size : int
        RSA key size in bits.
    """

    common_name: str = Field(
        default="IoT OTA Root CA",
        min_length=1,
        max_length=256,
        description="Subject Common Name for the CA certificate.",
    )
    organization: str = Field(
        default="IoT OTA Platform",
        min_length=1,
        max_length=256,
        description="Subject Organization name.",
    )
    country: str = Field(
        default="US",
        min_length=2,
        max_length=2,
        description="ISO 3166-1 alpha-2 country code.",
    )
    validity_days: int = Field(
        default=3650,
        gt=0,
        le=36500,
        description="Certificate lifetime in days.",
    )
    key_size: int = Field(
        default=4096,
        ge=2048,
        le=8192,
        description="RSA key size in bits.",
    )


class IssueCertRequest(BaseModel):
    """Request body for issuing a device or signing certificate.

    Attributes
    ----------
    device_id : str
        Unique identifier of the IoT device.
    common_name : str
        Subject Common Name for the certificate.
    key_size : int
        RSA key size in bits.
    validity_days : int
        Certificate lifetime in days.
    """

    device_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Unique identifier of the IoT device.",
    )
    common_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Subject Common Name for the certificate.",
    )
    key_size: int = Field(
        default=2048,
        ge=2048,
        le=8192,
        description="RSA key size in bits.",
    )
    validity_days: int = Field(
        default=365,
        gt=0,
        le=36500,
        description="Certificate lifetime in days.",
    )


class RevokeCertRequest(BaseModel):
    """Request body for revoking a certificate.

    Attributes
    ----------
    serial_number : str
        Hex-encoded serial number of the certificate to revoke.
    reason : str
        Human-readable revocation reason.
    """

    serial_number: str = Field(
        ...,
        min_length=1,
        description="Hex-encoded serial number of the certificate to revoke.",
    )
    reason: str = Field(
        default="unspecified",
        max_length=512,
        description="Revocation reason.",
    )


class CertResponse(BaseModel):
    """Response model for certificate data.

    Attributes
    ----------
    cert_id : str
        Platform-internal certificate identifier.
    serial_number : str
        Hex-encoded X.509 serial number.
    subject_cn : str
        Subject Common Name.
    issuer_cn : str
        Issuer Common Name.
    cert_type : str
        Certificate type (``'root_ca'``, ``'intermediate_ca'``,
        ``'device'``, ``'signing'``).
    status : str
        Lifecycle status.
    not_before : str
        Validity start (ISO 8601).
    not_after : str
        Validity end (ISO 8601).
    fingerprint_sha256 : str
        SHA-256 fingerprint of the DER-encoded certificate.
    pem : str or None
        PEM-encoded certificate data (included only when explicitly
        requested).
    """

    cert_id: str
    serial_number: str
    subject_cn: str
    issuer_cn: str
    cert_type: str
    status: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    pem: Optional[str] = None


class ChainValidationRequest(BaseModel):
    """Request body for chain validation.

    Attributes
    ----------
    serial_numbers : list[str]
        Ordered list of hex-encoded serial numbers from **leaf to root**.
    """

    serial_numbers: list[str] = Field(
        ...,
        min_length=1,
        description="Ordered serial numbers from leaf to root.",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ══════════════════════════════════════════════════════════════════════════════


def _cert_to_db_record(
    cert: x509.Certificate,
    cert_type: str,
    parent_cert_id: Optional[str] = None,
) -> dict:
    """Convert an X.509 certificate object into a database record dict.

    Args:
        cert: The X.509 certificate.
        cert_type: Type label (``'root_ca'``, ``'intermediate_ca'``,
            ``'device'``, ``'signing'``).
        parent_cert_id: ``cert_id`` of the issuing certificate, or
            ``None`` for self-signed roots.

    Returns
    -------
    dict
        A dictionary ready to be passed to
        :meth:`~app.db.sqlite_store.SQLiteStore.save_cert`.
    """
    subject_cn = _extract_cn(cert.subject) or ""
    issuer_cn = _extract_cn(cert.issuer) or ""
    serial_hex = format(cert.serial_number, "X")

    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = ":".join(f"{b:02X}" for b in hashlib.sha256(der_bytes).digest())

    pem_data = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Determine algorithm label from key size
    pub_key = cert.public_key()
    key_size = getattr(pub_key, "key_size", 0)
    algorithm = f"rsa_{key_size}"

    return {
        "cert_id": str(uuid4()),
        "serial_number": serial_hex,
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "cert_type": cert_type,
        "status": "active",
        "algorithm": algorithm,
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": fingerprint,
        "parent_cert_id": parent_cert_id,
        "pem_data": pem_data,
    }


def _db_record_to_response(record: dict, include_pem: bool = False) -> CertResponse:
    """Convert a database certificate record to a :class:`CertResponse`.

    Args:
        record: A row from the ``certificates`` table.
        include_pem: Whether to include the full PEM data.

    Returns
    -------
    CertResponse
        Serialisable response object.
    """
    return CertResponse(
        cert_id=record["cert_id"],
        serial_number=record["serial_number"],
        subject_cn=record["subject_cn"],
        issuer_cn=record["issuer_cn"],
        cert_type=record["cert_type"],
        status=record["status"],
        not_before=record["not_before"],
        not_after=record["not_after"],
        fingerprint_sha256=record["fingerprint_sha256"],
        pem=record.get("pem_data") if include_pem else None,
    )


def _extract_cn(name: x509.Name) -> Optional[str]:
    """Extract the Common Name from an X.509 Name.

    Args:
        name: X.509 name to inspect.

    Returns
    -------
    str or None
        The CN value, or ``None`` if no CN attribute is present.
    """
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════


# ── 1. Root CA ───────────────────────────────────────────────────────────────


@router.post("/ca/root", response_model=CertResponse, status_code=201)
async def create_root_ca(req: CreateCARequest) -> CertResponse:
    """Create a new self-signed Root Certificate Authority.

    Generates an RSA key pair, builds a self-signed X.509 v3 certificate
    with CA extensions, persists it to disk **and** to the database, and
    registers it as a trusted root in the chain validator.

    Returns
    -------
    CertResponse
        Metadata of the newly created Root CA certificate.

    Raises
    ------
    HTTPException 409
        If a Root CA already exists.
    HTTPException 500
        On unexpected internal errors.
    """
    store = get_store()

    # Guard: only one root CA allowed
    existing_roots = store.list_certs(cert_type="root_ca", status="active")
    if existing_roots:
        raise HTTPException(
            status_code=409,
            detail="A Root CA already exists. Revoke or remove it before creating a new one.",
        )

    try:
        cert, _key = _ca.create_root_ca(
            common_name=req.common_name,
            organization=req.organization,
            country=req.country,
            validity_days=req.validity_days,
            key_size=req.key_size,
        )

        record = _cert_to_db_record(cert, cert_type="root_ca")
        saved = store.save_cert(record)

        # Register as trusted root for chain validation
        _validator.add_trusted_root(cert)

        logger.info("Root CA created and stored – cert_id=%s", saved["cert_id"])
        return _db_record_to_response(saved, include_pem=True)

    except Exception as exc:
        logger.exception("Failed to create Root CA: %s", exc)
        raise HTTPException(status_code=500, detail=f"Root CA creation failed: {exc}") from exc


# ── 2. Intermediate CA ───────────────────────────────────────────────────────


@router.post("/ca/intermediate", response_model=CertResponse, status_code=201)
async def create_intermediate_ca(req: CreateCARequest) -> CertResponse:
    """Create an Intermediate CA signed by the existing Root CA.

    The Root CA **must** already exist.  The Intermediate CA receives
    ``BasicConstraints(ca=True, path_length=0)`` so it can sign leaf
    certificates but not further subordinate CAs.

    Returns
    -------
    CertResponse
        Metadata of the newly created Intermediate CA certificate.

    Raises
    ------
    HTTPException 400
        If no Root CA exists.
    HTTPException 409
        If an active Intermediate CA already exists.
    HTTPException 500
        On unexpected internal errors.
    """
    store = get_store()

    # Guard: root must exist
    root_records = store.list_certs(cert_type="root_ca", status="active")
    if not root_records:
        raise HTTPException(
            status_code=400,
            detail="No active Root CA found. Create a Root CA first.",
        )

    # Guard: only one intermediate
    existing_intermediates = store.list_certs(cert_type="intermediate_ca", status="active")
    if existing_intermediates:
        raise HTTPException(
            status_code=409,
            detail="An active Intermediate CA already exists.",
        )

    try:
        cert, _key = _ca.create_intermediate_ca(
            common_name=req.common_name,
            organization=req.organization,
            country=req.country,
            validity_days=req.validity_days,
            key_size=req.key_size,
        )

        root_cert_id = root_records[0]["cert_id"]
        record = _cert_to_db_record(cert, cert_type="intermediate_ca", parent_cert_id=root_cert_id)
        saved = store.save_cert(record)

        logger.info("Intermediate CA created – cert_id=%s", saved["cert_id"])
        return _db_record_to_response(saved, include_pem=True)

    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create Intermediate CA: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Intermediate CA creation failed: {exc}",
        ) from exc


# ── 3. Device certificate ────────────────────────────────────────────────────


@router.post("/certificates/device", response_model=CertResponse, status_code=201)
async def issue_device_certificate(req: IssueCertRequest) -> CertResponse:
    """Issue an end-entity certificate for an IoT device.

    The certificate is signed by the Intermediate CA when available,
    otherwise by the Root CA directly.

    Returns
    -------
    CertResponse
        Metadata of the newly issued device certificate.

    Raises
    ------
    HTTPException 400
        If no CA is available for signing.
    HTTPException 500
        On unexpected internal errors.
    """
    store = get_store()

    try:
        cert, _key = _ca.issue_device_certificate(
            device_id=req.device_id,
            common_name=req.common_name,
            key_size=req.key_size,
            validity_days=req.validity_days,
        )

        # Determine parent cert_id
        parent_cert_id: Optional[str] = None
        intermediate_records = store.list_certs(cert_type="intermediate_ca", status="active")
        if intermediate_records:
            parent_cert_id = intermediate_records[0]["cert_id"]
        else:
            root_records = store.list_certs(cert_type="root_ca", status="active")
            if root_records:
                parent_cert_id = root_records[0]["cert_id"]

        record = _cert_to_db_record(cert, cert_type="device", parent_cert_id=parent_cert_id)
        saved = store.save_cert(record)

        logger.info("Device certificate issued – cert_id=%s, device_id=%s", saved["cert_id"], req.device_id)
        return _db_record_to_response(saved, include_pem=True)

    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to issue device certificate: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Device certificate issuance failed: {exc}",
        ) from exc


# ── 4. Signing certificate ───────────────────────────────────────────────────


@router.post("/certificates/signing", response_model=CertResponse, status_code=201)
async def issue_signing_certificate(req: IssueCertRequest) -> CertResponse:
    """Issue a code-signing certificate for firmware packages.

    The certificate carries ``ExtendedKeyUsage(CODE_SIGNING)`` and is
    signed by the best available CA.

    Returns
    -------
    CertResponse
        Metadata of the newly issued signing certificate.

    Raises
    ------
    HTTPException 400
        If no CA is available.
    HTTPException 500
        On unexpected internal errors.
    """
    store = get_store()

    try:
        cert, _key = _ca.issue_signing_certificate(
            common_name=req.common_name,
            key_size=req.key_size,
            validity_days=req.validity_days,
        )

        # Determine parent cert_id
        parent_cert_id: Optional[str] = None
        intermediate_records = store.list_certs(cert_type="intermediate_ca", status="active")
        if intermediate_records:
            parent_cert_id = intermediate_records[0]["cert_id"]
        else:
            root_records = store.list_certs(cert_type="root_ca", status="active")
            if root_records:
                parent_cert_id = root_records[0]["cert_id"]

        record = _cert_to_db_record(cert, cert_type="signing", parent_cert_id=parent_cert_id)
        saved = store.save_cert(record)

        logger.info("Signing certificate issued – cert_id=%s", saved["cert_id"])
        return _db_record_to_response(saved, include_pem=True)

    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to issue signing certificate: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Signing certificate issuance failed: {exc}",
        ) from exc


# ── 5. List certificates ─────────────────────────────────────────────────────


@router.get("/certificates", response_model=list[CertResponse])
async def list_certificates(
    cert_type: Optional[str] = Query(
        default=None,
        description="Filter by certificate type (root_ca, intermediate_ca, device, signing).",
    ),
    status: Optional[str] = Query(
        default=None,
        description="Filter by status (active, revoked, expired).",
    ),
) -> list[CertResponse]:
    """List all certificates with optional type and status filters.

    Returns
    -------
    list[CertResponse]
        All matching certificate records (PEM data excluded for brevity).
    """
    store = get_store()
    records = store.list_certs(cert_type=cert_type, status=status)
    return [_db_record_to_response(r) for r in records]


# ── 6. Get certificate by ID ─────────────────────────────────────────────────


@router.get("/certificates/{cert_id}", response_model=CertResponse)
async def get_certificate(cert_id: str) -> CertResponse:
    """Retrieve a single certificate by its platform ``cert_id``.

    The response includes the full PEM-encoded certificate data.

    Raises
    ------
    HTTPException 404
        If no certificate with the given ID exists.
    """
    store = get_store()
    record = store.get_cert(cert_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Certificate not found: {cert_id}")
    return _db_record_to_response(record, include_pem=True)


# ── 7. Revoke certificate ────────────────────────────────────────────────────


@router.post("/certificates/revoke", response_model=CertResponse)
async def revoke_certificate(req: RevokeCertRequest) -> CertResponse:
    """Revoke a certificate by its serial number.

    Updates the certificate status to ``'revoked'`` in the database and
    adds the serial to the chain validator's revocation list.

    Returns
    -------
    CertResponse
        The updated certificate record.

    Raises
    ------
    HTTPException 404
        If no certificate with the given serial number exists.
    HTTPException 400
        If the certificate is already revoked.
    """
    store = get_store()

    record = store.get_cert_by_serial(req.serial_number)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Certificate not found with serial: {req.serial_number}",
        )

    if record["status"] == "revoked":
        raise HTTPException(
            status_code=400,
            detail="Certificate is already revoked.",
        )

    # Update DB
    store.update_cert_status(
        cert_id=record["cert_id"],
        status="revoked",
        revocation_reason=req.reason,
    )

    # Also revoke in the CA's in-memory list and the chain validator
    try:
        pem_data = record["pem_data"].encode("utf-8")
        cert_obj = x509.load_pem_x509_certificate(pem_data, default_backend())
        _ca.revoke_certificate(cert_obj, reason=req.reason)
        _validator.add_revoked_serial(req.serial_number)
    except Exception as exc:
        logger.warning("Could not add serial to in-memory revocation lists: %s", exc)

    # Fetch updated record
    updated = store.get_cert(record["cert_id"])
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to retrieve updated certificate.")

    logger.info("Certificate revoked – serial=%s, reason=%s", req.serial_number, req.reason)
    return _db_record_to_response(updated, include_pem=False)


# ── 8. Certificate chain ─────────────────────────────────────────────────────


@router.get("/certificates/{cert_id}/chain")
async def get_certificate_chain(cert_id: str) -> dict:
    """Walk the certificate chain from a leaf certificate up to the root.

    Follows ``parent_cert_id`` links in the database to reconstruct the
    full chain.

    Returns
    -------
    dict
        A dictionary with ``chain_length`` and a ``chain`` list of
        certificate summaries ordered from leaf to root.

    Raises
    ------
    HTTPException 404
        If the starting certificate is not found.
    """
    store = get_store()

    chain: list[dict] = []
    current_id: Optional[str] = cert_id

    while current_id is not None:
        record = store.get_cert(current_id)
        if record is None:
            if not chain:
                raise HTTPException(
                    status_code=404,
                    detail=f"Certificate not found: {cert_id}",
                )
            break  # Parent not in DB — chain ends here

        chain.append({
            "cert_id": record["cert_id"],
            "serial_number": record["serial_number"],
            "subject_cn": record["subject_cn"],
            "issuer_cn": record["issuer_cn"],
            "cert_type": record["cert_type"],
            "status": record["status"],
            "not_before": record["not_before"],
            "not_after": record["not_after"],
        })
        current_id = record.get("parent_cert_id")

    return {
        "chain_length": len(chain),
        "chain": chain,
    }


# ── 9. Validate chain ────────────────────────────────────────────────────────


@router.post("/certificates/validate-chain")
async def validate_certificate_chain(req: ChainValidationRequest) -> dict:
    """Validate a certificate chain given as an ordered list of serial numbers.

    Loads each certificate from the database, parses PEM data into
    :class:`~cryptography.x509.Certificate` objects, and delegates to
    :class:`~app.pki.chain_validator.ChainValidator` for full
    cryptographic chain validation.

    Returns
    -------
    dict
        Validation result containing ``valid``, ``errors``,
        ``chain_length``, ``leaf_subject``, and ``root_issuer``.

    Raises
    ------
    HTTPException 400
        If any serial number cannot be found in the database or its PEM
        data cannot be parsed.
    """
    store = get_store()
    cert_chain: list[x509.Certificate] = []

    for serial in req.serial_numbers:
        record = store.get_cert_by_serial(serial)
        if record is None:
            raise HTTPException(
                status_code=400,
                detail=f"Certificate not found for serial: {serial}",
            )
        try:
            pem_bytes = record["pem_data"].encode("utf-8")
            cert_obj = x509.load_pem_x509_certificate(pem_bytes, default_backend())
            cert_chain.append(cert_obj)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to parse PEM for serial {serial}: {exc}",
            ) from exc

    result = _validator.validate_chain(cert_chain)
    return result


# ── 10. Platform statistics ──────────────────────────────────────────────────


@router.get("/stats")
async def get_platform_stats() -> dict:
    """Return aggregate platform statistics.

    Returns
    -------
    dict
        Counts of certificates (total / active / revoked), devices,
        firmware images, and deployments (total / pending).
    """
    store = get_store()
    return store.get_stats()
