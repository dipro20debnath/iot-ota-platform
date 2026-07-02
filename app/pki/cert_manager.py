"""
Certificate Manager Module for IoT OTA Firmware Update Platform.

Provides certificate storage, lookup, lifecycle tracking, and metadata
extraction utilities.  Acts as an in-memory registry of X.509 certificates
with optional PEM export and expiry monitoring.

Usage::

    from app.pki.cert_manager import CertificateManager

    cm = CertificateManager(pki_data_dir="./pki_data")
    info = cm.register_certificate(cert, cert_type="device")
    expiry = cm.check_expiry(cert)
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

# Number of days before expiry to flag a certificate as "expiring soon".
_EXPIRY_WARNING_DAYS: int = 30


class CertificateManager:
    """Manages certificate storage, lookup, and lifecycle tracking.

    Maintains an in-memory registry keyed by serial number (hex) that
    stores metadata extracted from :class:`~cryptography.x509.Certificate`
    objects.  Also supports PEM export, fingerprinting, and expiry
    checking.

    Attributes:
        certs_dir: Filesystem path where certificate PEM files are stored.
    """

    def __init__(self, pki_data_dir: str = "./pki_data") -> None:
        """Initialise the CertificateManager.

        Args:
            pki_data_dir: Root directory for PKI artefacts.  A ``certs``
                subdirectory is created inside it automatically.
        """
        self.certs_dir: Path = Path(pki_data_dir) / "certs"
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        # Internal registry: serial_number (hex str) → cert info dict
        self._certificates: dict[str, dict] = {}

        logger.info(
            "CertificateManager initialised – certs directory: %s",
            self.certs_dir,
        )

    # ------------------------------------------------------------------
    # Registration and lookup
    # ------------------------------------------------------------------

    def register_certificate(
        self,
        cert: x509.Certificate,
        cert_type: str = "device",
    ) -> dict:
        """Register a certificate in the manager's registry.

        Extracts metadata (subject, issuer, validity window, CA status,
        fingerprint) from the certificate and stores it keyed by the
        hex-encoded serial number.

        Args:
            cert: The X.509 certificate to register.
            cert_type: A label describing the certificate's role
                (e.g. ``'root_ca'``, ``'intermediate_ca'``, ``'device'``,
                ``'signing'``).

        Returns:
            The certificate info dict that was stored in the registry.
        """
        serial_hex: str = format(cert.serial_number, "X")

        # Extract Common Names
        subject_cn = self._extract_cn(cert.subject)
        issuer_cn = self._extract_cn(cert.issuer)

        # Determine CA status via BasicConstraints
        is_ca = self._is_ca(cert)

        fingerprint = self.get_certificate_fingerprint(cert)

        cert_info: dict = {
            "serial_number": serial_hex,
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "cert_type": cert_type,
            "status": "active",
            "is_ca": is_ca,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": fingerprint,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "certificate": cert,
        }

        self._certificates[serial_hex] = cert_info
        logger.info(
            "Certificate registered – serial=%s, type=%s, subject=%s",
            serial_hex,
            cert_type,
            subject_cn,
        )
        return cert_info

    def get_certificate(self, serial_number: str) -> Optional[dict]:
        """Retrieve certificate info by serial number.

        Args:
            serial_number: Hex-encoded serial number of the certificate.

        Returns:
            The certificate info dict, or ``None`` if not found.
        """
        return self._certificates.get(serial_number)

    def list_certificates(
        self,
        cert_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict]:
        """List all registered certificates, optionally filtered.

        Args:
            cert_type: If provided, only return certificates whose
                ``cert_type`` matches this value.
            status: If provided, only return certificates whose
                ``status`` matches this value (e.g. ``'active'``,
                ``'expired'``).

        Returns:
            A list of certificate info dicts matching the filters.
        """
        results: list[dict] = []
        for info in self._certificates.values():
            if cert_type is not None and info.get("cert_type") != cert_type:
                continue
            if status is not None and info.get("status") != status:
                continue
            results.append(info)
        return results

    # ------------------------------------------------------------------
    # Expiry and fingerprinting
    # ------------------------------------------------------------------

    def check_expiry(self, cert: x509.Certificate) -> dict:
        """Check the expiry status of a certificate.

        Determines whether the certificate has already expired or is
        approaching expiry (within the next 30 days).

        Args:
            cert: The X.509 certificate to check.

        Returns:
            A dict with the following keys:

            * ``is_expired`` – ``True`` if ``not_after`` is in the past.
            * ``is_expiring_soon`` – ``True`` if the certificate will
              expire within :data:`_EXPIRY_WARNING_DAYS` days.
            * ``days_until_expiry`` – Integer days remaining (negative if
              already expired).
            * ``not_after`` – ISO 8601 string of the ``notAfter`` field.
        """
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc

        delta = not_after - now
        days_until_expiry = delta.days

        return {
            "is_expired": now > not_after,
            "is_expiring_soon": 0 < days_until_expiry <= _EXPIRY_WARNING_DAYS,
            "days_until_expiry": days_until_expiry,
            "not_after": not_after.isoformat(),
        }

    def get_certificate_fingerprint(self, cert: x509.Certificate) -> str:
        """Compute the SHA-256 fingerprint of a DER-encoded certificate.

        Args:
            cert: The certificate to fingerprint.

        Returns:
            Colon-separated uppercase hex string, e.g. ``'AA:BB:CC:…'``.
        """
        der_bytes: bytes = cert.public_bytes(serialization.Encoding.DER)
        digest: bytes = hashlib.sha256(der_bytes).digest()
        return ":".join(f"{b:02X}" for b in digest)

    def export_certificate_pem(self, cert: x509.Certificate) -> str:
        """Export a certificate as a PEM-encoded string.

        Args:
            cert: The certificate to export.

        Returns:
            The PEM representation of the certificate as a ``str``.
        """
        pem_bytes: bytes = cert.public_bytes(serialization.Encoding.PEM)
        return pem_bytes.decode("utf-8")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cn(name: x509.Name) -> Optional[str]:
        """Extract the Common Name from an X.509 Name.

        Args:
            name: The :class:`~cryptography.x509.Name` to inspect.

        Returns:
            The CN value, or ``None`` if absent.
        """
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
        return None

    @staticmethod
    def _is_ca(cert: x509.Certificate) -> bool:
        """Determine whether a certificate has ``ca=True`` in BasicConstraints.

        Args:
            cert: The certificate to inspect.

        Returns:
            ``True`` if BasicConstraints is present and ``ca`` is set,
            ``False`` otherwise.
        """
        try:
            bc = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            return bc.value.ca  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            return False
