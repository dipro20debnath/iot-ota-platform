"""
Certificate Authority Module for IoT OTA Firmware Update Platform.

Provides a complete X.509 certificate lifecycle management system including
Root CA creation, Intermediate CA issuance, device certificate signing,
firmware-signing certificate generation, and certificate revocation tracking.
"""

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, Union
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID, ExtensionOID

from app.pki.key_manager import KeyManager

logger = logging.getLogger(__name__)


class CertificateAuthority:
    """Manages X.509 certificate lifecycle for the IoT OTA Platform.

    Handles Root CA creation, Intermediate CA issuance, device certificate
    signing, firmware-signing certificate generation, and certificate
    revocation.  All cryptographic key operations are delegated to the
    companion :class:`KeyManager` instance.

    Attributes:
        pki_data_dir: Root directory for all PKI artefacts.
        certs_dir: Subdirectory where certificate PEM files are stored.
        key_manager: The :class:`KeyManager` used for key generation and I/O.
    """

    def __init__(
        self,
        pki_data_dir: str = "./pki_data",
        key_manager: Optional[KeyManager] = None,
    ) -> None:
        """Initialise the Certificate Authority.

        Args:
            pki_data_dir: Root directory for PKI artefacts.  A ``certs``
                subdirectory is created inside it automatically.
            key_manager: An existing :class:`KeyManager` instance.  If
                *None*, a new one is created using the same
                *pki_data_dir*.
        """
        self.pki_data_dir: Path = Path(pki_data_dir)
        self.certs_dir: Path = self.pki_data_dir / "certs"
        self.certs_dir.mkdir(parents=True, exist_ok=True)

        self.key_manager: KeyManager = (
            key_manager if key_manager is not None else KeyManager(pki_data_dir)
        )

        # In-memory revocation list: serial-number (hex) → record dict
        self._revoked_certs: dict[str, dict] = {}

        # Cached Root CA material
        self._root_ca_cert: Optional[x509.Certificate] = None
        self._root_ca_key: Optional[rsa.RSAPrivateKey] = None

        # Cached Intermediate CA material
        self._intermediate_ca_cert: Optional[x509.Certificate] = None
        self._intermediate_ca_key: Optional[rsa.RSAPrivateKey] = None

        logger.info(
            "CertificateAuthority initialised – certs directory: %s",
            self.certs_dir,
        )

    # ------------------------------------------------------------------
    # Root CA
    # ------------------------------------------------------------------

    def create_root_ca(
        self,
        common_name: str = "IoT OTA Root CA",
        organization: str = "IoT OTA Platform",
        country: str = "US",
        validity_days: int = 3650,
        key_size: int = 4096,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create a self-signed Root CA certificate.

        Generates an RSA key pair via :class:`KeyManager`, then builds a
        self-signed X.509 v3 certificate with the extensions required for
        a root certificate authority:

        * **BasicConstraints** – ``ca=True, path_length=1`` (critical)
        * **KeyUsage** – ``key_cert_sign``, ``crl_sign`` (critical)
        * **SubjectKeyIdentifier** – derived from the public key
        * **AuthorityKeyIdentifier** – self-referencing (self-signed)

        The certificate and private key are persisted to disk and cached
        in instance attributes for subsequent signing operations.

        Args:
            common_name: Subject CN for the root certificate.
            organization: Subject O for the root certificate.
            country: Subject C (ISO 3166-1 alpha-2 country code).
            validity_days: Lifetime of the certificate in days.
            key_size: RSA key size in bits (e.g. 2048, 4096).

        Returns:
            A ``(certificate, private_key)`` tuple.

        Raises:
            ValueError: If *key_size* is rejected by the cryptographic
                backend.
        """
        logger.info(
            "Creating Root CA – CN=%s, org=%s, validity=%d days, key=%d bits",
            common_name,
            organization,
            validity_days,
            key_size,
        )

        # --- Key generation ---
        private_key, public_key = self.key_manager.generate_rsa_key_pair(key_size)

        # --- Subject / Issuer (identical for self-signed) ---
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.now(tz=timezone.utc)

        # --- Certificate builder ---
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
                critical=False,
            )
        )

        # --- Self-sign ---
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # --- Persist to disk ---
        cert_path = str(self.certs_dir / "root_ca.pem")
        key_path = str(self.key_manager.keys_dir / "root_ca_key.pem")

        self.save_certificate(certificate, cert_path)
        self.key_manager.save_private_key(private_key, key_path)

        # --- Cache ---
        self._root_ca_cert = certificate
        self._root_ca_key = private_key

        logger.info(
            "Root CA created – serial=%s, expires=%s",
            format(certificate.serial_number, "X"),
            certificate.not_valid_after_utc.isoformat(),
        )
        return certificate, private_key

    # ------------------------------------------------------------------
    # Intermediate CA
    # ------------------------------------------------------------------

    def create_intermediate_ca(
        self,
        common_name: str = "IoT OTA Intermediate CA",
        organization: str = "IoT OTA Platform",
        country: str = "US",
        validity_days: int = 1825,
        key_size: int = 4096,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Create an Intermediate CA certificate signed by the Root CA.

        The Root CA **must** already exist (via :meth:`create_root_ca`).
        The intermediate certificate is issued with:

        * **BasicConstraints** – ``ca=True, path_length=0`` (critical)
        * **KeyUsage** – ``key_cert_sign``, ``crl_sign`` (critical)
        * **SubjectKeyIdentifier** – derived from the intermediate public key
        * **AuthorityKeyIdentifier** – derived from the Root CA certificate

        Args:
            common_name: Subject CN for the intermediate certificate.
            organization: Subject O for the intermediate certificate.
            country: Subject C (ISO 3166-1 alpha-2 country code).
            validity_days: Lifetime of the certificate in days.
            key_size: RSA key size in bits.

        Returns:
            A ``(certificate, private_key)`` tuple.

        Raises:
            RuntimeError: If the Root CA has not been created yet.
            ValueError: If *key_size* is rejected by the cryptographic
                backend.
        """
        if self._root_ca_cert is None or self._root_ca_key is None:
            raise RuntimeError(
                "Root CA must be created before issuing an Intermediate CA. "
                "Call create_root_ca() first."
            )

        logger.info(
            "Creating Intermediate CA – CN=%s, org=%s, validity=%d days, key=%d bits",
            common_name,
            organization,
            validity_days,
            key_size,
        )

        # --- Key generation ---
        private_key, public_key = self.key_manager.generate_rsa_key_pair(key_size)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.now(tz=timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._root_ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    self._root_ca_cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value  # type: ignore[arg-type]
                ),
                critical=False,
            )
        )

        # --- Sign with Root CA key ---
        certificate = builder.sign(
            private_key=self._root_ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # --- Persist ---
        cert_path = str(self.certs_dir / "intermediate_ca.pem")
        key_path = str(self.key_manager.keys_dir / "intermediate_ca_key.pem")

        self.save_certificate(certificate, cert_path)
        self.key_manager.save_private_key(private_key, key_path)

        # --- Cache ---
        self._intermediate_ca_cert = certificate
        self._intermediate_ca_key = private_key

        logger.info(
            "Intermediate CA created – serial=%s, issuer=%s, expires=%s",
            format(certificate.serial_number, "X"),
            self._root_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value,
            certificate.not_valid_after_utc.isoformat(),
        )
        return certificate, private_key

    # ------------------------------------------------------------------
    # Device certificates
    # ------------------------------------------------------------------

    def issue_device_certificate(
        self,
        device_id: str,
        common_name: str,
        key_size: int = 2048,
        validity_days: int = 365,
        use_intermediate: bool = True,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Issue an end-entity certificate for an IoT device.

        The certificate is signed by the Intermediate CA when available
        and *use_intermediate* is *True*; otherwise the Root CA is used
        directly.

        Extensions applied:

        * **BasicConstraints** – ``ca=False`` (critical)
        * **KeyUsage** – ``digital_signature``, ``key_encipherment``
          (critical)
        * **ExtendedKeyUsage** – ``OID_CLIENT_AUTH`` (non-critical)
        * **SubjectAlternativeName** – the *device_id* encoded as a
          ``UniformResourceIdentifier``
          (``urn:iot:device:<device_id>``)
        * **SubjectKeyIdentifier** – derived from the device public key
        * **AuthorityKeyIdentifier** – derived from the issuing CA cert

        Args:
            device_id: Unique device identifier (used in SAN and filenames).
            common_name: Subject CN for the device certificate.
            key_size: RSA key size in bits.
            validity_days: Lifetime of the certificate in days.
            use_intermediate: If *True* and an intermediate CA exists,
                use it as the issuer; otherwise fall back to the Root CA.

        Returns:
            A ``(certificate, private_key)`` tuple.

        Raises:
            RuntimeError: If no CA (root or intermediate) is available to
                sign the certificate.
        """
        # --- Resolve issuing CA ---
        issuer_cert, issuer_key = self._resolve_issuing_ca(use_intermediate)

        logger.info(
            "Issuing device certificate – device_id=%s, CN=%s, key=%d bits, validity=%d days",
            device_id,
            common_name,
            key_size,
            validity_days,
        )

        # --- Key generation ---
        private_key, public_key = self.key_manager.generate_rsa_key_pair(key_size)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.now(tz=timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            f"urn:iot:device:{device_id}"
                        ),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value  # type: ignore[arg-type]
                ),
                critical=False,
            )
        )

        certificate = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # --- Persist ---
        cert_path = str(self.certs_dir / f"device_{device_id}.pem")
        key_path = str(self.key_manager.keys_dir / f"device_{device_id}_key.pem")

        self.save_certificate(certificate, cert_path)
        self.key_manager.save_private_key(private_key, key_path)

        logger.info(
            "Device certificate issued – device_id=%s, serial=%s, issuer_cn=%s",
            device_id,
            format(certificate.serial_number, "X"),
            issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value,
        )
        return certificate, private_key

    # ------------------------------------------------------------------
    # Firmware-signing certificate
    # ------------------------------------------------------------------

    def issue_signing_certificate(
        self,
        common_name: str = "Firmware Signing Key",
        key_size: int = 4096,
        validity_days: int = 730,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Issue a code-signing certificate for firmware packages.

        The certificate is signed by the best available CA (Intermediate
        if present, otherwise Root).  It carries:

        * **BasicConstraints** – ``ca=False`` (critical)
        * **KeyUsage** – ``digital_signature`` (critical)
        * **ExtendedKeyUsage** – ``OID_CODE_SIGNING`` (critical)
        * **SubjectKeyIdentifier** – derived from the signing public key
        * **AuthorityKeyIdentifier** – derived from the issuing CA cert

        Args:
            common_name: Subject CN for the signing certificate.
            key_size: RSA key size in bits.
            validity_days: Lifetime of the certificate in days.

        Returns:
            A ``(certificate, private_key)`` tuple.

        Raises:
            RuntimeError: If no CA is available.
        """
        issuer_cert, issuer_key = self._resolve_issuing_ca(use_intermediate=True)

        logger.info(
            "Issuing firmware-signing certificate – CN=%s, key=%d bits, validity=%d days",
            common_name,
            key_size,
            validity_days,
        )

        private_key, public_key = self.key_manager.generate_rsa_key_pair(key_size)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.now(tz=timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value  # type: ignore[arg-type]
                ),
                critical=False,
            )
        )

        certificate = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # --- Persist ---
        cert_path = str(self.certs_dir / "signing_cert.pem")
        key_path = str(self.key_manager.keys_dir / "signing_key.pem")

        self.save_certificate(certificate, cert_path)
        self.key_manager.save_private_key(private_key, key_path)

        logger.info(
            "Firmware-signing certificate issued – serial=%s, issuer_cn=%s",
            format(certificate.serial_number, "X"),
            issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                0
            ].value,
        )
        return certificate, private_key

    # ------------------------------------------------------------------
    # Certificate revocation
    # ------------------------------------------------------------------

    def revoke_certificate(
        self,
        cert: x509.Certificate,
        reason: str = "unspecified",
    ) -> dict:
        """Mark a certificate as revoked in the in-memory revocation list.

        The revocation record is keyed by the certificate's serial number
        (hex-encoded) and stores the revocation timestamp and reason.

        Args:
            cert: The X.509 certificate to revoke.
            reason: Human-readable revocation reason (e.g.
                ``'key_compromise'``, ``'superseded'``, ``'unspecified'``).

        Returns:
            A dictionary containing:

            * ``serial_number`` – Hex-encoded serial number.
            * ``revoked_at`` – ISO 8601 timestamp of revocation.
            * ``reason`` – The supplied reason string.
        """
        serial_hex: str = format(cert.serial_number, "X")
        revoked_at: str = datetime.now(tz=timezone.utc).isoformat()

        record: dict = {
            "serial_number": serial_hex,
            "revoked_at": revoked_at,
            "reason": reason,
        }
        self._revoked_certs[serial_hex] = record

        logger.warning(
            "Certificate revoked – serial=%s, reason=%s, at=%s",
            serial_hex,
            reason,
            revoked_at,
        )
        return record

    def is_revoked(self, cert: x509.Certificate) -> bool:
        """Check whether a certificate has been revoked.

        Args:
            cert: The X.509 certificate to check.

        Returns:
            *True* if the certificate's serial number is present in the
            in-memory revocation list, *False* otherwise.
        """
        serial_hex: str = format(cert.serial_number, "X")
        revoked: bool = serial_hex in self._revoked_certs
        logger.debug(
            "Revocation check – serial=%s, revoked=%s",
            serial_hex,
            revoked,
        )
        return revoked

    def get_revoked_certs(self) -> list[dict]:
        """Return a list of all revoked certificate records.

        Returns:
            A list of dictionaries, each containing ``serial_number``,
            ``revoked_at``, and ``reason``.
        """
        return list(self._revoked_certs.values())

    # ------------------------------------------------------------------
    # Certificate I/O
    # ------------------------------------------------------------------

    def save_certificate(self, cert: x509.Certificate, filepath: str) -> None:
        """Persist an X.509 certificate to a PEM-encoded file.

        Parent directories are created automatically if they do not exist.

        Args:
            cert: The certificate object to save.
            filepath: Destination path for the PEM file.
        """
        logger.info("Saving certificate to %s …", filepath)
        pem_bytes: bytes = cert.public_bytes(serialization.Encoding.PEM)
        dest = Path(filepath)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(pem_bytes)
        logger.info("Certificate saved to %s.", filepath)

    def load_certificate(self, filepath: str) -> x509.Certificate:
        """Load an X.509 certificate from a PEM-encoded file.

        Args:
            filepath: Path to the PEM file.

        Returns:
            The deserialised :class:`~cryptography.x509.Certificate`.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            ValueError: If the file does not contain a valid PEM
                certificate.
        """
        logger.info("Loading certificate from %s …", filepath)
        pem_data: bytes = Path(filepath).read_bytes()
        certificate: x509.Certificate = x509.load_pem_x509_certificate(
            pem_data,
            backend=default_backend(),
        )
        logger.info("Certificate loaded from %s.", filepath)
        return certificate

    def serialize_certificate_pem(self, cert: x509.Certificate) -> bytes:
        """Serialize a certificate to PEM-encoded bytes.

        This is an in-memory operation; nothing is written to disk.

        Args:
            cert: The certificate to serialise.

        Returns:
            PEM-encoded bytes of the certificate.
        """
        return cert.public_bytes(serialization.Encoding.PEM)

    # ------------------------------------------------------------------
    # Certificate inspection
    # ------------------------------------------------------------------

    def get_certificate_info(self, cert: x509.Certificate) -> dict:
        """Extract human-readable metadata from a certificate.

        Args:
            cert: The certificate to inspect.

        Returns:
            A dictionary with the following keys:

            * ``serial_number`` – Hex-encoded serial number.
            * ``subject_cn`` – Subject Common Name (or ``None``).
            * ``issuer_cn`` – Issuer Common Name (or ``None``).
            * ``not_before`` – Validity start (ISO 8601 string).
            * ``not_after`` – Validity end (ISO 8601 string).
            * ``is_ca`` – Whether the certificate has ``ca=True`` in
              BasicConstraints.
            * ``fingerprint_sha256`` – Colon-separated SHA-256 fingerprint
              of the DER-encoded certificate.
            * ``key_usage`` – List of enabled key-usage flags, or ``None``
              if the extension is absent.
            * ``extended_key_usage`` – List of extended-key-usage OID
              dotted strings, or ``None``.
            * ``subject_alt_names`` – List of SAN values, or ``None``.
            * ``is_revoked`` – Whether the certificate appears in the
              local revocation list.
        """
        # --- Subject / Issuer CNs ---
        subject_cn = self._extract_cn(cert.subject)
        issuer_cn = self._extract_cn(cert.issuer)

        # --- Fingerprint ---
        der_bytes: bytes = cert.public_bytes(serialization.Encoding.DER)
        sha256_digest: bytes = hashlib.sha256(der_bytes).digest()
        fingerprint: str = ":".join(f"{b:02X}" for b in sha256_digest)

        # --- BasicConstraints ---
        is_ca: bool = False
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = bc_ext.value.ca  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            pass

        # --- KeyUsage ---
        key_usage_flags: Optional[list[str]] = None
        try:
            ku_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            ku: x509.KeyUsage = ku_ext.value  # type: ignore[assignment]
            key_usage_flags = [
                name
                for name in (
                    "digital_signature",
                    "content_commitment",
                    "key_encipherment",
                    "data_encipherment",
                    "key_agreement",
                    "key_cert_sign",
                    "crl_sign",
                )
                if getattr(ku, name, False)
            ]
            # encipher_only / decipher_only only valid when key_agreement is set
            if ku.key_agreement:
                if ku.encipher_only:
                    key_usage_flags.append("encipher_only")
                if ku.decipher_only:
                    key_usage_flags.append("decipher_only")
        except x509.ExtensionNotFound:
            pass

        # --- ExtendedKeyUsage ---
        eku_oids: Optional[list[str]] = None
        try:
            eku_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            eku_oids = [
                oid.dotted_string
                for oid in eku_ext.value  # type: ignore[union-attr]
            ]
        except x509.ExtensionNotFound:
            pass

        # --- SubjectAlternativeName ---
        san_values: Optional[list[str]] = None
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san: x509.SubjectAlternativeName = san_ext.value  # type: ignore[assignment]
            san_values = [name.value for name in san]
        except x509.ExtensionNotFound:
            pass

        return {
            "serial_number": format(cert.serial_number, "X"),
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "is_ca": is_ca,
            "fingerprint_sha256": fingerprint,
            "key_usage": key_usage_flags,
            "extended_key_usage": eku_oids,
            "subject_alt_names": san_values,
            "is_revoked": self.is_revoked(cert),
        }

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_root_ca(self) -> Optional[tuple[x509.Certificate, Any]]:
        """Return the cached Root CA material.

        Returns:
            A ``(certificate, private_key)`` tuple, or *None* if the Root
            CA has not been created.
        """
        if self._root_ca_cert is not None and self._root_ca_key is not None:
            return self._root_ca_cert, self._root_ca_key
        return None

    def get_intermediate_ca(self) -> Optional[tuple[x509.Certificate, Any]]:
        """Return the cached Intermediate CA material.

        Returns:
            A ``(certificate, private_key)`` tuple, or *None* if the
            Intermediate CA has not been created.
        """
        if (
            self._intermediate_ca_cert is not None
            and self._intermediate_ca_key is not None
        ):
            return self._intermediate_ca_cert, self._intermediate_ca_key
        return None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_issuing_ca(
        self,
        use_intermediate: bool = True,
    ) -> tuple[x509.Certificate, Any]:
        """Determine the appropriate issuing CA for signing operations.

        When *use_intermediate* is *True* and the Intermediate CA is
        available, it is returned.  Otherwise the Root CA is used.

        Args:
            use_intermediate: Prefer the Intermediate CA when available.

        Returns:
            A ``(issuer_certificate, issuer_private_key)`` tuple.

        Raises:
            RuntimeError: If no CA material is available at all.
        """
        if use_intermediate and self._intermediate_ca_cert is not None:
            logger.debug("Using Intermediate CA as issuer.")
            return self._intermediate_ca_cert, self._intermediate_ca_key

        if self._root_ca_cert is not None and self._root_ca_key is not None:
            logger.debug("Using Root CA as issuer.")
            return self._root_ca_cert, self._root_ca_key

        raise RuntimeError(
            "No CA is available for signing. "
            "Call create_root_ca() (and optionally create_intermediate_ca()) first."
        )

    @staticmethod
    def _extract_cn(name: x509.Name) -> Optional[str]:
        """Extract the Common Name (CN) from an X.509 Name.

        Args:
            name: The :class:`~cryptography.x509.Name` to inspect.

        Returns:
            The CN value as a string, or *None* if no CN attribute is
            present.
        """
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
        return None
