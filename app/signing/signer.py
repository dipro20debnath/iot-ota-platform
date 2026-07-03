"""
Firmware Code Signing Module for IoT OTA Firmware Update Platform.

Provides cryptographic signing of firmware binaries using RSA-PSS or ECDSA
algorithms.  Designed to integrate with the platform's existing PKI
infrastructure (:class:`~app.pki.key_manager.KeyManager` and
:class:`~app.pki.ca.CertificateAuthority`).

Usage example::

    from app.pki.key_manager import KeyManager
    from app.pki.ca import CertificateAuthority
    from app.signing.signer import FirmwareSigner

    km = KeyManager("./pki_data")
    ca = CertificateAuthority("./pki_data", key_manager=km)
    ca.create_root_ca()

    signing_cert, signing_key = ca.issue_signing_certificate()

    signer = FirmwareSigner()
    signer.load_signing_key(signing_key)
    signer.load_signing_certificate(signing_cert)

    result = signer.sign_firmware(firmware_bytes)
    # result["signature"]   → hex-encoded signature string
    # result["algorithm"]   → "RSA-PSS" or "ECDSA"
    # result["hash_sha256"] → hex SHA-256 digest of the firmware
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography import x509

logger = logging.getLogger(__name__)


class FirmwareSigner:
    """Signs firmware binaries using RSA-PSS or ECDSA for secure OTA updates.

    The signer supports two signing algorithms, chosen automatically based
    on the type of private key that has been loaded:

    * **RSA** → RSA-PSS with SHA-256 digest and maximum salt length.
    * **ECDSA** → ECDSA with SHA-256 digest.

    Attributes:
        _signing_key: The loaded private key (RSA or ECDSA), or *None*.
        _signing_cert: The loaded X.509 signing certificate, or *None*.
    """

    def __init__(self) -> None:
        """Initialise the FirmwareSigner with no key material loaded."""
        self._signing_key: Optional[
            Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
        ] = None
        self._signing_cert: Optional[x509.Certificate] = None
        logger.info("FirmwareSigner initialised.")

    # ------------------------------------------------------------------
    # Key / certificate loading
    # ------------------------------------------------------------------

    def load_signing_key(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    ) -> None:
        """Load a private key for signing operations.

        Accepts both RSA and ECDSA private keys.  The key type is used at
        signing time to select the appropriate algorithm (RSA-PSS or
        ECDSA).

        Args:
            private_key: An RSA or ECDSA private key object produced by
                :class:`~app.pki.key_manager.KeyManager`.

        Raises:
            TypeError: If *private_key* is not an RSA or ECDSA private key.
        """
        if not isinstance(
            private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)
        ):
            raise TypeError(
                f"Expected RSA or ECDSA private key, got {type(private_key).__name__}"
            )

        self._signing_key = private_key
        key_type = "RSA" if isinstance(private_key, rsa.RSAPrivateKey) else "ECDSA"
        logger.info("Signing key loaded (type=%s).", key_type)

    def load_signing_certificate(self, cert: x509.Certificate) -> None:
        """Load the signing certificate.

        The certificate is optional but recommended.  When present, its
        SHA-256 fingerprint is included in every signing result for
        traceability.

        Args:
            cert: An X.509 certificate, typically issued by
                :meth:`~app.pki.ca.CertificateAuthority.issue_signing_certificate`.
        """
        self._signing_cert = cert
        logger.info(
            "Signing certificate loaded – subject=%s.",
            cert.subject.rfc4514_string(),
        )

    # ------------------------------------------------------------------
    # Core signing
    # ------------------------------------------------------------------

    def sign_firmware(self, firmware_data: bytes) -> dict:
        """Sign firmware binary data.

        Automatically detects the loaded key type and selects the
        appropriate algorithm:

        * **RSA** → RSA-PSS padding, SHA-256 digest, maximum salt length.
        * **ECDSA** → ECDSA with SHA-256 digest.

        Args:
            firmware_data: Raw firmware binary content.

        Returns:
            A dictionary containing:

            * ``signature`` – Hex-encoded digital signature.
            * ``algorithm`` – ``'RSA-PSS'`` or ``'ECDSA'``.
            * ``hash_sha256`` – Hex-encoded SHA-256 digest of
              *firmware_data*.
            * ``file_size`` – Length of *firmware_data* in bytes.
            * ``signed_at`` – ISO 8601 UTC timestamp.
            * ``signer_fingerprint`` – SHA-256 fingerprint of the signing
              certificate (or ``None`` if no certificate was loaded).

        Raises:
            RuntimeError: If no signing key has been loaded.
        """
        if self._signing_key is None:
            raise RuntimeError(
                "No signing key loaded. Call load_signing_key() first."
            )

        # --- Determine algorithm and produce signature bytes ---
        if isinstance(self._signing_key, rsa.RSAPrivateKey):
            algorithm_name = "RSA-PSS"
            signature_bytes: bytes = self._signing_key.sign(
                firmware_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            # ECDSA key
            algorithm_name = "ECDSA"
            signature_bytes = self._signing_key.sign(
                firmware_data,
                ec.ECDSA(hashes.SHA256()),
            )

        # --- Compute SHA-256 hash ---
        firmware_hash: str = hashlib.sha256(firmware_data).hexdigest()

        # --- Certificate fingerprint (if available) ---
        signer_fingerprint: Optional[str] = None
        if self._signing_cert is not None:
            cert_der: bytes = self._signing_cert.public_bytes(
                serialization.Encoding.DER
            )
            signer_fingerprint = hashlib.sha256(cert_der).hexdigest()

        result: dict = {
            "signature": signature_bytes.hex(),
            "algorithm": algorithm_name,
            "hash_sha256": firmware_hash,
            "file_size": len(firmware_data),
            "signed_at": datetime.now(tz=timezone.utc).isoformat(),
            "signer_fingerprint": signer_fingerprint,
        }

        logger.info(
            "Firmware signed – algorithm=%s, size=%d bytes, hash=%s",
            algorithm_name,
            len(firmware_data),
            firmware_hash,
        )
        return result

    def sign_firmware_file(self, filepath: str) -> dict:
        """Sign a firmware file from disk.

        Reads the entire file into memory and delegates to
        :meth:`sign_firmware`.

        Args:
            filepath: Path to the firmware binary file.

        Returns:
            The same result dictionary as :meth:`sign_firmware`.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            RuntimeError: If no signing key has been loaded.
        """
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Firmware file not found: {filepath}")

        firmware_data: bytes = path.read_bytes()
        logger.info(
            "Read firmware file %s (%d bytes).", filepath, len(firmware_data)
        )
        return self.sign_firmware(firmware_data)

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def compute_hash(self, data: bytes, algorithm: str = "sha256") -> str:
        """Compute the hex-encoded hash digest of arbitrary data.

        Args:
            data: The bytes to hash.
            algorithm: Hash algorithm name – ``'sha256'`` (default) or
                ``'sha384'``.

        Returns:
            Hex-encoded hash string.

        Raises:
            ValueError: If *algorithm* is not ``'sha256'`` or ``'sha384'``.
        """
        algorithm = algorithm.lower()
        if algorithm == "sha256":
            digest: str = hashlib.sha256(data).hexdigest()
        elif algorithm == "sha384":
            digest = hashlib.sha384(data).hexdigest()
        else:
            raise ValueError(
                f"Unsupported hash algorithm '{algorithm}'. "
                "Supported: 'sha256', 'sha384'."
            )
        logger.debug("Computed %s hash: %s", algorithm, digest)
        return digest

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_signer_info(self) -> dict:
        """Return information about the currently loaded signing key and certificate.

        Returns:
            A dictionary containing:

            * ``key_loaded`` – *True* if a signing key is present.
            * ``key_type`` – ``'RSA'``, ``'ECDSA'``, or ``None``.
            * ``key_size`` – Key size in bits, or ``None``.
            * ``cert_loaded`` – *True* if a signing certificate is present.
            * ``cert_subject`` – RFC 4514 subject string, or ``None``.
            * ``cert_fingerprint`` – SHA-256 hex fingerprint, or ``None``.
        """
        key_type: Optional[str] = None
        key_size: Optional[int] = None

        if self._signing_key is not None:
            if isinstance(self._signing_key, rsa.RSAPrivateKey):
                key_type = "RSA"
            else:
                key_type = "ECDSA"
            key_size = self._signing_key.key_size

        cert_subject: Optional[str] = None
        cert_fingerprint: Optional[str] = None

        if self._signing_cert is not None:
            cert_subject = self._signing_cert.subject.rfc4514_string()
            cert_der: bytes = self._signing_cert.public_bytes(
                serialization.Encoding.DER
            )
            cert_fingerprint = hashlib.sha256(cert_der).hexdigest()

        info: dict = {
            "key_loaded": self._signing_key is not None,
            "key_type": key_type,
            "key_size": key_size,
            "cert_loaded": self._signing_cert is not None,
            "cert_subject": cert_subject,
            "cert_fingerprint": cert_fingerprint,
        }
        logger.debug("Signer info: %s", info)
        return info
