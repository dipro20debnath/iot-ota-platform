"""
Firmware Signature Verification Module for IoT OTA Firmware Update Platform.

Provides cryptographic verification of firmware signatures produced by
:class:`~app.signing.signer.FirmwareSigner`.  Supports both RSA-PSS and
ECDSA signatures and integrates with the platform's existing PKI
infrastructure (:class:`~app.pki.key_manager.KeyManager` and
:class:`~app.pki.ca.CertificateAuthority`).

Usage example::

    from app.signing.verifier import FirmwareVerifier

    verifier = FirmwareVerifier()

    # Verify using a public key directly
    result = verifier.verify_signature(firmware_bytes, signature_hex, public_key)

    # Verify using a certificate (extracts the public key automatically)
    result = verifier.verify_with_certificate(firmware_bytes, signature_hex, cert)

    # Full verification: hash integrity + signature authenticity
    result = verifier.verify_complete(firmware_bytes, signature_hex, expected_hash, cert)
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography import x509

logger = logging.getLogger(__name__)


class FirmwareVerifier:
    """Verifies firmware signatures to ensure authenticity and integrity.

    The verifier automatically detects the key type (RSA or ECDSA) and
    selects the appropriate verification algorithm:

    * **RSA** → RSA-PSS with SHA-256 digest and maximum salt length.
    * **ECDSA** → ECDSA with SHA-256 digest.

    All verification methods return structured result dictionaries that
    include a ``valid`` boolean, algorithm details, and timestamps.
    """

    def __init__(self) -> None:
        """Initialise the FirmwareVerifier."""
        logger.info("FirmwareVerifier initialised.")

    # ------------------------------------------------------------------
    # Core verification
    # ------------------------------------------------------------------

    def verify_signature(
        self,
        firmware_data: bytes,
        signature_hex: str,
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ) -> dict:
        """Verify a firmware signature against a public key.

        Automatically detects the key type (RSA or ECDSA) and applies the
        matching verification algorithm.

        Args:
            firmware_data: Raw firmware binary content.
            signature_hex: Hex-encoded signature string (as produced by
                :meth:`~app.signing.signer.FirmwareSigner.sign_firmware`).
            public_key: The RSA or ECDSA public key to verify against.

        Returns:
            A dictionary containing:

            * ``valid`` – *True* if the signature is authentic.
            * ``algorithm`` – ``'RSA-PSS'`` or ``'ECDSA'``.
            * ``hash_sha256`` – Hex-encoded SHA-256 digest of
              *firmware_data*.
            * ``file_size`` – Length of *firmware_data* in bytes.
            * ``verified_at`` – ISO 8601 UTC timestamp.
            * ``error`` – Error message string if verification failed,
              otherwise ``None``.
        """
        signature_bytes: bytes = bytes.fromhex(signature_hex)
        firmware_hash: str = hashlib.sha256(firmware_data).hexdigest()

        valid: bool = False
        error: Optional[str] = None
        algorithm: str

        try:
            if isinstance(public_key, rsa.RSAPublicKey):
                algorithm = "RSA-PSS"
                public_key.verify(
                    signature_bytes,
                    firmware_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                algorithm = "ECDSA"
                public_key.verify(
                    signature_bytes,
                    firmware_data,
                    ec.ECDSA(hashes.SHA256()),
                )
            else:
                algorithm = "UNKNOWN"
                error = f"Unsupported key type: {type(public_key).__name__}"
                logger.error(error)
                return {
                    "valid": False,
                    "algorithm": algorithm,
                    "hash_sha256": firmware_hash,
                    "file_size": len(firmware_data),
                    "verified_at": datetime.now(tz=timezone.utc).isoformat(),
                    "error": error,
                }

            valid = True
            logger.info(
                "Signature verification PASSED – algorithm=%s, hash=%s",
                algorithm,
                firmware_hash,
            )

        except InvalidSignature:
            valid = False
            error = "Signature verification failed: invalid signature."
            logger.warning(
                "Signature verification FAILED – algorithm=%s, hash=%s",
                algorithm,
                firmware_hash,
            )

        return {
            "valid": valid,
            "algorithm": algorithm,
            "hash_sha256": firmware_hash,
            "file_size": len(firmware_data),
            "verified_at": datetime.now(tz=timezone.utc).isoformat(),
            "error": error,
        }

    # ------------------------------------------------------------------
    # Certificate-based verification
    # ------------------------------------------------------------------

    def verify_with_certificate(
        self,
        firmware_data: bytes,
        signature_hex: str,
        cert: x509.Certificate,
    ) -> dict:
        """Verify a firmware signature using a certificate's public key.

        Extracts the public key from the provided X.509 certificate and
        delegates to :meth:`verify_signature`.  The signer's subject name
        is appended to the result for audit purposes.

        Args:
            firmware_data: Raw firmware binary content.
            signature_hex: Hex-encoded signature string.
            cert: The X.509 signing certificate.

        Returns:
            The same result dictionary as :meth:`verify_signature`, plus:

            * ``signer_subject`` – RFC 4514 representation of the
              certificate subject.
        """
        public_key = cert.public_key()
        result: dict = self.verify_signature(
            firmware_data, signature_hex, public_key
        )
        result["signer_subject"] = cert.subject.rfc4514_string()

        logger.info(
            "Certificate-based verification – subject=%s, valid=%s",
            result["signer_subject"],
            result["valid"],
        )
        return result

    # ------------------------------------------------------------------
    # File-based verification
    # ------------------------------------------------------------------

    def verify_firmware_file(
        self,
        filepath: str,
        signature_hex: str,
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ) -> dict:
        """Verify the signature of a firmware file on disk.

        Reads the file into memory and delegates to
        :meth:`verify_signature`.

        Args:
            filepath: Path to the firmware binary file.
            signature_hex: Hex-encoded signature string.
            public_key: The RSA or ECDSA public key to verify against.

        Returns:
            The same result dictionary as :meth:`verify_signature`.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
        """
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Firmware file not found: {filepath}")

        firmware_data: bytes = path.read_bytes()
        logger.info(
            "Read firmware file %s (%d bytes) for verification.",
            filepath,
            len(firmware_data),
        )
        return self.verify_signature(firmware_data, signature_hex, public_key)

    # ------------------------------------------------------------------
    # Hash verification
    # ------------------------------------------------------------------

    def verify_hash(
        self,
        firmware_data: bytes,
        expected_hash: str,
        algorithm: str = "sha256",
    ) -> dict:
        """Verify firmware integrity by comparing hash digests.

        Args:
            firmware_data: Raw firmware binary content.
            expected_hash: The expected hex-encoded hash digest.
            algorithm: Hash algorithm – ``'sha256'`` (default) or
                ``'sha384'``.

        Returns:
            A dictionary containing:

            * ``valid`` – *True* if the computed hash matches the expected
              hash.
            * ``expected`` – The expected hash string.
            * ``actual`` – The computed hash string.
            * ``algorithm`` – The hash algorithm used.

        Raises:
            ValueError: If *algorithm* is not ``'sha256'`` or ``'sha384'``.
        """
        algorithm = algorithm.lower()
        if algorithm == "sha256":
            actual_hash: str = hashlib.sha256(firmware_data).hexdigest()
        elif algorithm == "sha384":
            actual_hash = hashlib.sha384(firmware_data).hexdigest()
        else:
            raise ValueError(
                f"Unsupported hash algorithm '{algorithm}'. "
                "Supported: 'sha256', 'sha384'."
            )

        valid: bool = actual_hash == expected_hash
        if valid:
            logger.info(
                "Hash verification PASSED – algorithm=%s, hash=%s",
                algorithm,
                actual_hash,
            )
        else:
            logger.warning(
                "Hash verification FAILED – algorithm=%s, expected=%s, actual=%s",
                algorithm,
                expected_hash,
                actual_hash,
            )

        return {
            "valid": valid,
            "expected": expected_hash,
            "actual": actual_hash,
            "algorithm": algorithm,
        }

    # ------------------------------------------------------------------
    # Complete verification (hash + signature)
    # ------------------------------------------------------------------

    def verify_complete(
        self,
        firmware_data: bytes,
        signature_hex: str,
        expected_hash: str,
        cert: x509.Certificate,
    ) -> dict:
        """Perform complete firmware verification: hash check **and** signature.

        Runs both :meth:`verify_hash` and :meth:`verify_with_certificate`
        and combines the results.  The overall ``valid`` flag is *True*
        only if **both** checks pass.

        Args:
            firmware_data: Raw firmware binary content.
            signature_hex: Hex-encoded signature string.
            expected_hash: Expected SHA-256 hex digest.
            cert: The X.509 signing certificate.

        Returns:
            A dictionary containing:

            * ``valid`` – *True* only if both hash and signature are valid.
            * ``hash_check`` – Result dictionary from :meth:`verify_hash`.
            * ``signature_check`` – Result dictionary from
              :meth:`verify_with_certificate`.
        """
        hash_result: dict = self.verify_hash(firmware_data, expected_hash)
        sig_result: dict = self.verify_with_certificate(
            firmware_data, signature_hex, cert
        )

        overall_valid: bool = hash_result["valid"] and sig_result["valid"]

        logger.info(
            "Complete verification – hash_valid=%s, sig_valid=%s, overall=%s",
            hash_result["valid"],
            sig_result["valid"],
            overall_valid,
        )

        return {
            "valid": overall_valid,
            "hash_check": hash_result,
            "signature_check": sig_result,
        }
