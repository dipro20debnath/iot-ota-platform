"""
PKI Key Management Module for IoT OTA Firmware Update Platform.

Provides comprehensive cryptographic key generation, serialization,
persistence, and inspection utilities using RSA and ECDSA algorithms.
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Optional, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

logger = logging.getLogger(__name__)

# Mapping of human-readable curve names to cryptography curve objects.
_SUPPORTED_CURVES: dict[str, ec.EllipticCurve] = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
}


class KeyManager:
    """Manages cryptographic key lifecycle for the OTA firmware update platform.

    Handles generation, serialization, persistence, and inspection of
    RSA and ECDSA key pairs used for firmware signing and verification.

    Attributes:
        keys_dir: Filesystem path where key material is stored.
    """

    def __init__(self, pki_data_dir: str = "./pki_data") -> None:
        """Initialise the KeyManager and ensure the storage directory exists.

        Args:
            pki_data_dir: Root directory for PKI artefacts.  A ``keys``
                sub-directory is created inside it automatically.
        """
        self.keys_dir: Path = Path(pki_data_dir) / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        logger.info("KeyManager initialised – keys directory: %s", self.keys_dir)

    # ------------------------------------------------------------------
    # Key-pair generation
    # ------------------------------------------------------------------

    def generate_rsa_key_pair(
        self, key_size: int = 2048
    ) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate an RSA key pair.

        Args:
            key_size: Length of the RSA modulus in bits (e.g. 2048, 4096).

        Returns:
            A ``(private_key, public_key)`` tuple.

        Raises:
            ValueError: If *key_size* is not a positive integer accepted
                by the underlying library.
        """
        logger.info("Generating RSA key pair (key_size=%d) …", key_size)
        private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key: rsa.RSAPublicKey = private_key.public_key()
        logger.info("RSA key pair generated successfully.")
        return private_key, public_key

    def generate_ecdsa_key_pair(
        self, curve: str = "P-256"
    ) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an ECDSA key pair on the requested named curve.

        Args:
            curve: Named curve identifier.  Supported values are
                ``'P-256'`` and ``'P-384'``.

        Returns:
            A ``(private_key, public_key)`` tuple.

        Raises:
            ValueError: If *curve* is not one of the supported names.
        """
        if curve not in _SUPPORTED_CURVES:
            supported = ", ".join(sorted(_SUPPORTED_CURVES))
            raise ValueError(
                f"Unsupported curve '{curve}'. Supported curves: {supported}"
            )

        ec_curve = _SUPPORTED_CURVES[curve]
        logger.info("Generating ECDSA key pair (curve=%s) …", curve)
        private_key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec_curve,
            backend=default_backend(),
        )
        public_key: ec.EllipticCurvePublicKey = private_key.public_key()
        logger.info("ECDSA key pair generated successfully.")
        return private_key, public_key

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    def save_private_key(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        filepath: str,
        passphrase: Optional[bytes] = None,
    ) -> None:
        """Persist a private key to a PEM-encoded file.

        Args:
            private_key: The private key object to save.
            filepath: Destination path for the PEM file.
            passphrase: If provided, the key is encrypted with
                AES-256-CBC using this passphrase.
        """
        encryption: serialization.KeySerializationEncryption
        if passphrase is not None:
            encryption = serialization.BestAvailableEncryption(passphrase)
            logger.info("Saving encrypted private key to %s …", filepath)
        else:
            encryption = serialization.NoEncryption()
            logger.info("Saving private key (unencrypted) to %s …", filepath)

        pem_bytes: bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        dest = Path(filepath)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(pem_bytes)
        logger.info("Private key saved to %s.", filepath)

    def save_public_key(
        self,
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
        filepath: str,
    ) -> None:
        """Persist a public key to a PEM-encoded file.

        Args:
            public_key: The public key object to save.
            filepath: Destination path for the PEM file.
        """
        logger.info("Saving public key to %s …", filepath)
        pem_bytes: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        dest = Path(filepath)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(pem_bytes)
        logger.info("Public key saved to %s.", filepath)

    def load_private_key(
        self,
        filepath: str,
        passphrase: Optional[bytes] = None,
    ) -> Any:
        """Load a PEM-encoded private key from disk.

        Args:
            filepath: Path to the PEM file.
            passphrase: Passphrase used to decrypt the key (if encrypted).

        Returns:
            The deserialised private key object.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            ValueError | TypeError: If the passphrase is incorrect or
                the file is malformed.
        """
        logger.info("Loading private key from %s …", filepath)
        pem_data: bytes = Path(filepath).read_bytes()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=passphrase,
            backend=default_backend(),
        )
        logger.info("Private key loaded from %s.", filepath)
        return private_key

    def load_public_key(self, filepath: str) -> Any:
        """Load a PEM-encoded public key from disk.

        Args:
            filepath: Path to the PEM file.

        Returns:
            The deserialised public key object.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            ValueError: If the file content is not a valid PEM public key.
        """
        logger.info("Loading public key from %s …", filepath)
        pem_data: bytes = Path(filepath).read_bytes()
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend(),
        )
        logger.info("Public key loaded from %s.", filepath)
        return public_key

    # ------------------------------------------------------------------
    # In-memory serialization
    # ------------------------------------------------------------------

    def serialize_private_key_pem(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
        passphrase: Optional[bytes] = None,
    ) -> bytes:
        """Serialize a private key to PEM-encoded bytes (without writing to disk).

        Args:
            private_key: The private key to serialise.
            passphrase: If provided, the PEM output is encrypted with
                AES-256-CBC using this passphrase.

        Returns:
            PEM-encoded bytes of the private key.
        """
        encryption: serialization.KeySerializationEncryption
        if passphrase is not None:
            encryption = serialization.BestAvailableEncryption(passphrase)
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def serialize_public_key_pem(
        self,
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ) -> bytes:
        """Serialize a public key to PEM-encoded bytes (without writing to disk).

        Args:
            public_key: The public key to serialise.

        Returns:
            PEM-encoded bytes of the public key.
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # ------------------------------------------------------------------
    # Key inspection
    # ------------------------------------------------------------------

    def get_key_fingerprint(
        self,
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ) -> str:
        """Compute the SHA-256 fingerprint of a public key.

        The fingerprint is derived from the DER-encoded
        SubjectPublicKeyInfo representation of the key.

        Args:
            public_key: The public key to fingerprint.

        Returns:
            A colon-separated hexadecimal string, e.g.
            ``'AA:BB:CC:DD:…'``.
        """
        der_bytes: bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest: bytes = hashlib.sha256(der_bytes).digest()
        fingerprint: str = ":".join(f"{b:02X}" for b in digest)
        return fingerprint

    def get_key_info(
        self,
        private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
    ) -> dict:
        """Return a summary dictionary describing a private key.

        Args:
            private_key: The private key to inspect.

        Returns:
            A dictionary with the following keys:

            * ``algorithm`` – ``'RSA'`` or ``'ECDSA'``.
            * ``key_size`` – Key size in bits.
            * ``fingerprint`` – SHA-256 fingerprint of the corresponding
              public key (colon-separated hex).
        """
        public_key = private_key.public_key()
        fingerprint = self.get_key_fingerprint(public_key)

        if isinstance(private_key, rsa.RSAPrivateKey):
            return {
                "algorithm": "RSA",
                "key_size": private_key.key_size,
                "fingerprint": fingerprint,
            }
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            return {
                "algorithm": "ECDSA",
                "key_size": private_key.key_size,
                "fingerprint": fingerprint,
            }
        else:
            return {
                "algorithm": "UNKNOWN",
                "key_size": getattr(private_key, "key_size", None),
                "fingerprint": fingerprint,
            }
