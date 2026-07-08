"""
Firmware Manifest Generation and Validation Module for IoT OTA Platform.

Generates and validates JSON firmware manifests that accompany firmware
binaries during secure OTA distribution.  A manifest is a self-contained
JSON document carrying:

* Firmware metadata (name, version, target device type, release notes).
* A SHA-256 hash of the firmware binary.
* A hex-encoded cryptographic signature (RSA-PSS or ECDSA).
* Signer certificate fingerprint (for traceability).
* A manifest-level integrity hash (``manifest_hash``).

Devices download the manifest **before** pulling the firmware itself,
validate its structure and integrity, then verify the firmware binary
against the manifest to confirm authenticity.

Integrates with:
    * :class:`~app.signing.signer.FirmwareSigner` — signs firmware data.
    * :class:`~app.signing.verifier.FirmwareVerifier` — verifies signatures.

Usage example::

    from app.signing.signer import FirmwareSigner
    from app.signing.manifest import FirmwareManifest

    signer = FirmwareSigner()
    signer.load_signing_key(signing_key)
    signer.load_signing_certificate(signing_cert)

    manifest_mgr = FirmwareManifest()
    manifest_mgr.set_signer(signer)

    manifest = manifest_mgr.generate_manifest(
        firmware_data=firmware_bytes,
        version="1.2.0",
        name="sensor-hub-firmware",
        target_device_type="sensor-hub-v2",
    )
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.signing.signer import FirmwareSigner
from app.signing.verifier import FirmwareVerifier

logger = logging.getLogger(__name__)

# Pre-compiled pattern for basic semantic-version validation.
# Accepts 'MAJOR.MINOR.PATCH' with optional pre-release / build suffixes.
_SEMVER_PATTERN: re.Pattern[str] = re.compile(
    r"^\d+\.\d+\.\d+([-.+].+)?$"
)


class FirmwareManifest:
    """Generates and validates JSON firmware manifests for secure OTA distribution.

    A manifest is a JSON document that contains metadata about a firmware
    binary, its cryptographic hash, the digital signature, and signer
    certificate information.  IoT devices use the manifest to verify
    firmware authenticity and integrity before installing an update.

    Attributes:
        MANIFEST_VERSION: The schema version stamped into every generated
            manifest (currently ``'1.0'``).
    """

    MANIFEST_VERSION: str = "1.0"

    # Required fields that **must** be present in every valid manifest.
    _REQUIRED_FIELDS: list[str] = [
        "manifest_version",
        "firmware_id",
        "version",
        "name",
        "target_device_type",
        "file_hash_sha256",
        "file_size_bytes",
        "signature",
        "signing_algorithm",
        "created_at",
    ]

    def __init__(self) -> None:
        """Initialise the FirmwareManifest with no signer loaded."""
        self._signer: Optional[FirmwareSigner] = None
        self._verifier: FirmwareVerifier = FirmwareVerifier()
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.logger.info("FirmwareManifest initialised.")

    # ------------------------------------------------------------------
    # Signer configuration
    # ------------------------------------------------------------------

    def set_signer(self, signer: FirmwareSigner) -> None:
        """Set the :class:`FirmwareSigner` used when generating manifests.

        Args:
            signer: A fully configured ``FirmwareSigner`` instance
                (signing key **must** already be loaded).
        """
        self._signer = signer
        self.logger.info("FirmwareSigner attached to manifest generator.")

    # ------------------------------------------------------------------
    # Manifest generation
    # ------------------------------------------------------------------

    def generate_manifest(
        self,
        firmware_data: bytes,
        version: str,
        name: str,
        target_device_type: str = "generic",
        release_notes: str = "",
        min_version: Optional[str] = None,
        firmware_id: Optional[str] = None,
        download_url: Optional[str] = None,
    ) -> dict[str, Any]:
        """Generate a complete firmware manifest.

        The generation pipeline:

        1. Compute the SHA-256 hash of *firmware_data*.
        2. Sign the firmware binary via the attached :class:`FirmwareSigner`.
        3. Assemble the manifest dictionary with all metadata fields.
        4. Compute the ``manifest_hash`` (SHA-256 of the JSON-serialized
           manifest **excluding** the ``manifest_hash`` field itself).
        5. Insert ``manifest_hash`` into the manifest.

        Args:
            firmware_data: Raw firmware binary content.
            version: Semantic version string (e.g. ``'1.2.0'``).
            name: Human-readable firmware name.
            target_device_type: Device type this firmware targets
                (default ``'generic'``).
            release_notes: Optional free-text release notes.
            min_version: Minimum currently-installed version required to
                apply this update.  ``None`` means no restriction.
            firmware_id: Unique identifier for this firmware release.
                Auto-generated as a UUID4 string when *None*.
            download_url: URL from which devices can fetch the firmware
                binary.  ``None`` if distribution uses a different channel.

        Returns:
            A dictionary representing the signed firmware manifest.  See
            the module docstring for field descriptions.

        Raises:
            RuntimeError: If no signer has been set via :meth:`set_signer`.
        """
        if self._signer is None:
            raise RuntimeError(
                "No signer configured. Call set_signer() before "
                "generating a manifest."
            )

        # --- Step 1: Hash the firmware binary ---
        file_hash: str = hashlib.sha256(firmware_data).hexdigest()
        self.logger.debug(
            "Firmware SHA-256: %s (%d bytes)", file_hash, len(firmware_data)
        )

        # --- Step 2: Sign the firmware ---
        sign_result: dict[str, Any] = self._signer.sign_firmware(firmware_data)

        # --- Step 3: Assemble manifest ---
        manifest: dict[str, Any] = {
            "manifest_version": self.MANIFEST_VERSION,
            "firmware_id": firmware_id or str(uuid4()),
            "version": version,
            "name": name,
            "target_device_type": target_device_type,
            "file_hash_sha256": file_hash,
            "file_size_bytes": len(firmware_data),
            "signature": sign_result["signature"],
            "signing_algorithm": sign_result["algorithm"],
            "signer_fingerprint": sign_result.get("signer_fingerprint"),
            "release_notes": release_notes,
            "min_version": min_version,
            "download_url": download_url,
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
        }

        # --- Steps 4-5: Compute and attach manifest hash ---
        manifest["manifest_hash"] = self._compute_manifest_hash(manifest)

        self.logger.info(
            "Manifest generated – firmware_id=%s, version=%s, name=%s",
            manifest["firmware_id"],
            version,
            name,
        )
        return manifest

    # ------------------------------------------------------------------
    # Manifest validation (structural / integrity)
    # ------------------------------------------------------------------

    def validate_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Validate a manifest's structure and internal integrity.

        Performs the following checks:

        1. **Required fields** – every field listed by
           :meth:`get_required_fields` must be present.
        2. **Manifest hash** – if ``manifest_hash`` is present the hash
           is recomputed and compared.
        3. **Version format** – ``version`` is checked against a basic
           semver pattern; non-conforming values produce a warning (not
           an error) because some teams use custom version schemes.
        4. **File size** – ``file_size_bytes`` must be a positive integer.

        Args:
            manifest: The manifest dictionary to validate.

        Returns:
            A result dictionary with:

            * ``valid`` – *True* when no errors were found.
            * ``errors`` – List of error description strings.
            * ``warnings`` – List of warning description strings.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # --- 1. Required fields ---
        for field in self.get_required_fields():
            if field not in manifest:
                errors.append(f"Missing required field: '{field}'")

        # --- 2. Manifest hash integrity ---
        if "manifest_hash" in manifest:
            expected_hash = self._compute_manifest_hash(manifest)
            if manifest["manifest_hash"] != expected_hash:
                errors.append(
                    "manifest_hash mismatch – the manifest may have been "
                    "tampered with."
                )
        else:
            warnings.append(
                "manifest_hash field is missing; integrity cannot be "
                "verified."
            )

        # --- 3. Version format ---
        version_str: Optional[str] = manifest.get("version")
        if version_str is not None and not _SEMVER_PATTERN.match(version_str):
            warnings.append(
                f"Version '{version_str}' does not follow semantic "
                "versioning (MAJOR.MINOR.PATCH)."
            )

        # --- 4. File size ---
        file_size = manifest.get("file_size_bytes")
        if file_size is not None:
            if not isinstance(file_size, int) or file_size <= 0:
                errors.append(
                    f"file_size_bytes must be a positive integer, "
                    f"got {file_size!r}."
                )

        valid: bool = len(errors) == 0

        self.logger.info(
            "Manifest validation – valid=%s, errors=%d, warnings=%d",
            valid,
            len(errors),
            len(warnings),
        )
        return {"valid": valid, "errors": errors, "warnings": warnings}

    # ------------------------------------------------------------------
    # Firmware verification against a manifest
    # ------------------------------------------------------------------

    def verify_firmware_with_manifest(
        self,
        firmware_data: bytes,
        manifest: dict[str, Any],
        public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
    ) -> dict[str, Any]:
        """Verify firmware data against its manifest using a public key.

        Three independent checks are performed:

        1. **Size** – ``len(firmware_data)`` must equal
           ``manifest['file_size_bytes']``.
        2. **Hash** – SHA-256 of *firmware_data* must equal
           ``manifest['file_hash_sha256']``.
        3. **Signature** – the hex-encoded signature in the manifest is
           verified against *firmware_data* using the supplied
           *public_key*.

        Args:
            firmware_data: Raw firmware binary content.
            manifest: The manifest dictionary to verify against.
            public_key: The RSA or ECDSA public key corresponding to the
                signing key that produced the manifest.

        Returns:
            A result dictionary with:

            * ``valid`` – *True* only when **all** checks pass.
            * ``size_valid`` – *True* if the file size matches.
            * ``hash_valid`` – *True* if the file hash matches.
            * ``signature_valid`` – *True* if the signature is authentic.
            * ``errors`` – List of error description strings.
        """
        errors: list[str] = []

        # --- 1. Size check ---
        expected_size: int = manifest.get("file_size_bytes", 0)
        actual_size: int = len(firmware_data)
        size_valid: bool = actual_size == expected_size
        if not size_valid:
            errors.append(
                f"Size mismatch: expected {expected_size} bytes, "
                f"got {actual_size} bytes."
            )

        # --- 2. Hash check ---
        expected_hash: str = manifest.get("file_hash_sha256", "")
        actual_hash: str = hashlib.sha256(firmware_data).hexdigest()
        hash_valid: bool = actual_hash == expected_hash
        if not hash_valid:
            errors.append(
                f"Hash mismatch: expected {expected_hash}, "
                f"got {actual_hash}."
            )

        # --- 3. Signature check ---
        signature_hex: str = manifest.get("signature", "")
        sig_result: dict[str, Any] = self._verifier.verify_signature(
            firmware_data, signature_hex, public_key
        )
        signature_valid: bool = sig_result["valid"]
        if not signature_valid:
            errors.append(
                sig_result.get("error", "Signature verification failed.")
            )

        overall_valid: bool = size_valid and hash_valid and signature_valid

        self.logger.info(
            "Firmware verification – size=%s, hash=%s, sig=%s, overall=%s",
            size_valid,
            hash_valid,
            signature_valid,
            overall_valid,
        )
        return {
            "valid": overall_valid,
            "size_valid": size_valid,
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "errors": errors,
        }

    def verify_firmware_with_certificate(
        self,
        firmware_data: bytes,
        manifest: dict[str, Any],
        cert: x509.Certificate,
    ) -> dict[str, Any]:
        """Verify firmware data against its manifest using an X.509 certificate.

        Extracts the public key from *cert* and delegates to
        :meth:`verify_firmware_with_manifest`.  The signer's subject
        name is appended to the result for audit / logging purposes.

        Args:
            firmware_data: Raw firmware binary content.
            manifest: The manifest dictionary to verify against.
            cert: The X.509 signing certificate whose public key
                corresponds to the key that produced the manifest.

        Returns:
            The same result dictionary as
            :meth:`verify_firmware_with_manifest`, plus:

            * ``signer_subject`` – RFC 4514 representation of the
              certificate subject.
        """
        public_key = cert.public_key()
        result: dict[str, Any] = self.verify_firmware_with_manifest(
            firmware_data, manifest, public_key
        )
        result["signer_subject"] = cert.subject.rfc4514_string()

        self.logger.info(
            "Certificate-based firmware verification – subject=%s, valid=%s",
            result["signer_subject"],
            result["valid"],
        )
        return result

    # ------------------------------------------------------------------
    # Manifest I/O
    # ------------------------------------------------------------------

    def save_manifest(self, manifest: dict[str, Any], filepath: str) -> None:
        """Save a manifest dictionary to a JSON file with pretty formatting.

        Parent directories are created automatically if they do not
        exist.

        Args:
            manifest: The manifest dictionary to persist.
            filepath: Destination file path (e.g. ``'./manifests/v1.2.0.json'``).
        """
        dest = Path(filepath)
        dest.parent.mkdir(parents=True, exist_ok=True)

        with dest.open("w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)

        self.logger.info("Manifest saved to %s.", filepath)

    def load_manifest(self, filepath: str) -> dict[str, Any]:
        """Load a manifest dictionary from a JSON file.

        Args:
            filepath: Path to the JSON manifest file.

        Returns:
            The deserialised manifest dictionary.

        Raises:
            FileNotFoundError: If *filepath* does not exist.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Manifest file not found: {filepath}")

        with path.open("r", encoding="utf-8") as fh:
            manifest: dict[str, Any] = json.load(fh)

        self.logger.info("Manifest loaded from %s.", filepath)
        return manifest

    def manifest_to_json(self, manifest: dict[str, Any]) -> str:
        """Serialize a manifest dictionary to a JSON string.

        Keys are sorted to guarantee deterministic output, which is
        important for reproducible hashing.

        Args:
            manifest: The manifest dictionary to serialise.

        Returns:
            A pretty-printed JSON string with sorted keys.
        """
        return json.dumps(manifest, indent=2, sort_keys=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_manifest_hash(self, manifest: dict[str, Any]) -> str:
        """Compute the SHA-256 hash of a manifest, excluding ``manifest_hash``.

        A copy of *manifest* is made with the ``manifest_hash`` key
        removed (if present), then serialized to JSON with sorted keys
        and hashed.

        Args:
            manifest: The manifest dictionary.

        Returns:
            A 64-character lowercase hex SHA-256 digest string.
        """
        # Work on a shallow copy to avoid mutating the original dict.
        hashable: dict[str, Any] = {
            k: v for k, v in manifest.items() if k != "manifest_hash"
        }
        canonical_json: str = json.dumps(hashable, sort_keys=True)
        digest: str = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
        self.logger.debug("Computed manifest hash: %s", digest)
        return digest

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def get_required_fields() -> list[str]:
        """Return the list of fields that must be present in every valid manifest.

        Returns:
            A list of field-name strings.
        """
        return [
            "manifest_version",
            "firmware_id",
            "version",
            "name",
            "target_device_type",
            "file_hash_sha256",
            "file_size_bytes",
            "signature",
            "signing_algorithm",
            "created_at",
        ]
