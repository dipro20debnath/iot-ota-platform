"""
Comprehensive test suite for the Firmware Manifest module.

Covers manifest generation, structural validation, firmware verification
against manifests (with both public keys and certificates), and manifest
I/O (save, load, JSON serialisation).

Run with::

    python -m pytest tests/test_manifest.py -v
    python -m unittest tests.test_manifest -v

Total: 20 tests across 4 test classes.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so ``app.*`` can be imported
# regardless of how the test runner is invoked.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.pki.key_manager import KeyManager
from app.pki.ca import CertificateAuthority
from app.signing.signer import FirmwareSigner
from app.signing.manifest import FirmwareManifest


# ======================================================================
# Manifest Generation
# ======================================================================

class TestManifestGeneration(unittest.TestCase):
    """Tests for generating firmware manifests."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        # Build minimal PKI: Root CA → Signing Certificate
        self.ca.create_root_ca(key_size=2048)
        self.signing_cert, self.signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        self.signer = FirmwareSigner()
        self.signer.load_signing_key(self.signing_key)
        self.signer.load_signing_certificate(self.signing_cert)

        self.manifest_mgr = FirmwareManifest()
        self.manifest_mgr.set_signer(self.signer)

        self.firmware_data = b"OTA firmware payload v1.0.0 for sensor-hub"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_generate_manifest(self) -> None:
        """Generated manifest contains all required fields."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="sensor-hub-firmware",
        )

        for field in FirmwareManifest.get_required_fields():
            self.assertIn(
                field, manifest, f"Required field '{field}' missing from manifest"
            )

    def test_manifest_hash_present(self) -> None:
        """manifest_hash field exists and is a 64-character hex string."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="sensor-hub-firmware",
        )

        self.assertIn("manifest_hash", manifest)
        manifest_hash: str = manifest["manifest_hash"]
        self.assertEqual(len(manifest_hash), 64)
        # Must be valid hex
        bytes.fromhex(manifest_hash)

    def test_manifest_firmware_hash(self) -> None:
        """file_hash_sha256 matches an independent hashlib.sha256 computation."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="sensor-hub-firmware",
        )

        expected_hash = hashlib.sha256(self.firmware_data).hexdigest()
        self.assertEqual(manifest["file_hash_sha256"], expected_hash)

    def test_manifest_file_size(self) -> None:
        """file_size_bytes equals len(firmware_data)."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="2.0.0",
            name="actuator-firmware",
        )

        self.assertEqual(manifest["file_size_bytes"], len(self.firmware_data))

    def test_manifest_version_field(self) -> None:
        """The version field in the manifest matches the input."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="3.1.4",
            name="gateway-firmware",
        )

        self.assertEqual(manifest["version"], "3.1.4")

    def test_manifest_has_signature(self) -> None:
        """The signature field is a non-empty valid hex string."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="sensor-hub-firmware",
        )

        sig: str = manifest["signature"]
        self.assertIsInstance(sig, str)
        self.assertGreater(len(sig), 0)
        # Must parse as hex without raising
        bytes.fromhex(sig)

    def test_generate_without_signer_raises(self) -> None:
        """Calling generate_manifest without a signer raises RuntimeError."""
        bare_manifest = FirmwareManifest()
        with self.assertRaises(RuntimeError):
            bare_manifest.generate_manifest(
                firmware_data=self.firmware_data,
                version="1.0.0",
                name="should-fail",
            )

    def test_manifest_with_all_optional_fields(self) -> None:
        """All optional fields appear in the manifest when supplied."""
        manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="2.5.0",
            name="temp-sensor-fw",
            target_device_type="temp-sensor-v3",
            release_notes="Bug fixes and performance improvements.",
            min_version="2.0.0",
            firmware_id="custom-firmware-id-001",
            download_url="https://ota.example.com/fw/temp-sensor-v3/2.5.0.bin",
        )

        self.assertEqual(manifest["target_device_type"], "temp-sensor-v3")
        self.assertEqual(
            manifest["release_notes"],
            "Bug fixes and performance improvements.",
        )
        self.assertEqual(manifest["min_version"], "2.0.0")
        self.assertEqual(manifest["firmware_id"], "custom-firmware-id-001")
        self.assertEqual(
            manifest["download_url"],
            "https://ota.example.com/fw/temp-sensor-v3/2.5.0.bin",
        )


# ======================================================================
# Manifest Validation (structural + integrity)
# ======================================================================

class TestManifestValidation(unittest.TestCase):
    """Tests for validating firmware manifest structure and integrity."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        self.ca.create_root_ca(key_size=2048)
        signing_cert, signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        signer = FirmwareSigner()
        signer.load_signing_key(signing_key)
        signer.load_signing_certificate(signing_cert)

        self.manifest_mgr = FirmwareManifest()
        self.manifest_mgr.set_signer(signer)

        self.firmware_data = b"validation-test firmware payload"
        self.manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="validation-test",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_validate_valid_manifest(self) -> None:
        """A freshly generated manifest passes validation with no errors."""
        result = self.manifest_mgr.validate_manifest(self.manifest)

        self.assertTrue(result["valid"])
        self.assertEqual(len(result["errors"]), 0)

    def test_validate_missing_field(self) -> None:
        """Removing a required field causes validation to fail."""
        broken = dict(self.manifest)
        del broken["firmware_id"]

        result = self.manifest_mgr.validate_manifest(broken)

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("firmware_id" in e for e in result["errors"]),
            "Expected an error mentioning 'firmware_id'",
        )

    def test_validate_tampered_hash(self) -> None:
        """Changing manifest_hash causes validation to fail."""
        tampered = dict(self.manifest)
        tampered["manifest_hash"] = "0" * 64

        result = self.manifest_mgr.validate_manifest(tampered)

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("manifest_hash" in e for e in result["errors"]),
            "Expected an error about manifest_hash mismatch",
        )

    def test_validate_bad_version(self) -> None:
        """A non-semver version string produces a warning."""
        odd_version = dict(self.manifest)
        odd_version["version"] = "abc"
        # Recompute manifest_hash so only the version format triggers a warning
        odd_version["manifest_hash"] = self.manifest_mgr._compute_manifest_hash(
            odd_version
        )

        result = self.manifest_mgr.validate_manifest(odd_version)

        # Warnings are expected, but it may still be structurally valid
        self.assertTrue(
            any("abc" in w for w in result["warnings"]),
            "Expected a warning about non-semver version 'abc'",
        )


# ======================================================================
# Firmware Verification with Manifest
# ======================================================================

class TestFirmwareVerificationWithManifest(unittest.TestCase):
    """Tests for verifying firmware data against a manifest."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        self.ca.create_root_ca(key_size=2048)
        self.signing_cert, self.signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        self.signer = FirmwareSigner()
        self.signer.load_signing_key(self.signing_key)
        self.signer.load_signing_certificate(self.signing_cert)

        self.manifest_mgr = FirmwareManifest()
        self.manifest_mgr.set_signer(self.signer)

        self.firmware_data = b"verification-test firmware binary payload"
        self.manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="verify-test",
        )

        self.public_key = self.signing_key.public_key()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_verify_valid_firmware(self) -> None:
        """Valid firmware passes all verification checks."""
        result = self.manifest_mgr.verify_firmware_with_manifest(
            self.firmware_data, self.manifest, self.public_key
        )

        self.assertTrue(result["valid"])
        self.assertTrue(result["size_valid"])
        self.assertTrue(result["hash_valid"])
        self.assertTrue(result["signature_valid"])
        self.assertEqual(len(result["errors"]), 0)

    def test_verify_tampered_firmware(self) -> None:
        """Tampered firmware (same length substitution) fails hash check."""
        # Replace last byte to keep size identical
        tampered = self.firmware_data[:-1] + bytes(
            [(self.firmware_data[-1] + 1) % 256]
        )

        result = self.manifest_mgr.verify_firmware_with_manifest(
            tampered, self.manifest, self.public_key
        )

        self.assertFalse(result["valid"])
        self.assertFalse(result["hash_valid"])

    def test_verify_wrong_size(self) -> None:
        """Firmware with a different size fails size check."""
        wrong_size_data = self.firmware_data + b"EXTRA-BYTES"

        result = self.manifest_mgr.verify_firmware_with_manifest(
            wrong_size_data, self.manifest, self.public_key
        )

        self.assertFalse(result["valid"])
        self.assertFalse(result["size_valid"])

    def test_verify_wrong_key(self) -> None:
        """Verification with an unrelated key fails signature check."""
        other_priv, other_pub = self.km.generate_rsa_key_pair(key_size=2048)

        result = self.manifest_mgr.verify_firmware_with_manifest(
            self.firmware_data, self.manifest, other_pub
        )

        self.assertFalse(result["valid"])
        self.assertFalse(result["signature_valid"])

    def test_verify_with_certificate(self) -> None:
        """Certificate-based verification succeeds and includes signer_subject."""
        result = self.manifest_mgr.verify_firmware_with_certificate(
            self.firmware_data, self.manifest, self.signing_cert
        )

        self.assertTrue(result["valid"])
        self.assertIn("signer_subject", result)
        self.assertIsNotNone(result["signer_subject"])


# ======================================================================
# Manifest I/O
# ======================================================================

class TestManifestIO(unittest.TestCase):
    """Tests for saving, loading, and serialising manifests."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        self.ca.create_root_ca(key_size=2048)
        signing_cert, signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        signer = FirmwareSigner()
        signer.load_signing_key(signing_key)
        signer.load_signing_certificate(signing_cert)

        self.manifest_mgr = FirmwareManifest()
        self.manifest_mgr.set_signer(signer)

        self.firmware_data = b"io-test firmware binary content"
        self.manifest = self.manifest_mgr.generate_manifest(
            firmware_data=self.firmware_data,
            version="1.0.0",
            name="io-test",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_save_and_load(self) -> None:
        """Saving a manifest and loading it back produces identical data."""
        filepath = os.path.join(self.tmp_dir.name, "manifests", "test.json")

        self.manifest_mgr.save_manifest(self.manifest, filepath)
        loaded = self.manifest_mgr.load_manifest(filepath)

        self.assertEqual(self.manifest, loaded)

    def test_manifest_to_json(self) -> None:
        """manifest_to_json produces valid JSON that round-trips correctly."""
        json_str = self.manifest_mgr.manifest_to_json(self.manifest)

        # Must be parseable JSON
        parsed = json.loads(json_str)
        self.assertEqual(parsed, self.manifest)

    def test_json_sorted_keys(self) -> None:
        """JSON output has keys sorted alphabetically."""
        json_str = self.manifest_mgr.manifest_to_json(self.manifest)
        parsed = json.loads(json_str)

        keys = list(parsed.keys())
        self.assertEqual(keys, sorted(keys))


# ======================================================================
# Entry point
# ======================================================================

if __name__ == "__main__":
    unittest.main()
