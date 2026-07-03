"""
Comprehensive test suite for the Firmware Code Signing and Verification modules.

Covers RSA-PSS and ECDSA signing, signature verification, hash verification,
complete (hash + signature) verification, tamper detection, and error handling.

Run with::

    python -m pytest tests/test_signing.py -v
    python -m unittest tests.test_signing -v

Total: 22 tests across 4 test classes.
"""

import hashlib
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
from app.signing.verifier import FirmwareVerifier


# ======================================================================
# RSA Firmware Signing
# ======================================================================

class TestFirmwareSigning(unittest.TestCase):
    """Tests for firmware signing with RSA keys."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        # Build a minimal PKI: Root CA → Signing Certificate
        self.ca.create_root_ca(key_size=2048)
        self.signing_cert, self.signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        self.signer = FirmwareSigner()
        self.signer.load_signing_key(self.signing_key)
        self.signer.load_signing_certificate(self.signing_cert)

        self.firmware_data = b"IoT firmware binary payload v1.0.0"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_sign_firmware_rsa(self) -> None:
        """Signing firmware produces a result dict with all required fields."""
        result = self.signer.sign_firmware(self.firmware_data)

        self.assertIn("signature", result)
        self.assertIn("algorithm", result)
        self.assertIn("hash_sha256", result)
        self.assertIn("file_size", result)
        self.assertIn("signed_at", result)
        self.assertIn("signer_fingerprint", result)

        # Signature must be a valid hex string
        bytes.fromhex(result["signature"])

    def test_sign_firmware_returns_hash(self) -> None:
        """The hash_sha256 in the result matches a manual hashlib computation."""
        result = self.signer.sign_firmware(self.firmware_data)
        expected_hash = hashlib.sha256(self.firmware_data).hexdigest()
        self.assertEqual(result["hash_sha256"], expected_hash)

    def test_sign_firmware_algorithm(self) -> None:
        """RSA key produces an 'RSA-PSS' algorithm label."""
        result = self.signer.sign_firmware(self.firmware_data)
        self.assertEqual(result["algorithm"], "RSA-PSS")

    def test_sign_different_data_different_signatures(self) -> None:
        """Two different firmware payloads produce different signatures."""
        result_a = self.signer.sign_firmware(b"firmware-version-1")
        result_b = self.signer.sign_firmware(b"firmware-version-2")
        self.assertNotEqual(result_a["signature"], result_b["signature"])

    def test_sign_same_data_same_hash(self) -> None:
        """Signing the same data twice always produces the same hash."""
        result_a = self.signer.sign_firmware(self.firmware_data)
        result_b = self.signer.sign_firmware(self.firmware_data)
        self.assertEqual(result_a["hash_sha256"], result_b["hash_sha256"])

    def test_sign_firmware_file(self) -> None:
        """Signing from a file produces a result consistent with in-memory signing."""
        filepath = os.path.join(self.tmp_dir.name, "firmware.bin")
        Path(filepath).write_bytes(self.firmware_data)

        file_result = self.signer.sign_firmware_file(filepath)
        mem_result = self.signer.sign_firmware(self.firmware_data)

        # Hash and file_size must be identical; signatures may differ (RSA-PSS
        # uses randomised salt) but both must be valid hex strings.
        self.assertEqual(file_result["hash_sha256"], mem_result["hash_sha256"])
        self.assertEqual(file_result["file_size"], mem_result["file_size"])
        self.assertEqual(file_result["algorithm"], mem_result["algorithm"])

    def test_signer_info(self) -> None:
        """get_signer_info returns key and certificate metadata."""
        info = self.signer.get_signer_info()

        self.assertTrue(info["key_loaded"])
        self.assertEqual(info["key_type"], "RSA")
        self.assertIsNotNone(info["key_size"])
        self.assertTrue(info["cert_loaded"])
        self.assertIsNotNone(info["cert_subject"])
        self.assertIsNotNone(info["cert_fingerprint"])

    def test_sign_without_key_raises(self) -> None:
        """Signing without a loaded key raises RuntimeError."""
        empty_signer = FirmwareSigner()
        with self.assertRaises(RuntimeError):
            empty_signer.sign_firmware(self.firmware_data)


# ======================================================================
# Firmware Verification
# ======================================================================

class TestFirmwareVerification(unittest.TestCase):
    """Tests for firmware signature verification with RSA keys."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name, key_manager=self.km
        )

        # Build PKI and sign firmware
        self.ca.create_root_ca(key_size=2048)
        self.signing_cert, self.signing_key = self.ca.issue_signing_certificate(
            key_size=2048
        )

        self.signer = FirmwareSigner()
        self.signer.load_signing_key(self.signing_key)
        self.signer.load_signing_certificate(self.signing_cert)

        self.firmware_data = b"IoT firmware binary payload v2.0.0"
        self.sign_result = self.signer.sign_firmware(self.firmware_data)

        self.verifier = FirmwareVerifier()
        self.public_key = self.signing_key.public_key()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_verify_valid_signature(self) -> None:
        """A valid signature is recognised as authentic."""
        result = self.verifier.verify_signature(
            self.firmware_data,
            self.sign_result["signature"],
            self.public_key,
        )
        self.assertTrue(result["valid"])
        self.assertIsNone(result["error"])

    def test_verify_tampered_data(self) -> None:
        """Tampered firmware data fails signature verification."""
        tampered = self.firmware_data + b"TAMPERED"
        result = self.verifier.verify_signature(
            tampered,
            self.sign_result["signature"],
            self.public_key,
        )
        self.assertFalse(result["valid"])
        self.assertIsNotNone(result["error"])

    def test_verify_wrong_key(self) -> None:
        """Verification with a different key fails."""
        other_priv, other_pub = self.km.generate_rsa_key_pair(key_size=2048)
        result = self.verifier.verify_signature(
            self.firmware_data,
            self.sign_result["signature"],
            other_pub,
        )
        self.assertFalse(result["valid"])

    def test_verify_with_certificate(self) -> None:
        """Verification through a certificate succeeds and includes signer_subject."""
        result = self.verifier.verify_with_certificate(
            self.firmware_data,
            self.sign_result["signature"],
            self.signing_cert,
        )
        self.assertTrue(result["valid"])
        self.assertIn("signer_subject", result)
        self.assertIsNotNone(result["signer_subject"])

    def test_verify_hash_valid(self) -> None:
        """Hash verification passes when the expected hash matches."""
        expected_hash = hashlib.sha256(self.firmware_data).hexdigest()
        result = self.verifier.verify_hash(self.firmware_data, expected_hash)
        self.assertTrue(result["valid"])
        self.assertEqual(result["expected"], result["actual"])

    def test_verify_hash_tampered(self) -> None:
        """Hash verification fails when data has been tampered with."""
        original_hash = hashlib.sha256(self.firmware_data).hexdigest()
        tampered = self.firmware_data + b"TAMPERED"
        result = self.verifier.verify_hash(tampered, original_hash)
        self.assertFalse(result["valid"])
        self.assertNotEqual(result["expected"], result["actual"])

    def test_verify_complete_valid(self) -> None:
        """Complete verification (hash + signature) passes for valid data."""
        expected_hash = hashlib.sha256(self.firmware_data).hexdigest()
        result = self.verifier.verify_complete(
            self.firmware_data,
            self.sign_result["signature"],
            expected_hash,
            self.signing_cert,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["hash_check"]["valid"])
        self.assertTrue(result["signature_check"]["valid"])

    def test_verify_complete_bad_hash(self) -> None:
        """Complete verification fails when the expected hash is wrong."""
        bad_hash = "0" * 64  # Deliberately wrong hash
        result = self.verifier.verify_complete(
            self.firmware_data,
            self.sign_result["signature"],
            bad_hash,
            self.signing_cert,
        )
        self.assertFalse(result["valid"])
        self.assertFalse(result["hash_check"]["valid"])
        # The signature itself is still valid
        self.assertTrue(result["signature_check"]["valid"])

    def test_verify_complete_bad_sig(self) -> None:
        """Complete verification fails when the signature is tampered."""
        expected_hash = hashlib.sha256(self.firmware_data).hexdigest()

        # Tamper the signature by flipping a byte
        sig_bytes = bytes.fromhex(self.sign_result["signature"])
        tampered_sig_bytes = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        tampered_sig_hex = tampered_sig_bytes.hex()

        result = self.verifier.verify_complete(
            self.firmware_data,
            tampered_sig_hex,
            expected_hash,
            self.signing_cert,
        )
        self.assertFalse(result["valid"])
        # Hash is fine, but signature is not
        self.assertTrue(result["hash_check"]["valid"])
        self.assertFalse(result["signature_check"]["valid"])


# ======================================================================
# ECDSA Signing and Verification
# ======================================================================

class TestECDSASigning(unittest.TestCase):
    """Tests for firmware signing and verification with ECDSA keys."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)

        # Generate an ECDSA P-256 key pair directly (the CA issues RSA
        # certs, so we use the KeyManager to generate ECDSA keys and load
        # them into the signer manually).
        self.ec_private, self.ec_public = self.km.generate_ecdsa_key_pair(
            curve="P-256"
        )

        self.signer = FirmwareSigner()
        self.signer.load_signing_key(self.ec_private)

        self.verifier = FirmwareVerifier()
        self.firmware_data = b"ECDSA-signed IoT firmware payload v3.0.0"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_sign_ecdsa(self) -> None:
        """ECDSA signing reports algorithm as 'ECDSA'."""
        result = self.signer.sign_firmware(self.firmware_data)
        self.assertEqual(result["algorithm"], "ECDSA")
        # Signature must be valid hex
        bytes.fromhex(result["signature"])

    def test_verify_ecdsa(self) -> None:
        """An ECDSA-signed firmware verifies successfully."""
        sign_result = self.signer.sign_firmware(self.firmware_data)
        verify_result = self.verifier.verify_signature(
            self.firmware_data,
            sign_result["signature"],
            self.ec_public,
        )
        self.assertTrue(verify_result["valid"])
        self.assertEqual(verify_result["algorithm"], "ECDSA")

    def test_ecdsa_tamper_detection(self) -> None:
        """Tampered data fails ECDSA verification."""
        sign_result = self.signer.sign_firmware(self.firmware_data)
        tampered = self.firmware_data + b"EVIL"
        verify_result = self.verifier.verify_signature(
            tampered,
            sign_result["signature"],
            self.ec_public,
        )
        self.assertFalse(verify_result["valid"])


# ======================================================================
# Hash Computation
# ======================================================================

class TestComputeHash(unittest.TestCase):
    """Tests for the FirmwareSigner.compute_hash utility."""

    def setUp(self) -> None:
        self.signer = FirmwareSigner()
        self.data = b"hash-test-data-payload"

    # ------------------------------------------------------------------

    def test_sha256_hash(self) -> None:
        """SHA-256 hash is 64 hex characters."""
        digest = self.signer.compute_hash(self.data, algorithm="sha256")
        self.assertEqual(len(digest), 64)
        # Must be valid hex
        bytes.fromhex(digest)

    def test_sha384_hash(self) -> None:
        """SHA-384 hash is 96 hex characters."""
        digest = self.signer.compute_hash(self.data, algorithm="sha384")
        self.assertEqual(len(digest), 96)
        bytes.fromhex(digest)

    def test_hash_consistency(self) -> None:
        """The same data always produces the same hash."""
        hash_a = self.signer.compute_hash(self.data)
        hash_b = self.signer.compute_hash(self.data)
        self.assertEqual(hash_a, hash_b)


# ======================================================================
# Entry point
# ======================================================================

if __name__ == "__main__":
    unittest.main()
