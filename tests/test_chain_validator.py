"""
Comprehensive test suite for the Chain Validator module.

Covers full-chain validation, signature verification, validity-period
checking, revocation detection, and chain-summary generation.

Run with::

    python -m pytest tests/test_chain_validator.py -v
    python -m unittest tests.test_chain_validator -v
"""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so ``app.pki`` can be imported
# regardless of how the test runner is invoked.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
from cryptography.x509.oid import ExtensionOID, NameOID

from app.pki.ca import CertificateAuthority
from app.pki.chain_validator import ChainValidator
from app.pki.key_manager import KeyManager


# ======================================================================
# Helper: build an expired certificate for testing
# ======================================================================


def _build_expired_cert(
    issuer_cert: x509.Certificate,
    issuer_key,
    km: KeyManager,
) -> x509.Certificate:
    """Create a certificate whose validity window is entirely in the past.

    The certificate is valid from 10 days ago to 1 day ago, so it is
    expired at the time of the test.
    """
    device_key, _ = km.generate_rsa_key_pair(key_size=2048)

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Expired Device"),
        ]))
        .issuer_name(issuer_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now - timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


# ======================================================================
# Chain Validation
# ======================================================================


class TestChainValidation(unittest.TestCase):
    """Tests for end-to-end certificate chain validation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )

        # Build a full chain: root → intermediate → device
        self.root_cert, self.root_key = self.ca.create_root_ca(
            common_name="Test Root CA",
            key_size=2048,
        )
        self.inter_cert, self.inter_key = self.ca.create_intermediate_ca(
            common_name="Test Intermediate CA",
            key_size=2048,
        )
        self.device_cert, self.device_key = self.ca.issue_device_certificate(
            device_id="chain-dev-001",
            common_name="Chain Test Device",
        )

        self.validator = ChainValidator()
        self.validator.add_trusted_root(self.root_cert)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_valid_full_chain(self) -> None:
        """A valid [device, intermediate, root] chain passes validation."""
        result = self.validator.validate_chain([
            self.device_cert,
            self.inter_cert,
            self.root_cert,
        ])

        self.assertTrue(result["valid"], f"Errors: {result['errors']}")
        self.assertEqual(result["chain_length"], 3)
        self.assertEqual(result["errors"], [])

    def test_valid_two_level_chain(self) -> None:
        """A valid [device, root] chain passes when device is signed by root directly."""
        # Create a CA without intermediate, issuing directly from root
        ca2 = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        root2, _ = ca2.create_root_ca(
            common_name="Direct Root CA",
            key_size=2048,
        )
        device2, _ = ca2.issue_device_certificate(
            device_id="direct-dev",
            common_name="Direct Device",
            use_intermediate=False,
        )

        validator2 = ChainValidator()
        validator2.add_trusted_root(root2)

        result = validator2.validate_chain([device2, root2])

        self.assertTrue(result["valid"], f"Errors: {result['errors']}")
        self.assertEqual(result["chain_length"], 2)

    def test_empty_chain(self) -> None:
        """An empty chain is invalid."""
        result = self.validator.validate_chain([])

        self.assertFalse(result["valid"])
        self.assertEqual(result["chain_length"], 0)
        self.assertGreater(len(result["errors"]), 0)
        self.assertIn("empty", result["errors"][0].lower())

    def test_untrusted_root(self) -> None:
        """A chain with an untrusted root is invalid."""
        # Create a second, untrusted root
        ca2 = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        untrusted_root, _ = ca2.create_root_ca(
            common_name="Untrusted Root",
            key_size=2048,
        )
        ca2.create_intermediate_ca(common_name="Untrusted Inter", key_size=2048)
        untrusted_device, _ = ca2.issue_device_certificate(
            device_id="untrusted-dev",
            common_name="Untrusted Device",
        )

        # Use the original validator which only trusts self.root_cert
        result = self.validator.validate_chain([
            untrusted_device,
            ca2._intermediate_ca_cert,
            untrusted_root,
        ])

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("not in the trusted" in e for e in result["errors"]),
            f"Expected trust error, got: {result['errors']}",
        )

    def test_expired_cert_in_chain(self) -> None:
        """A chain containing an expired certificate is invalid."""
        expired_cert = _build_expired_cert(
            self.inter_cert,
            self.inter_key,
            self.km,
        )

        result = self.validator.validate_chain([
            expired_cert,
            self.inter_cert,
            self.root_cert,
        ])

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("expired" in e.lower() for e in result["errors"]),
            f"Expected expiry error, got: {result['errors']}",
        )

    def test_revoked_cert_in_chain(self) -> None:
        """A chain containing a revoked certificate is invalid."""
        inter_serial = format(self.inter_cert.serial_number, "X")
        self.validator.add_revoked_serial(inter_serial)

        result = self.validator.validate_chain([
            self.device_cert,
            self.inter_cert,
            self.root_cert,
        ])

        self.assertFalse(result["valid"])
        self.assertTrue(
            any("revoked" in e.lower() for e in result["errors"]),
            f"Expected revocation error, got: {result['errors']}",
        )


# ======================================================================
# Signature Verification
# ======================================================================


class TestSignatureVerification(unittest.TestCase):
    """Tests for individual certificate signature verification."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )

        self.root_cert, _ = self.ca.create_root_ca(
            common_name="Sig Root CA",
            key_size=2048,
        )
        self.inter_cert, _ = self.ca.create_intermediate_ca(
            common_name="Sig Intermediate CA",
            key_size=2048,
        )
        self.device_cert, _ = self.ca.issue_device_certificate(
            device_id="sig-dev",
            common_name="Sig Test Device",
        )
        self.validator = ChainValidator()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_verify_intermediate_signature(self) -> None:
        """Intermediate cert signature is valid against root cert."""
        self.assertTrue(
            self.validator.verify_signature(self.inter_cert, self.root_cert)
        )

    def test_verify_device_signature(self) -> None:
        """Device cert signature is valid against intermediate cert."""
        self.assertTrue(
            self.validator.verify_signature(self.device_cert, self.inter_cert)
        )

    def test_verify_wrong_issuer(self) -> None:
        """Device cert signature is INVALID against root cert (wrong issuer)."""
        self.assertFalse(
            self.validator.verify_signature(self.device_cert, self.root_cert)
        )


# ======================================================================
# Validity Period
# ======================================================================


class TestValidityPeriod(unittest.TestCase):
    """Tests for certificate validity-period checking."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.root_cert, self.root_key = self.ca.create_root_ca(
            common_name="Validity Root CA",
            key_size=2048,
        )
        self.ca.create_intermediate_ca(
            common_name="Validity Intermediate CA",
            key_size=2048,
        )
        self.validator = ChainValidator()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_valid_cert(self) -> None:
        """A currently valid certificate passes the validity check."""
        result = self.validator.check_validity_period(self.root_cert)

        self.assertTrue(result["valid"])
        self.assertFalse(result["is_expired"])
        self.assertFalse(result["not_yet_valid"])

    def test_expired_cert(self) -> None:
        """An expired certificate is flagged correctly."""
        expired = _build_expired_cert(
            self.ca._intermediate_ca_cert,
            self.ca._intermediate_ca_key,
            self.km,
        )

        result = self.validator.check_validity_period(expired)

        self.assertFalse(result["valid"])
        self.assertTrue(result["is_expired"])


# ======================================================================
# Revocation Check
# ======================================================================


class TestRevocationCheck(unittest.TestCase):
    """Tests for the revocation-check method."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.root_cert, _ = self.ca.create_root_ca(
            common_name="Revoke Root CA",
            key_size=2048,
        )
        self.validator = ChainValidator()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_not_revoked(self) -> None:
        """A clean certificate is not reported as revoked."""
        result = self.validator.check_revocation(self.root_cert)

        self.assertFalse(result["revoked"])
        self.assertEqual(
            result["serial_number"],
            format(self.root_cert.serial_number, "X"),
        )

    def test_revoked(self) -> None:
        """A certificate with its serial in the revocation set is revoked."""
        serial = format(self.root_cert.serial_number, "X")
        self.validator.add_revoked_serial(serial)

        result = self.validator.check_revocation(self.root_cert)

        self.assertTrue(result["revoked"])


# ======================================================================
# Chain Summary
# ======================================================================


class TestChainSummary(unittest.TestCase):
    """Tests for the chain-summary helper."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )

        self.root_cert, _ = self.ca.create_root_ca(
            common_name="Summary Root CA",
            key_size=2048,
        )
        self.inter_cert, _ = self.ca.create_intermediate_ca(
            common_name="Summary Intermediate CA",
            key_size=2048,
        )
        self.device_cert, _ = self.ca.issue_device_certificate(
            device_id="summary-dev",
            common_name="Summary Device",
        )
        self.validator = ChainValidator()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_chain_summary(self) -> None:
        """Chain summary returns correct number of entries with expected data."""
        chain = [self.device_cert, self.inter_cert, self.root_cert]
        summary = self.validator.get_chain_summary(chain)

        self.assertEqual(len(summary), 3)

        # Leaf (device)
        self.assertEqual(summary[0]["subject"], "Summary Device")
        self.assertFalse(summary[0]["is_ca"])

        # Intermediate
        self.assertEqual(summary[1]["subject"], "Summary Intermediate CA")
        self.assertTrue(summary[1]["is_ca"])

        # Root
        self.assertEqual(summary[2]["subject"], "Summary Root CA")
        self.assertTrue(summary[2]["is_ca"])

        # Every entry must have the required keys
        for entry in summary:
            for key in ("subject", "issuer", "serial_number", "not_before", "not_after", "is_ca"):
                self.assertIn(key, entry, f"Missing key '{key}' in summary entry")


# ======================================================================
# Entry point
# ======================================================================

if __name__ == "__main__":
    unittest.main()
