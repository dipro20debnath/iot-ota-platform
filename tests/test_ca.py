"""
Comprehensive test suite for the Certificate Authority module.

Covers Root CA creation, Intermediate CA issuance, device certificate
issuance, signing certificate issuance, certificate revocation, and
certificate information/serialization utilities.

Run with::

    python -m pytest tests/test_ca.py -v
    python -m unittest tests.test_ca -v
"""

import os
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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.pki.ca import CertificateAuthority
from app.pki.key_manager import KeyManager


# ======================================================================
# Root CA Creation
# ======================================================================


class TestRootCACreation(unittest.TestCase):
    """Tests for self-signed Root CA creation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_create_root_ca_defaults(self) -> None:
        """Root CA is self-signed: subject == issuer and ca=True."""
        cert, _key = self.ca.create_root_ca()

        # Self-signed: subject matches issuer
        self.assertEqual(cert.subject, cert.issuer)

        # CA flag must be True
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(bc.value.ca)

    def test_root_ca_key_size(self) -> None:
        """Root CA with 4096-bit key has the correct key size."""
        cert, key = self.ca.create_root_ca(key_size=4096)

        self.assertIsInstance(key, rsa.RSAPrivateKey)
        self.assertEqual(key.key_size, 4096)

        # The certificate's embedded public key should also be 4096 bits
        pub = cert.public_key()
        self.assertIsInstance(pub, rsa.RSAPublicKey)
        self.assertEqual(pub.key_size, 4096)

    def test_root_ca_extensions(self) -> None:
        """Root CA carries BasicConstraints(ca=True) and KeyUsage(key_cert_sign, crl_sign)."""
        cert, _ = self.ca.create_root_ca()

        # BasicConstraints
        bc = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(bc.critical)
        self.assertTrue(bc.value.ca)

        # KeyUsage
        ku = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        )
        self.assertTrue(ku.critical)
        self.assertTrue(ku.value.key_cert_sign)
        self.assertTrue(ku.value.crl_sign)

    def test_root_ca_validity_period(self) -> None:
        """Root CA created with 3650-day validity has correct not_after."""
        validity_days = 3650
        cert, _ = self.ca.create_root_ca(validity_days=validity_days)

        expected_expiry = datetime.now(timezone.utc) + timedelta(days=validity_days)
        actual_expiry = cert.not_valid_after_utc

        # Allow 60-second tolerance for test execution time
        delta = abs((expected_expiry - actual_expiry).total_seconds())
        self.assertLess(delta, 60)

    def test_root_ca_persistence(self) -> None:
        """Root CA cert and key files are saved to disk."""
        cert, _ = self.ca.create_root_ca()

        cert_path = Path(self.tmp_dir.name) / "certs" / "root_ca.pem"
        key_path = Path(self.tmp_dir.name) / "keys" / "root_ca_key.pem"

        self.assertTrue(cert_path.exists(), f"Cert file not found: {cert_path}")
        self.assertTrue(key_path.exists(), f"Key file not found: {key_path}")

        # Verify the saved cert can be loaded and matches
        loaded = x509.load_pem_x509_certificate(cert_path.read_bytes())
        self.assertEqual(loaded.serial_number, cert.serial_number)


# ======================================================================
# Intermediate CA Creation
# ======================================================================


class TestIntermediateCACreation(unittest.TestCase):
    """Tests for Intermediate CA issuance by the Root CA."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_create_intermediate_ca(self) -> None:
        """Intermediate CA issuer matches Root CA subject."""
        root_cert, _ = self.ca.create_root_ca()
        inter_cert, _ = self.ca.create_intermediate_ca()

        # Issuer of intermediate == subject of root
        self.assertEqual(inter_cert.issuer, root_cert.subject)

        # Intermediate is NOT self-signed
        self.assertNotEqual(inter_cert.subject, inter_cert.issuer)

    def test_intermediate_without_root_raises(self) -> None:
        """Creating intermediate CA without root raises RuntimeError."""
        with self.assertRaises(RuntimeError):
            self.ca.create_intermediate_ca()

    def test_intermediate_ca_extensions(self) -> None:
        """Intermediate CA has BasicConstraints(ca=True, path_length=0)."""
        self.ca.create_root_ca()
        inter_cert, _ = self.ca.create_intermediate_ca()

        bc = inter_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertTrue(bc.value.ca)
        self.assertEqual(bc.value.path_length, 0)

    def test_intermediate_signed_by_root(self) -> None:
        """Intermediate CA signature is verifiable with Root CA public key."""
        root_cert, _ = self.ca.create_root_ca()
        inter_cert, _ = self.ca.create_intermediate_ca()

        # Verify signature using the root's public key.
        # If the signature is invalid, verify() raises InvalidSignature.
        root_pub = root_cert.public_key()
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        # This should NOT raise — the intermediate was signed by root.
        root_pub.verify(
            inter_cert.signature,
            inter_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            inter_cert.signature_hash_algorithm,
        )


# ======================================================================
# Device Certificate Issuance
# ======================================================================


class TestDeviceCertificateIssuance(unittest.TestCase):
    """Tests for end-entity device certificate issuance."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.ca.create_root_ca()
        self.ca.create_intermediate_ca()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_issue_device_cert(self) -> None:
        """Device certificate is NOT a CA."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="dev-001",
            common_name="IoT Device 001",
        )

        bc = device_cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        self.assertFalse(bc.value.ca)

    def test_device_cert_subject(self) -> None:
        """Device certificate's CN matches the requested common_name."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="dev-002",
            common_name="IoT Device 002",
        )

        cn_attrs = device_cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )
        self.assertEqual(len(cn_attrs), 1)
        self.assertEqual(cn_attrs[0].value, "IoT Device 002")

    def test_device_cert_signed_by_intermediate(self) -> None:
        """Device certificate is signed by the Intermediate CA."""
        inter_cert = self.ca._intermediate_ca_cert
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="dev-003",
            common_name="IoT Device 003",
        )

        # Issuer of device cert == subject of intermediate CA
        self.assertEqual(device_cert.issuer, inter_cert.subject)

        # Verify cryptographic signature
        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        inter_cert.public_key().verify(
            device_cert.signature,
            device_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            device_cert.signature_hash_algorithm,
        )

    def test_device_cert_persistence(self) -> None:
        """Device cert and key files are saved to disk."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="dev-004",
            common_name="IoT Device 004",
        )

        cert_path = Path(self.tmp_dir.name) / "certs" / "device_dev-004.pem"
        key_path = Path(self.tmp_dir.name) / "keys" / "device_dev-004_key.pem"

        self.assertTrue(cert_path.exists(), f"Cert file not found: {cert_path}")
        self.assertTrue(key_path.exists(), f"Key file not found: {key_path}")


# ======================================================================
# Signing Certificate
# ======================================================================


class TestSigningCertificate(unittest.TestCase):
    """Tests for firmware code-signing certificate issuance."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.ca.create_root_ca()
        self.ca.create_intermediate_ca()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_issue_signing_cert(self) -> None:
        """Signing certificate has CODE_SIGNING extended key usage."""
        from cryptography.x509.oid import ExtendedKeyUsageOID

        signing_cert, _ = self.ca.issue_signing_certificate()

        eku = signing_cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        oid_list = list(eku.value)
        self.assertIn(ExtendedKeyUsageOID.CODE_SIGNING, oid_list)

    def test_signing_cert_signed_by_ca(self) -> None:
        """Signing certificate's signature is verifiable by the issuing CA."""
        signing_cert, _ = self.ca.issue_signing_certificate()

        # The signing cert should be issued by the intermediate CA
        issuer_cert = self.ca._intermediate_ca_cert

        from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

        issuer_cert.public_key().verify(
            signing_cert.signature,
            signing_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            signing_cert.signature_hash_algorithm,
        )


# ======================================================================
# Certificate Revocation
# ======================================================================


class TestCertificateRevocation(unittest.TestCase):
    """Tests for certificate revocation tracking."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.ca.create_root_ca()
        self.ca.create_intermediate_ca()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_revoke_certificate(self) -> None:
        """Revoking a certificate makes is_revoked return True."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="rev-001",
            common_name="Revoke Test Device",
        )

        self.assertFalse(self.ca.is_revoked(device_cert))
        self.ca.revoke_certificate(device_cert, reason="key_compromise")
        self.assertTrue(self.ca.is_revoked(device_cert))

    def test_not_revoked(self) -> None:
        """A non-revoked certificate returns False from is_revoked."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="rev-002",
            common_name="Not Revoked Device",
        )

        self.assertFalse(self.ca.is_revoked(device_cert))

    def test_revocation_record(self) -> None:
        """Revocation record contains serial_number, revoked_at, reason."""
        device_cert, _ = self.ca.issue_device_certificate(
            device_id="rev-003",
            common_name="Record Test Device",
        )

        record = self.ca.revoke_certificate(device_cert, reason="superseded")

        self.assertIn("serial_number", record)
        self.assertIn("revoked_at", record)
        self.assertIn("reason", record)
        self.assertEqual(record["reason"], "superseded")
        self.assertEqual(
            record["serial_number"],
            format(device_cert.serial_number, "X"),
        )

    def test_list_revoked(self) -> None:
        """get_revoked_certs returns all revoked certificates."""
        certs = []
        for i in range(3):
            cert, _ = self.ca.issue_device_certificate(
                device_id=f"rev-batch-{i}",
                common_name=f"Batch Revoke Device {i}",
            )
            certs.append(cert)

        for cert in certs:
            self.ca.revoke_certificate(cert)

        revoked = self.ca.get_revoked_certs()
        self.assertEqual(len(revoked), 3)

        revoked_serials = {r["serial_number"] for r in revoked}
        for cert in certs:
            self.assertIn(format(cert.serial_number, "X"), revoked_serials)


# ======================================================================
# Certificate Info
# ======================================================================


class TestCertificateInfo(unittest.TestCase):
    """Tests for certificate inspection and serialization."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.ca = CertificateAuthority(
            pki_data_dir=self.tmp_dir.name,
            key_manager=self.km,
        )
        self.root_cert, _ = self.ca.create_root_ca(
            common_name="Test Root CA",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_get_cert_info(self) -> None:
        """get_certificate_info returns correct metadata for Root CA."""
        info = self.ca.get_certificate_info(self.root_cert)

        self.assertEqual(info["subject_cn"], "Test Root CA")
        self.assertEqual(info["issuer_cn"], "Test Root CA")
        self.assertTrue(info["is_ca"])
        self.assertIn("fingerprint_sha256", info)
        self.assertIn(":", info["fingerprint_sha256"])

    def test_cert_serialization(self) -> None:
        """Save and reload a certificate; fingerprints match."""
        cert_path = os.path.join(self.tmp_dir.name, "test_cert.pem")

        self.ca.save_certificate(self.root_cert, cert_path)
        loaded = self.ca.load_certificate(cert_path)

        original_info = self.ca.get_certificate_info(self.root_cert)
        loaded_info = self.ca.get_certificate_info(loaded)

        self.assertEqual(
            original_info["fingerprint_sha256"],
            loaded_info["fingerprint_sha256"],
        )
        self.assertEqual(
            original_info["serial_number"],
            loaded_info["serial_number"],
        )


# ======================================================================
# Entry point
# ======================================================================

if __name__ == "__main__":
    unittest.main()
