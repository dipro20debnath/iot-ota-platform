"""
Comprehensive test suite for the PKI KeyManager module.

Covers RSA and ECDSA key generation, PEM serialization (with and
without passphrase encryption), file-based round-trip persistence,
SHA-256 fingerprinting, and key-info inspection.

Run with:
    python -m pytest tests/test_pki.py -v
    python -m unittest tests.test_pki -v
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so ``app.pki`` can be imported
# regardless of how the test runner is invoked.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.pki.key_manager import KeyManager


# ======================================================================
# RSA Key Generation
# ======================================================================

class TestRSAKeyGeneration(unittest.TestCase):
    """Tests for RSA key-pair generation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_generate_rsa_2048(self) -> None:
        """A 2048-bit RSA key pair has the correct modulus length."""
        private_key, public_key = self.km.generate_rsa_key_pair(key_size=2048)
        self.assertEqual(private_key.key_size, 2048)

    def test_generate_rsa_4096(self) -> None:
        """A 4096-bit RSA key pair has the correct modulus length."""
        private_key, public_key = self.km.generate_rsa_key_pair(key_size=4096)
        self.assertEqual(private_key.key_size, 4096)

    def test_rsa_key_types(self) -> None:
        """Generated objects are the expected RSA key types."""
        private_key, public_key = self.km.generate_rsa_key_pair()
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)


# ======================================================================
# ECDSA Key Generation
# ======================================================================

class TestECDSAKeyGeneration(unittest.TestCase):
    """Tests for ECDSA key-pair generation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_generate_ecdsa_p256(self) -> None:
        """A P-256 ECDSA key pair uses the secp256r1 curve."""
        private_key, public_key = self.km.generate_ecdsa_key_pair(curve="P-256")
        self.assertEqual(private_key.curve.name, "secp256r1")

    def test_generate_ecdsa_p384(self) -> None:
        """A P-384 ECDSA key pair uses the secp384r1 curve."""
        private_key, public_key = self.km.generate_ecdsa_key_pair(curve="P-384")
        self.assertEqual(private_key.curve.name, "secp384r1")

    def test_invalid_curve(self) -> None:
        """An unsupported curve name raises ValueError."""
        with self.assertRaises(ValueError):
            self.km.generate_ecdsa_key_pair(curve="P-521")


# ======================================================================
# PEM Serialization (in-memory)
# ======================================================================

class TestKeySerializationPEM(unittest.TestCase):
    """Tests for in-memory PEM serialization of keys."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        self.rsa_priv, self.rsa_pub = self.km.generate_rsa_key_pair(key_size=2048)
        self.ec_priv, self.ec_pub = self.km.generate_ecdsa_key_pair(curve="P-256")

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_serialize_rsa_private_key_pem(self) -> None:
        """RSA private key PEM starts with the expected header."""
        pem = self.km.serialize_private_key_pem(self.rsa_priv)
        self.assertTrue(
            pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
            or pem.startswith(b"-----BEGIN PRIVATE KEY-----"),
            f"Unexpected PEM header: {pem[:40]}",
        )

    def test_serialize_rsa_public_key_pem(self) -> None:
        """RSA public key PEM starts with the expected header."""
        pem = self.km.serialize_public_key_pem(self.rsa_pub)
        self.assertTrue(pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_serialize_ecdsa_private_key_pem(self) -> None:
        """ECDSA private key PEM starts with the expected header."""
        pem = self.km.serialize_private_key_pem(self.ec_priv)
        self.assertTrue(
            pem.startswith(b"-----BEGIN EC PRIVATE KEY-----")
            or pem.startswith(b"-----BEGIN PRIVATE KEY-----"),
            f"Unexpected PEM header: {pem[:40]}",
        )

    def test_serialize_with_passphrase(self) -> None:
        """Encrypted private key PEM starts with ENCRYPTED header."""
        pem = self.km.serialize_private_key_pem(
            self.rsa_priv, passphrase=b"supersecret"
        )
        self.assertTrue(pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))


# ======================================================================
# File-based key operations (round-trip)
# ======================================================================

class TestKeyFileOperations(unittest.TestCase):
    """Tests for saving and loading keys to/from PEM files."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_save_and_load_rsa_private_key(self) -> None:
        """Round-trip an RSA private key through PEM file storage."""
        priv, pub = self.km.generate_rsa_key_pair()
        filepath = os.path.join(self.tmp_dir.name, "rsa_priv.pem")

        self.km.save_private_key(priv, filepath)
        loaded = self.km.load_private_key(filepath)

        original_fp = self.km.get_key_fingerprint(pub)
        loaded_fp = self.km.get_key_fingerprint(loaded.public_key())
        self.assertEqual(original_fp, loaded_fp)

    def test_save_and_load_rsa_public_key(self) -> None:
        """Round-trip an RSA public key through PEM file storage."""
        _priv, pub = self.km.generate_rsa_key_pair()
        filepath = os.path.join(self.tmp_dir.name, "rsa_pub.pem")

        self.km.save_public_key(pub, filepath)
        loaded = self.km.load_public_key(filepath)

        self.assertEqual(
            self.km.get_key_fingerprint(pub),
            self.km.get_key_fingerprint(loaded),
        )

    def test_save_and_load_with_passphrase(self) -> None:
        """Round-trip an encrypted RSA private key."""
        priv, pub = self.km.generate_rsa_key_pair()
        filepath = os.path.join(self.tmp_dir.name, "rsa_enc.pem")
        passphrase = b"correct-horse-battery-staple"

        self.km.save_private_key(priv, filepath, passphrase=passphrase)
        loaded = self.km.load_private_key(filepath, passphrase=passphrase)

        self.assertEqual(
            self.km.get_key_fingerprint(pub),
            self.km.get_key_fingerprint(loaded.public_key()),
        )

    def test_load_with_wrong_passphrase(self) -> None:
        """Loading with the wrong passphrase raises an error."""
        priv, _pub = self.km.generate_rsa_key_pair()
        filepath = os.path.join(self.tmp_dir.name, "rsa_enc_bad.pem")

        self.km.save_private_key(priv, filepath, passphrase=b"right")
        with self.assertRaises(Exception):
            self.km.load_private_key(filepath, passphrase=b"wrong")

    def test_save_and_load_ecdsa_key(self) -> None:
        """Full round-trip for ECDSA private and public keys."""
        priv, pub = self.km.generate_ecdsa_key_pair(curve="P-256")
        priv_path = os.path.join(self.tmp_dir.name, "ec_priv.pem")
        pub_path = os.path.join(self.tmp_dir.name, "ec_pub.pem")

        self.km.save_private_key(priv, priv_path)
        self.km.save_public_key(pub, pub_path)

        loaded_priv = self.km.load_private_key(priv_path)
        loaded_pub = self.km.load_public_key(pub_path)

        self.assertEqual(
            self.km.get_key_fingerprint(pub),
            self.km.get_key_fingerprint(loaded_priv.public_key()),
        )
        self.assertEqual(
            self.km.get_key_fingerprint(pub),
            self.km.get_key_fingerprint(loaded_pub),
        )


# ======================================================================
# Key Fingerprinting
# ======================================================================

class TestKeyFingerprint(unittest.TestCase):
    """Tests for SHA-256 public-key fingerprinting."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)
        _priv, self.pub = self.km.generate_rsa_key_pair()

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_fingerprint_format(self) -> None:
        """Fingerprint matches the colon-separated hex pattern."""
        fp = self.km.get_key_fingerprint(self.pub)
        # SHA-256 produces 32 bytes → 32 hex pairs separated by colons
        pattern = r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$"
        self.assertRegex(fp, pattern)

    def test_fingerprint_consistency(self) -> None:
        """The same key always produces the same fingerprint."""
        fp1 = self.km.get_key_fingerprint(self.pub)
        fp2 = self.km.get_key_fingerprint(self.pub)
        self.assertEqual(fp1, fp2)

    def test_different_keys_different_fingerprints(self) -> None:
        """Two independently generated keys have distinct fingerprints."""
        _priv2, pub2 = self.km.generate_rsa_key_pair()
        fp1 = self.km.get_key_fingerprint(self.pub)
        fp2 = self.km.get_key_fingerprint(pub2)
        self.assertNotEqual(fp1, fp2)


# ======================================================================
# Key Info
# ======================================================================

class TestKeyInfo(unittest.TestCase):
    """Tests for the key-info inspection helper."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.km = KeyManager(pki_data_dir=self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------

    def test_rsa_key_info(self) -> None:
        """RSA key info reports correct algorithm, size, and fingerprint."""
        priv, pub = self.km.generate_rsa_key_pair(key_size=2048)
        info = self.km.get_key_info(priv)

        self.assertEqual(info["algorithm"], "RSA")
        self.assertEqual(info["key_size"], 2048)
        self.assertEqual(info["fingerprint"], self.km.get_key_fingerprint(pub))

    def test_ecdsa_key_info(self) -> None:
        """ECDSA key info reports correct algorithm, size, and fingerprint."""
        priv, pub = self.km.generate_ecdsa_key_pair(curve="P-256")
        info = self.km.get_key_info(priv)

        self.assertEqual(info["algorithm"], "ECDSA")
        self.assertEqual(info["key_size"], priv.key_size)
        self.assertEqual(info["fingerprint"], self.km.get_key_fingerprint(pub))


# ======================================================================
# Entry point
# ======================================================================

if __name__ == "__main__":
    unittest.main()
