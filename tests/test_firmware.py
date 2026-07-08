"""
Firmware Storage & Versioning — Test Suite
==========================================

Comprehensive unit tests for :mod:`app.firmware.storage` and
:mod:`app.firmware.versioning`.

Run with::

    python -m pytest tests/test_firmware.py -v
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path

from app.firmware.storage import FirmwareStorage
from app.firmware.versioning import SemanticVersion, VersionManager


# ═════════════════════════════════════════════════════════════════════════════
# Storage Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestFirmwareStorage(unittest.TestCase):
    """Tests for :class:`FirmwareStorage`."""

    def setUp(self) -> None:
        """Create a :class:`FirmwareStorage` backed by a temporary directory."""
        self._tmp = tempfile.mkdtemp()
        self.storage = FirmwareStorage(store_dir=self._tmp, max_size_mb=1)

    def tearDown(self) -> None:
        """Remove the temporary storage directory."""
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _sample_data(size: int = 256) -> bytes:
        """Return deterministic sample firmware bytes."""
        return os.urandom(size)

    # ── save_firmware ────────────────────────────────────────────────────

    def test_save_firmware(self) -> None:
        """save_firmware returns a dict with all expected metadata fields."""
        data = self._sample_data()
        result = self.storage.save_firmware(
            data, firmware_id="fw-001", version="1.0.0", device_type="sensor"
        )
        self.assertIsInstance(result, dict)
        expected_keys = {
            "firmware_id",
            "version",
            "device_type",
            "file_path",
            "file_hash_sha256",
            "file_size_bytes",
            "stored_at",
        }
        self.assertEqual(set(result.keys()), expected_keys)
        self.assertEqual(result["firmware_id"], "fw-001")
        self.assertEqual(result["version"], "1.0.0")
        self.assertEqual(result["device_type"], "sensor")
        self.assertEqual(result["file_size_bytes"], len(data))

    def test_save_and_retrieve(self) -> None:
        """Saved firmware binary can be retrieved byte-for-byte."""
        data = self._sample_data(512)
        self.storage.save_firmware(
            data, firmware_id="fw-002", version="2.0.0"
        )
        retrieved = self.storage.get_firmware("fw-002", "2.0.0")
        self.assertEqual(data, retrieved)

    def test_save_computes_hash(self) -> None:
        """SHA-256 hash in the result matches a manual computation."""
        data = self._sample_data(128)
        result = self.storage.save_firmware(
            data, firmware_id="fw-003", version="0.1.0"
        )
        expected_hash = hashlib.sha256(data).hexdigest()
        self.assertEqual(result["file_hash_sha256"], expected_hash)

    def test_save_exceeds_size_limit(self) -> None:
        """Saving data larger than max_size raises ValueError."""
        big_data = b"\x00" * (2 * 1024 * 1024)  # 2 MB > 1 MB limit
        with self.assertRaises(ValueError):
            self.storage.save_firmware(
                big_data, firmware_id="fw-big", version="1.0.0"
            )

    def test_save_duplicate_version(self) -> None:
        """Saving the same version twice raises FileExistsError."""
        data = self._sample_data()
        self.storage.save_firmware(
            data, firmware_id="fw-dup", version="1.0.0"
        )
        with self.assertRaises(FileExistsError):
            self.storage.save_firmware(
                data, firmware_id="fw-dup", version="1.0.0"
            )

    # ── get_firmware / get_firmware_path ──────────────────────────────────

    def test_get_nonexistent(self) -> None:
        """Getting a non-existent firmware returns None."""
        self.assertIsNone(self.storage.get_firmware("ghost", "0.0.0"))

    def test_get_firmware_path(self) -> None:
        """get_firmware_path returns a Path for an existing firmware."""
        data = self._sample_data()
        self.storage.save_firmware(
            data, firmware_id="fw-path", version="1.0.0"
        )
        path = self.storage.get_firmware_path("fw-path", "1.0.0")
        self.assertIsNotNone(path)
        self.assertIsInstance(path, Path)
        self.assertTrue(path.exists())

    def test_get_firmware_path_nonexistent(self) -> None:
        """get_firmware_path returns None for a missing firmware."""
        self.assertIsNone(self.storage.get_firmware_path("ghost", "0.0.0"))

    # ── delete_firmware ──────────────────────────────────────────────────

    def test_delete_firmware(self) -> None:
        """Deleting an existing firmware succeeds and removes the file."""
        data = self._sample_data()
        self.storage.save_firmware(
            data, firmware_id="fw-del", version="1.0.0"
        )
        self.assertTrue(self.storage.firmware_exists("fw-del", "1.0.0"))
        result = self.storage.delete_firmware("fw-del", "1.0.0")
        self.assertTrue(result)
        self.assertFalse(self.storage.firmware_exists("fw-del", "1.0.0"))

    def test_delete_nonexistent(self) -> None:
        """Deleting a non-existent firmware returns False."""
        self.assertFalse(self.storage.delete_firmware("ghost", "0.0.0"))

    # ── list_firmware ────────────────────────────────────────────────────

    def test_list_firmware(self) -> None:
        """list_firmware returns entries for all saved firmware."""
        for i in range(3):
            self.storage.save_firmware(
                self._sample_data(),
                firmware_id=f"fw-list-{i}",
                version="1.0.0",
            )
        items = self.storage.list_firmware()
        self.assertEqual(len(items), 3)

    def test_list_by_device_type(self) -> None:
        """list_firmware with device_type filter returns only matching items."""
        self.storage.save_firmware(
            self._sample_data(),
            firmware_id="fw-a",
            version="1.0.0",
            device_type="sensor",
        )
        self.storage.save_firmware(
            self._sample_data(),
            firmware_id="fw-b",
            version="1.0.0",
            device_type="gateway",
        )
        self.storage.save_firmware(
            self._sample_data(),
            firmware_id="fw-c",
            version="1.0.0",
            device_type="sensor",
        )

        sensors = self.storage.list_firmware(device_type="sensor")
        self.assertEqual(len(sensors), 2)
        for item in sensors:
            self.assertEqual(item["device_type"], "sensor")

        gateways = self.storage.list_firmware(device_type="gateway")
        self.assertEqual(len(gateways), 1)

    # ── firmware_exists ──────────────────────────────────────────────────

    def test_firmware_exists(self) -> None:
        """firmware_exists returns True for a stored firmware."""
        self.assertFalse(self.storage.firmware_exists("fw-ex", "1.0.0"))
        self.storage.save_firmware(
            self._sample_data(), firmware_id="fw-ex", version="1.0.0"
        )
        self.assertTrue(self.storage.firmware_exists("fw-ex", "1.0.0"))

    # ── get_firmware_info ────────────────────────────────────────────────

    def test_get_firmware_info(self) -> None:
        """get_firmware_info returns complete metadata dict."""
        data = self._sample_data(64)
        self.storage.save_firmware(
            data, firmware_id="fw-info", version="1.0.0"
        )
        info = self.storage.get_firmware_info("fw-info", "1.0.0")
        self.assertIsNotNone(info)
        self.assertEqual(info["firmware_id"], "fw-info")
        self.assertEqual(info["version"], "1.0.0")
        self.assertEqual(info["file_size_bytes"], 64)
        self.assertEqual(
            info["file_hash_sha256"], hashlib.sha256(data).hexdigest()
        )
        self.assertIn("file_path", info)
        self.assertIn("device_type", info)

    def test_get_firmware_info_nonexistent(self) -> None:
        """get_firmware_info returns None for missing firmware."""
        self.assertIsNone(self.storage.get_firmware_info("ghost", "0.0.0"))

    # ── get_storage_stats ────────────────────────────────────────────────

    def test_storage_stats(self) -> None:
        """get_storage_stats returns correct aggregate counts."""
        self.storage.save_firmware(
            self._sample_data(100),
            firmware_id="fw-s1",
            version="1.0.0",
            device_type="sensor",
        )
        self.storage.save_firmware(
            self._sample_data(200),
            firmware_id="fw-s2",
            version="1.0.0",
            device_type="gateway",
        )
        stats = self.storage.get_storage_stats()
        self.assertEqual(stats["total_files"], 2)
        self.assertEqual(stats["total_size_bytes"], 300)
        self.assertIn("sensor", stats["device_types"])
        self.assertIn("gateway", stats["device_types"])

    # ── cleanup_old_versions ─────────────────────────────────────────────

    def test_cleanup_old_versions(self) -> None:
        """cleanup_old_versions removes oldest versions beyond keep_count."""
        # Save 7 versions with slight time gaps so mtime ordering is reliable.
        for i in range(7):
            self.storage.save_firmware(
                self._sample_data(),
                firmware_id="fw-clean",
                version=f"1.0.{i}",
            )
            time.sleep(0.05)  # Ensure distinct mtimes

        deleted = self.storage.cleanup_old_versions(
            "fw-clean", keep_count=3
        )
        self.assertEqual(len(deleted), 4)

        # The 3 newest should remain.
        remaining = self.storage.list_firmware()
        self.assertEqual(len(remaining), 3)

    def test_cleanup_empty_firmware(self) -> None:
        """cleanup_old_versions on unknown firmware returns empty list."""
        deleted = self.storage.cleanup_old_versions("nonexistent")
        self.assertEqual(deleted, [])


# ═════════════════════════════════════════════════════════════════════════════
# Semantic Version Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestSemanticVersion(unittest.TestCase):
    """Tests for :class:`SemanticVersion`."""

    # ── Parsing ──────────────────────────────────────────────────────────

    def test_parse_simple(self) -> None:
        """Parse a plain MAJOR.MINOR.PATCH string."""
        v = SemanticVersion("1.2.3")
        self.assertEqual(v.major, 1)
        self.assertEqual(v.minor, 2)
        self.assertEqual(v.patch, 3)
        self.assertIsNone(v.pre_release)
        self.assertIsNone(v.build_metadata)

    def test_parse_with_prerelease(self) -> None:
        """Parse a version with pre-release identifier."""
        v = SemanticVersion("1.0.0-beta")
        self.assertEqual(v.pre_release, "beta")
        self.assertEqual(v.major, 1)

    def test_parse_with_prerelease_dotted(self) -> None:
        """Parse a version with dotted pre-release identifier."""
        v = SemanticVersion("1.0.0-beta.1")
        self.assertEqual(v.pre_release, "beta.1")

    def test_parse_with_build(self) -> None:
        """Parse a version with build metadata."""
        v = SemanticVersion("1.0.0+build.123")
        self.assertEqual(v.build_metadata, "build.123")
        self.assertIsNone(v.pre_release)

    def test_parse_full(self) -> None:
        """Parse a version with both pre-release and build metadata."""
        v = SemanticVersion("2.1.0-alpha.3+build.42")
        self.assertEqual(v.major, 2)
        self.assertEqual(v.minor, 1)
        self.assertEqual(v.patch, 0)
        self.assertEqual(v.pre_release, "alpha.3")
        self.assertEqual(v.build_metadata, "build.42")

    def test_invalid_version(self) -> None:
        """Parsing an invalid string raises ValueError."""
        with self.assertRaises(ValueError):
            SemanticVersion("abc")

    def test_invalid_version_incomplete(self) -> None:
        """Parsing an incomplete version raises ValueError."""
        with self.assertRaises(ValueError):
            SemanticVersion("1.2")

    # ── Comparisons ──────────────────────────────────────────────────────

    def test_comparison_equal(self) -> None:
        """Two identical versions are equal."""
        self.assertEqual(SemanticVersion("1.2.3"), SemanticVersion("1.2.3"))

    def test_comparison_less_than_patch(self) -> None:
        """Lower patch version is less than higher."""
        self.assertLess(SemanticVersion("1.2.3"), SemanticVersion("1.2.4"))

    def test_comparison_less_than_minor(self) -> None:
        """Lower minor version is less than higher."""
        self.assertLess(SemanticVersion("1.2.3"), SemanticVersion("1.3.0"))

    def test_comparison_less_than_major(self) -> None:
        """Lower major version is less than higher."""
        self.assertLess(SemanticVersion("1.2.3"), SemanticVersion("2.0.0"))

    def test_comparison_greater_than(self) -> None:
        """Higher version is greater than lower."""
        self.assertGreater(SemanticVersion("2.0.0"), SemanticVersion("1.9.9"))

    def test_comparison_le(self) -> None:
        """Less-than-or-equal works correctly."""
        self.assertLessEqual(SemanticVersion("1.0.0"), SemanticVersion("1.0.0"))
        self.assertLessEqual(SemanticVersion("1.0.0"), SemanticVersion("1.0.1"))

    def test_comparison_ge(self) -> None:
        """Greater-than-or-equal works correctly."""
        self.assertGreaterEqual(
            SemanticVersion("1.0.1"), SemanticVersion("1.0.0")
        )
        self.assertGreaterEqual(
            SemanticVersion("1.0.0"), SemanticVersion("1.0.0")
        )

    def test_sorting(self) -> None:
        """A list of versions sorts correctly."""
        versions = [
            SemanticVersion("2.0.0"),
            SemanticVersion("1.0.0"),
            SemanticVersion("1.1.0"),
            SemanticVersion("1.0.1"),
            SemanticVersion("0.9.9"),
        ]
        versions.sort()
        expected = ["0.9.9", "1.0.0", "1.0.1", "1.1.0", "2.0.0"]
        self.assertEqual([str(v) for v in versions], expected)

    def test_hash_consistency(self) -> None:
        """Equal versions produce the same hash."""
        v1 = SemanticVersion("1.2.3")
        v2 = SemanticVersion("1.2.3")
        self.assertEqual(hash(v1), hash(v2))

    # ── Upgrade classification ───────────────────────────────────────────

    def test_compatible_upgrade(self) -> None:
        """Same major, higher version is a compatible upgrade."""
        v1 = SemanticVersion("1.0.0")
        v2 = SemanticVersion("1.5.2")
        self.assertTrue(v1.is_compatible_upgrade(v2))

    def test_compatible_upgrade_same(self) -> None:
        """Same version is considered a compatible upgrade (target >= self)."""
        v = SemanticVersion("1.0.0")
        self.assertTrue(v.is_compatible_upgrade(v))

    def test_not_compatible_upgrade_different_major(self) -> None:
        """Different major version is NOT a compatible upgrade."""
        v1 = SemanticVersion("1.0.0")
        v2 = SemanticVersion("2.0.0")
        self.assertFalse(v1.is_compatible_upgrade(v2))

    def test_major_upgrade(self) -> None:
        """Different major version triggers is_major_upgrade."""
        v1 = SemanticVersion("1.0.0")
        v2 = SemanticVersion("2.0.0")
        self.assertTrue(v1.is_major_upgrade(v2))

    def test_not_major_upgrade(self) -> None:
        """Same major version is not a major upgrade."""
        v1 = SemanticVersion("1.0.0")
        v2 = SemanticVersion("1.9.0")
        self.assertFalse(v1.is_major_upgrade(v2))

    # ── Bump helpers ─────────────────────────────────────────────────────

    def test_bump_patch(self) -> None:
        """bump_patch increments the patch number."""
        v = SemanticVersion("1.2.3")
        bumped = v.bump_patch()
        self.assertEqual(str(bumped), "1.2.4")

    def test_bump_minor(self) -> None:
        """bump_minor increments minor and resets patch."""
        v = SemanticVersion("1.2.3")
        bumped = v.bump_minor()
        self.assertEqual(str(bumped), "1.3.0")

    def test_bump_major(self) -> None:
        """bump_major increments major and resets minor & patch."""
        v = SemanticVersion("1.2.3")
        bumped = v.bump_major()
        self.assertEqual(str(bumped), "2.0.0")

    # ── is_valid ─────────────────────────────────────────────────────────

    def test_is_valid_true(self) -> None:
        """Valid version strings are accepted."""
        self.assertTrue(SemanticVersion.is_valid("1.0.0"))
        self.assertTrue(SemanticVersion.is_valid("0.0.1"))
        self.assertTrue(SemanticVersion.is_valid("1.2.3-alpha"))
        self.assertTrue(SemanticVersion.is_valid("1.2.3+build.1"))
        self.assertTrue(SemanticVersion.is_valid("1.2.3-rc.1+build.99"))

    def test_is_valid_false(self) -> None:
        """Invalid version strings are rejected."""
        self.assertFalse(SemanticVersion.is_valid("abc"))
        self.assertFalse(SemanticVersion.is_valid("1.2"))
        self.assertFalse(SemanticVersion.is_valid(""))
        self.assertFalse(SemanticVersion.is_valid("v1.0.0"))

    # ── str / repr ───────────────────────────────────────────────────────

    def test_str(self) -> None:
        """__str__ returns canonical version string."""
        self.assertEqual(str(SemanticVersion("1.2.3")), "1.2.3")
        self.assertEqual(str(SemanticVersion("1.0.0-beta")), "1.0.0-beta")

    def test_repr(self) -> None:
        """__repr__ returns a developer-friendly string."""
        v = SemanticVersion("1.2.3")
        self.assertIn("SemanticVersion", repr(v))
        self.assertIn("1.2.3", repr(v))


# ═════════════════════════════════════════════════════════════════════════════
# Version Manager Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestVersionManager(unittest.TestCase):
    """Tests for :class:`VersionManager`."""

    def setUp(self) -> None:
        """Create a default VersionManager."""
        self.mgr = VersionManager(allow_downgrade=False, allow_major_upgrade=True)

    # ── Registration ─────────────────────────────────────────────────────

    def test_register_version(self) -> None:
        """Registered version appears in get_all_versions."""
        sv = self.mgr.register_version("fw-001", "1.0.0")
        self.assertIsInstance(sv, SemanticVersion)
        versions = self.mgr.get_all_versions("fw-001")
        self.assertEqual(len(versions), 1)
        self.assertEqual(str(versions[0]), "1.0.0")

    def test_register_duplicate(self) -> None:
        """Registering the same version twice does not create duplicates."""
        self.mgr.register_version("fw-001", "1.0.0")
        self.mgr.register_version("fw-001", "1.0.0")
        self.assertEqual(len(self.mgr.get_all_versions("fw-001")), 1)

    def test_register_maintains_sorted_order(self) -> None:
        """Registered versions are kept in ascending order."""
        self.mgr.register_version("fw-001", "2.0.0")
        self.mgr.register_version("fw-001", "1.0.0")
        self.mgr.register_version("fw-001", "1.5.0")
        versions = self.mgr.get_all_versions("fw-001")
        self.assertEqual(
            [str(v) for v in versions], ["1.0.0", "1.5.0", "2.0.0"]
        )

    # ── get_latest_version ───────────────────────────────────────────────

    def test_get_latest(self) -> None:
        """get_latest_version returns the highest registered version."""
        self.mgr.register_version("fw-001", "1.0.0")
        self.mgr.register_version("fw-001", "1.1.0")
        self.mgr.register_version("fw-001", "0.9.0")
        latest = self.mgr.get_latest_version("fw-001")
        self.assertIsNotNone(latest)
        self.assertEqual(str(latest), "1.1.0")

    def test_get_latest_empty(self) -> None:
        """get_latest_version returns None when no versions exist."""
        self.assertIsNone(self.mgr.get_latest_version("unknown-fw"))

    # ── check_upgrade_policy ─────────────────────────────────────────────

    def test_check_upgrade_patch(self) -> None:
        """Patch upgrade is allowed and typed as 'patch'."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.0.0", "1.0.1")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["upgrade_type"], "patch")

    def test_check_upgrade_minor(self) -> None:
        """Minor upgrade is allowed and typed as 'minor'."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.0.0", "1.1.0")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["upgrade_type"], "minor")

    def test_check_upgrade_major_allowed(self) -> None:
        """Major upgrade is allowed when allow_major_upgrade=True."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.0.0", "2.0.0")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["upgrade_type"], "major")

    def test_check_upgrade_major_blocked(self) -> None:
        """Major upgrade is blocked when allow_major_upgrade=False."""
        mgr = VersionManager(allow_downgrade=False, allow_major_upgrade=False)
        result = mgr.check_upgrade_policy("fw-001", "1.0.0", "2.0.0")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["upgrade_type"], "major")

    def test_check_downgrade_blocked(self) -> None:
        """Downgrade is blocked when allow_downgrade=False."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.1.0", "1.0.0")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["upgrade_type"], "downgrade")

    def test_check_downgrade_allowed(self) -> None:
        """Downgrade is permitted when allow_downgrade=True."""
        mgr = VersionManager(allow_downgrade=True)
        result = mgr.check_upgrade_policy("fw-001", "1.1.0", "1.0.0")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["upgrade_type"], "downgrade")

    def test_same_version(self) -> None:
        """Same version → upgrade_type='same', allowed=True."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.0.0", "1.0.0")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["upgrade_type"], "same")

    def test_check_upgrade_returns_current_and_target(self) -> None:
        """Result dict echoes the current and target version strings."""
        result = self.mgr.check_upgrade_policy("fw-001", "1.0.0", "1.0.1")
        self.assertEqual(result["current"], "1.0.0")
        self.assertEqual(result["target"], "1.0.1")

    # ── get_upgrade_path ─────────────────────────────────────────────────

    def test_upgrade_path(self) -> None:
        """Upgrade path includes intermediate registered versions."""
        for v in ["1.0.0", "1.0.1", "1.0.2", "1.1.0"]:
            self.mgr.register_version("fw-001", v)

        path = self.mgr.get_upgrade_path("fw-001", "1.0.0", "1.1.0")
        self.assertEqual(path, ["1.0.1", "1.0.2", "1.1.0"])

    def test_upgrade_path_no_intermediates(self) -> None:
        """Upgrade path with no intermediates returns only the target."""
        self.mgr.register_version("fw-001", "1.0.0")
        self.mgr.register_version("fw-001", "2.0.0")
        path = self.mgr.get_upgrade_path("fw-001", "1.0.0", "2.0.0")
        self.assertEqual(path, ["2.0.0"])

    def test_upgrade_path_empty(self) -> None:
        """Upgrade path for an unknown firmware returns empty list."""
        path = self.mgr.get_upgrade_path("unknown", "1.0.0", "2.0.0")
        self.assertEqual(path, [])

    # ── suggest_next_version ─────────────────────────────────────────────

    def test_suggest_next_version_patch(self) -> None:
        """suggest_next_version with 'patch' bumps the patch number."""
        self.mgr.register_version("fw-001", "1.2.3")
        self.assertEqual(
            self.mgr.suggest_next_version("fw-001", "patch"), "1.2.4"
        )

    def test_suggest_next_version_minor(self) -> None:
        """suggest_next_version with 'minor' bumps minor, resets patch."""
        self.mgr.register_version("fw-001", "1.2.3")
        self.assertEqual(
            self.mgr.suggest_next_version("fw-001", "minor"), "1.3.0"
        )

    def test_suggest_next_version_major(self) -> None:
        """suggest_next_version with 'major' bumps major, resets others."""
        self.mgr.register_version("fw-001", "1.2.3")
        self.assertEqual(
            self.mgr.suggest_next_version("fw-001", "major"), "2.0.0"
        )

    def test_suggest_next_version_no_versions(self) -> None:
        """suggest_next_version raises ValueError when no versions exist."""
        with self.assertRaises(ValueError):
            self.mgr.suggest_next_version("unknown-fw")

    def test_suggest_next_version_invalid_bump(self) -> None:
        """suggest_next_version raises ValueError for an invalid bump type."""
        self.mgr.register_version("fw-001", "1.0.0")
        with self.assertRaises(ValueError):
            self.mgr.suggest_next_version("fw-001", "invalid")


# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main()
