"""
Firmware API Endpoint Tests
============================

Comprehensive test suite for the firmware REST API exposed by
:mod:`app.routers.firmware`.

Tests cover:

* Upload (valid, invalid version, missing name)
* Listing and filtering
* Detail retrieval (existing / non-existent)
* Binary download (existing / non-existent)
* Version upgrade checks
* Publishing and deprecation
* Rollback execution and history
* Storage statistics

All tests use an in-memory SQLite store (``STORE_MODE=memory``) and a
temporary directory for firmware binary storage, ensuring full isolation.
"""

from __future__ import annotations

import os

# Force in-memory database before importing any app modules.
os.environ["STORE_MODE"] = "memory"

import io
import shutil
import tempfile
import unittest
from typing import Any

from fastapi.testclient import TestClient

from app.db.store import get_store, reset_store
from app.firmware.storage import FirmwareStorage
from app.main import app


# ── Helpers ──────────────────────────────────────────────────────────────────


def _upload_firmware(
    client: TestClient,
    *,
    name: str = "test-firmware",
    version: str = "1.0.0",
    device_type: str = "generic",
    content: bytes = b"\x00\x01\x02\x03firmware-payload",
) -> dict[str, Any]:
    """Upload a firmware file via the API and return the JSON response."""
    response = client.post(
        "/api/firmware/upload",
        data={
            "name": name,
            "version": version,
            "device_type": device_type,
            "description": "Automated test firmware.",
            "release_notes": "Test release.",
        },
        files={"file": ("firmware.bin", io.BytesIO(content), "application/octet-stream")},
    )
    assert response.status_code == 200, (
        f"Upload failed ({response.status_code}): {response.text}"
    )
    return response.json()


# ── Test Cases ───────────────────────────────────────────────────────────────


class TestFirmwareUpload(unittest.TestCase):
    """Tests for POST /api/firmware/upload."""

    def setUp(self) -> None:
        self.temp_dir: str = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        # Reset the rollback manager to use the new storage
        from app.firmware.rollback import RollbackManager

        self._original_rollback = fw_module._rollback_manager
        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_upload_firmware(self) -> None:
        """A valid multipart upload should return 200 with all expected fields."""
        data = _upload_firmware(self.client)

        self.assertIn("firmware_id", data)
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["name"], "test-firmware")
        self.assertEqual(data["device_type"], "generic")
        self.assertIn("file_hash_sha256", data)
        self.assertGreater(data["file_size_bytes"], 0)
        self.assertEqual(data["status"], "draft")
        self.assertIn("created_at", data)

    def test_upload_invalid_version(self) -> None:
        """Uploading with an invalid version string should return 400."""
        response = self.client.post(
            "/api/firmware/upload",
            data={"name": "bad-fw", "version": "abc", "device_type": "generic"},
            files={
                "file": ("fw.bin", io.BytesIO(b"\x00\x01"), "application/octet-stream")
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid semantic version", response.json()["detail"])

    def test_upload_missing_name(self) -> None:
        """Omitting the required 'name' field should return 422."""
        response = self.client.post(
            "/api/firmware/upload",
            data={"version": "1.0.0"},
            files={
                "file": ("fw.bin", io.BytesIO(b"\x00\x01"), "application/octet-stream")
            },
        )
        self.assertEqual(response.status_code, 422)


class TestFirmwareList(unittest.TestCase):
    """Tests for GET /api/firmware/list."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)
        self._uploaded = _upload_firmware(self.client)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_list_firmware(self) -> None:
        """GET /list should include the previously uploaded firmware."""
        response = self.client.get("/api/firmware/list")
        self.assertEqual(response.status_code, 200)
        items = response.json()
        self.assertIsInstance(items, list)
        self.assertGreaterEqual(len(items), 1)
        ids = [i["firmware_id"] for i in items]
        self.assertIn(self._uploaded["firmware_id"], ids)

    def test_list_by_device_type(self) -> None:
        """Filtering by device_type should narrow results."""
        response = self.client.get(
            "/api/firmware/list", params={"device_type": "generic"}
        )
        self.assertEqual(response.status_code, 200)
        items = response.json()
        for item in items:
            self.assertEqual(item.get("target_device_type"), "generic")


class TestFirmwareDetails(unittest.TestCase):
    """Tests for GET /api/firmware/{firmware_id}."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)
        self._uploaded = _upload_firmware(self.client)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_get_firmware_details(self) -> None:
        """Detail endpoint should return full firmware metadata."""
        fw_id = self._uploaded["firmware_id"]
        response = self.client.get(f"/api/firmware/{fw_id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["firmware_id"], fw_id)
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["name"], "test-firmware")

    def test_get_nonexistent(self) -> None:
        """Requesting a non-existent ID should return 404."""
        response = self.client.get("/api/firmware/nonexistent-id-12345")
        self.assertEqual(response.status_code, 404)


class TestFirmwareDownload(unittest.TestCase):
    """Tests for GET /api/firmware/{firmware_id}/download."""

    _CONTENT: bytes = b"\xDE\xAD\xBE\xEF" * 64

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)
        self._uploaded = _upload_firmware(self.client, content=self._CONTENT)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_download_firmware(self) -> None:
        """Downloaded bytes should match the originally uploaded content."""
        fw_id = self._uploaded["firmware_id"]
        response = self.client.get(f"/api/firmware/{fw_id}/download")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, self._CONTENT)
        self.assertIn("application/octet-stream", response.headers["content-type"])
        self.assertIn("Content-Disposition", response.headers)

    def test_download_nonexistent(self) -> None:
        """Downloading a non-existent firmware should return 404."""
        response = self.client.get("/api/firmware/no-such-fw/download")
        self.assertEqual(response.status_code, 404)


class TestVersionCheck(unittest.TestCase):
    """Tests for POST /api/firmware/check-upgrade."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_check_upgrade_allowed(self) -> None:
        """A minor version bump should be allowed."""
        response = self.client.post(
            "/api/firmware/check-upgrade",
            json={
                "firmware_id": "fw-test",
                "current_version": "1.0.0",
                "target_version": "1.1.0",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["allowed"])
        self.assertEqual(data["upgrade_type"], "minor")

    def test_check_downgrade_blocked(self) -> None:
        """A downgrade should be blocked (VersionManager has allow_downgrade=False)."""
        response = self.client.post(
            "/api/firmware/check-upgrade",
            json={
                "firmware_id": "fw-test",
                "current_version": "2.0.0",
                "target_version": "1.0.0",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["allowed"])
        self.assertEqual(data["upgrade_type"], "downgrade")


class TestFirmwarePublish(unittest.TestCase):
    """Tests for POST /api/firmware/publish/{firmware_id}."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)
        self._uploaded = _upload_firmware(self.client)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_publish_firmware(self) -> None:
        """Publishing should set status to 'published'."""
        fw_id = self._uploaded["firmware_id"]
        response = self.client.post(f"/api/firmware/publish/{fw_id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "published")
        self.assertIn("published_at", data)

    def test_publish_nonexistent(self) -> None:
        """Publishing a non-existent firmware should return 404."""
        response = self.client.post("/api/firmware/publish/no-such-id")
        self.assertEqual(response.status_code, 404)


class TestFirmwareDeprecate(unittest.TestCase):
    """Tests for POST /api/firmware/deprecate/{firmware_id}."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)
        self._uploaded = _upload_firmware(self.client)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_deprecate_firmware(self) -> None:
        """Deprecating should set status to 'deprecated'."""
        fw_id = self._uploaded["firmware_id"]
        response = self.client.post(f"/api/firmware/deprecate/{fw_id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "deprecated")


class TestRollbackEndpoints(unittest.TestCase):
    """Tests for POST /api/firmware/rollback and GET /rollback-history."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)

        # Upload two versions of the same firmware
        self._v1 = _upload_firmware(
            self.client, name="rollback-fw", version="1.0.0"
        )
        self._v2 = _upload_firmware(
            self.client,
            name="rollback-fw",
            version="2.0.0",
            content=b"\xFF" * 32,
        )

        # The rollback manager needs v1 binary in storage under v2's firmware_id
        # Since each upload creates its own firmware_id, we store v1 binary
        # under v2's ID for rollback testing.
        self._storage.save_firmware(
            firmware_data=b"\x00\x01\x02\x03firmware-payload",
            firmware_id=self._v2["firmware_id"],
            version="1.0.0",
            device_type="generic",
        )

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_rollback(self) -> None:
        """Rolling back from v2 to v1 should succeed."""
        response = self.client.post(
            "/api/firmware/rollback",
            json={
                "firmware_id": self._v2["firmware_id"],
                "current_version": "2.0.0",
                "target_version": "1.0.0",
                "device_type": "generic",
            },
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["rolled_back_from"], "2.0.0")
        self.assertEqual(data["rolled_back_to"], "1.0.0")

    def test_rollback_history(self) -> None:
        """After a rollback, the history endpoint should record the event."""
        # Execute a rollback first
        self.client.post(
            "/api/firmware/rollback",
            json={
                "firmware_id": self._v2["firmware_id"],
                "current_version": "2.0.0",
                "target_version": "1.0.0",
                "device_type": "generic",
            },
        )

        response = self.client.get("/api/firmware/rollback-history")
        self.assertEqual(response.status_code, 200)
        history = response.json()
        self.assertIsInstance(history, list)
        self.assertGreaterEqual(len(history), 1)
        self.assertEqual(history[0]["firmware_id"], self._v2["firmware_id"])


class TestStorageStats(unittest.TestCase):
    """Tests for GET /api/firmware/storage-stats."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self._storage = FirmwareStorage(store_dir=self.temp_dir)

        import app.routers.firmware as fw_module

        self._original_storage = fw_module._firmware_storage
        fw_module._firmware_storage = self._storage

        self._original_rollback = fw_module._rollback_manager
        from app.firmware.rollback import RollbackManager

        fw_module._rollback_manager = RollbackManager(
            self._storage, fw_module._version_manager
        )

        reset_store()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        import app.routers.firmware as fw_module

        fw_module._firmware_storage = self._original_storage
        fw_module._rollback_manager = self._original_rollback
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        reset_store()

    def test_storage_stats(self) -> None:
        """Storage stats should return a dict with expected keys."""
        response = self.client.get("/api/firmware/storage-stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_files", data)
        self.assertIn("total_size_bytes", data)
        self.assertIn("device_types", data)
        self.assertIsInstance(data["total_files"], int)
        self.assertIsInstance(data["total_size_bytes"], int)
        self.assertIsInstance(data["device_types"], list)


if __name__ == "__main__":
    unittest.main()
