"""
Device API Endpoint Tests
==========================

Comprehensive test suite for the device REST API exposed by
:mod:`app.routers.devices`.

Tests cover:

* Device registration (valid, duplicate names, with metadata)
* Device listing (all, filtered by status, filtered by type)
* Device detail retrieval (existing / non-existent)
* Heartbeat processing (valid, unknown device)
* Group creation and listing
* Device-to-group assignment
* Fleet statistics
* Device decommissioning

All tests use an in-memory SQLite store (``STORE_MODE=memory``) to
ensure full isolation between runs.
"""

from __future__ import annotations

import os

# Force in-memory database before importing any app modules.
os.environ["STORE_MODE"] = "memory"

import unittest
from typing import Any

from fastapi.testclient import TestClient

from app.db.store import get_store, reset_store
from app.main import app
from app.routers.devices import _registry


# ── Helpers ──────────────────────────────────────────────────────────────────


def _register_device(
    client: TestClient,
    *,
    name: str = "test-sensor-01",
    device_type: str = "sensor-v2",
    firmware_version: str | None = "1.0.0",
    ip_address: str | None = "192.168.1.10",
    group_name: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Register a device via the API and return the JSON response."""
    payload: dict[str, Any] = {
        "name": name,
        "device_type": device_type,
    }
    if firmware_version is not None:
        payload["firmware_version"] = firmware_version
    if ip_address is not None:
        payload["ip_address"] = ip_address
    if group_name is not None:
        payload["group_name"] = group_name
    if metadata is not None:
        payload["metadata"] = metadata

    response = client.post("/api/devices/register", json=payload)
    assert response.status_code == 200, (
        f"Registration failed ({response.status_code}): {response.text}"
    )
    return response.json()


# ── Test Cases ───────────────────────────────────────────────────────────────


class TestDeviceRegistration(unittest.TestCase):
    """Tests for POST /api/devices/register."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_register_device_success(self) -> None:
        """A valid registration returns the device record with status 'registered'."""
        data = _register_device(self.client)
        self.assertEqual(data["status"], "success")
        self.assertIn("device", data)
        device = data["device"]
        self.assertEqual(device["name"], "test-sensor-01")
        self.assertEqual(device["device_type"], "sensor-v2")
        self.assertEqual(device["status"], "registered")
        self.assertIn("device_id", device)

    def test_register_device_with_metadata(self) -> None:
        """Metadata dict is persisted alongside the device."""
        meta = {"location": "warehouse-A", "floor": 3}
        data = _register_device(self.client, metadata=meta)
        device = data["device"]
        self.assertEqual(device["metadata"], meta)

    def test_register_multiple_devices(self) -> None:
        """Multiple devices can be registered and each gets a unique ID."""
        d1 = _register_device(self.client, name="device-alpha")
        d2 = _register_device(self.client, name="device-beta")
        self.assertNotEqual(
            d1["device"]["device_id"],
            d2["device"]["device_id"],
        )


class TestDeviceListing(unittest.TestCase):
    """Tests for GET /api/devices/list."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_list_empty(self) -> None:
        """An empty registry returns count 0."""
        resp = self.client.get("/api/devices/list")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["devices"], [])

    def test_list_after_registration(self) -> None:
        """Registered devices appear in the list."""
        _register_device(self.client, name="dev-1")
        _register_device(self.client, name="dev-2")
        resp = self.client.get("/api/devices/list")
        data = resp.json()
        self.assertEqual(data["count"], 2)

    def test_list_filter_by_status(self) -> None:
        """Filtering by status returns only matching devices."""
        _register_device(self.client, name="active-dev")
        resp = self.client.get("/api/devices/list", params={"status": "registered"})
        data = resp.json()
        self.assertEqual(data["count"], 1)

        resp2 = self.client.get("/api/devices/list", params={"status": "active"})
        data2 = resp2.json()
        self.assertEqual(data2["count"], 0)

    def test_list_filter_by_type(self) -> None:
        """Filtering by device_type returns only matching devices."""
        _register_device(self.client, name="s1", device_type="sensor-v2")
        _register_device(self.client, name="g1", device_type="gateway")
        resp = self.client.get("/api/devices/list", params={"device_type": "gateway"})
        data = resp.json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["devices"][0]["device_type"], "gateway")


class TestDeviceDetail(unittest.TestCase):
    """Tests for GET /api/devices/{device_id}."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_get_existing_device(self) -> None:
        """An existing device is returned correctly."""
        reg = _register_device(self.client)
        device_id = reg["device"]["device_id"]

        resp = self.client.get(f"/api/devices/{device_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["device"]["device_id"], device_id)

    def test_get_nonexistent_device(self) -> None:
        """A missing device returns 404."""
        resp = self.client.get("/api/devices/does-not-exist")
        self.assertEqual(resp.status_code, 404)


class TestDeviceHeartbeat(unittest.TestCase):
    """Tests for POST /api/devices/heartbeat."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_heartbeat_success(self) -> None:
        """A valid heartbeat updates device fields."""
        reg = _register_device(self.client)
        device_id = reg["device"]["device_id"]

        resp = self.client.post(
            "/api/devices/heartbeat",
            json={
                "device_id": device_id,
                "firmware_version": "1.1.0",
                "status": "active",
                "ip_address": "10.0.0.5",
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["device"]["firmware_version"], "1.1.0")
        self.assertEqual(data["device"]["status"], "active")
        self.assertIsNotNone(data["device"]["last_heartbeat"])

    def test_heartbeat_unknown_device(self) -> None:
        """A heartbeat for an unregistered device returns 404."""
        resp = self.client.post(
            "/api/devices/heartbeat",
            json={
                "device_id": "unknown-id",
                "firmware_version": "1.0.0",
                "status": "active",
            },
        )
        self.assertEqual(resp.status_code, 404)


class TestDeviceGroups(unittest.TestCase):
    """Tests for group endpoints."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_create_group(self) -> None:
        """Creating a group returns the group record."""
        resp = self.client.post(
            "/api/devices/groups",
            json={"name": "warehouse-fleet", "description": "All warehouse sensors"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["group"]["name"], "warehouse-fleet")
        self.assertIn("group_id", data["group"])

    def test_list_groups(self) -> None:
        """All created groups appear in the list."""
        self.client.post("/api/devices/groups", json={"name": "group-a"})
        self.client.post("/api/devices/groups", json={"name": "group-b"})

        resp = self.client.get("/api/devices/groups/list")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 2)

    def test_assign_device_to_group(self) -> None:
        """Assigning a device to a group updates its group_name."""
        reg = _register_device(self.client)
        device_id = reg["device"]["device_id"]

        resp = self.client.post(
            f"/api/devices/{device_id}/group",
            json={"group_name": "production"},
        )
        self.assertEqual(resp.status_code, 200)

        # Verify the device record reflects the group
        detail = self.client.get(f"/api/devices/{device_id}").json()
        self.assertEqual(detail["device"]["group_name"], "production")

    def test_assign_unknown_device_to_group(self) -> None:
        """Assigning an unknown device returns 404."""
        resp = self.client.post(
            "/api/devices/nonexistent/group",
            json={"group_name": "production"},
        )
        self.assertEqual(resp.status_code, 404)


class TestFleetStats(unittest.TestCase):
    """Tests for GET /api/devices/stats."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_empty_fleet_stats(self) -> None:
        """Empty fleet returns zero totals."""
        resp = self.client.get("/api/devices/stats")
        self.assertEqual(resp.status_code, 200)
        stats = resp.json()["stats"]
        self.assertEqual(stats["total_devices"], 0)
        self.assertEqual(stats["total_groups"], 0)

    def test_fleet_stats_after_registrations(self) -> None:
        """Stats reflect registered devices and groups."""
        _register_device(self.client, name="s1", device_type="sensor")
        _register_device(self.client, name="s2", device_type="sensor")
        _register_device(self.client, name="g1", device_type="gateway")
        self.client.post("/api/devices/groups", json={"name": "grp1"})

        resp = self.client.get("/api/devices/stats")
        stats = resp.json()["stats"]
        self.assertEqual(stats["total_devices"], 3)
        self.assertEqual(stats["by_status"].get("registered"), 3)
        self.assertEqual(stats["by_type"].get("sensor"), 2)
        self.assertEqual(stats["by_type"].get("gateway"), 1)
        self.assertEqual(stats["total_groups"], 1)


class TestDeviceDecommission(unittest.TestCase):
    """Tests for POST /api/devices/{device_id}/decommission."""

    def setUp(self) -> None:
        reset_store()
        _registry._groups.clear()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        reset_store()
        _registry._groups.clear()

    def test_decommission_device(self) -> None:
        """Decommissioning sets the device status to 'revoked'."""
        reg = _register_device(self.client)
        device_id = reg["device"]["device_id"]

        resp = self.client.post(f"/api/devices/{device_id}/decommission")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")

        # Verify status changed
        detail = self.client.get(f"/api/devices/{device_id}").json()
        self.assertEqual(detail["device"]["status"], "revoked")

    def test_decommission_nonexistent_device(self) -> None:
        """Decommissioning a missing device returns 404."""
        resp = self.client.post("/api/devices/fake-id/decommission")
        self.assertEqual(resp.status_code, 404)

    def test_decommission_reflects_in_stats(self) -> None:
        """Decommissioned device is counted as 'revoked' in fleet stats."""
        reg = _register_device(self.client)
        device_id = reg["device"]["device_id"]
        self.client.post(f"/api/devices/{device_id}/decommission")

        stats = self.client.get("/api/devices/stats").json()["stats"]
        self.assertEqual(stats["by_status"].get("revoked"), 1)


if __name__ == "__main__":
    unittest.main()
