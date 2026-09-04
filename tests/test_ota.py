"""
OTA Update Tests
=================

Comprehensive test suite for the OTA update system:

* :mod:`app.ota.update_manager` — update checking, deployment lifecycle.
* :mod:`app.ota.deployment` — staged rollout management.
* :mod:`app.routers.updates` — REST API endpoints.

All tests use an in-memory SQLite store (``STORE_MODE=memory``) and the
FastAPI :class:`~fastapi.testclient.TestClient` for HTTP-level assertions.
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


# ── Helpers ──────────────────────────────────────────────────────────────────


def _seed_firmware(store: Any, **overrides: Any) -> dict[str, Any]:
    """Insert a firmware record into the store and return it."""
    defaults: dict[str, Any] = {
        "firmware_id": "fw-001",
        "version": "2.0.0",
        "name": "TestFirmware",
        "status": "published",
        "target_device_type": "sensor",
    }
    defaults.update(overrides)
    return store.save_firmware(defaults)


def _seed_device(store: Any, **overrides: Any) -> dict[str, Any]:
    """Insert a device record into the store and return it."""
    defaults: dict[str, Any] = {
        "device_id": "dev-001",
        "name": "TestSensor",
        "device_type": "sensor",
        "firmware_version": "1.0.0",
        "status": "active",
    }
    defaults.update(overrides)
    return store.save_device(defaults)


# ── Update Check Tests ───────────────────────────────────────────────────────


class TestUpdateCheck(unittest.TestCase):
    """Tests for GET /api/updates/check/{device_id}."""

    def setUp(self) -> None:
        reset_store()
        self.store = get_store()
        self.client = TestClient(app)

        _seed_firmware(self.store)
        _seed_device(self.store)

    def tearDown(self) -> None:
        reset_store()

    def test_update_available(self) -> None:
        """A device on v1.0.0 should see v2.0.0 as available."""
        resp = self.client.get("/api/updates/check/dev-001")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["update_available"])
        self.assertEqual(data["current_version"], "1.0.0")
        self.assertIsNotNone(data["latest_firmware"])
        self.assertEqual(data["latest_firmware"]["version"], "2.0.0")

    def test_no_update_when_current(self) -> None:
        """A device already on the latest version should have no update."""
        _seed_device(
            self.store,
            device_id="dev-current",
            name="CurrentDevice",
            firmware_version="2.0.0",
        )
        resp = self.client.get("/api/updates/check/dev-current")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["update_available"])

    def test_update_check_unknown_device(self) -> None:
        """Checking a non-existent device should return 404."""
        resp = self.client.get("/api/updates/check/no-such-device")
        self.assertEqual(resp.status_code, 404)

    def test_update_available_no_firmware_version(self) -> None:
        """A device with no firmware_version should see any published FW."""
        _seed_device(
            self.store,
            device_id="dev-new",
            name="NewDevice",
            firmware_version=None,
        )
        resp = self.client.get("/api/updates/check/dev-new")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["update_available"])


# ── Deployment Lifecycle Tests ───────────────────────────────────────────────


class TestDeploymentLifecycle(unittest.TestCase):
    """Tests for deployment create / start / complete / cancel endpoints."""

    def setUp(self) -> None:
        reset_store()
        self.store = get_store()
        self.client = TestClient(app)

        _seed_firmware(self.store)
        _seed_device(self.store)

    def tearDown(self) -> None:
        reset_store()

    def test_create_deployment(self) -> None:
        """POST /api/updates/deployments creates a pending deployment."""
        resp = self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "pending")
        self.assertEqual(data["firmware_id"], "fw-001")
        self.assertEqual(data["device_id"], "dev-001")

    def test_create_deployment_missing_firmware(self) -> None:
        """Creating a deployment with a non-existent firmware returns 404."""
        resp = self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "no-fw", "device_id": "dev-001"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_full_deployment_lifecycle(self) -> None:
        """A deployment can move from pending → in_progress → completed."""
        # Create
        resp = self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        dep_id = resp.json()["deployment_id"]

        # Start
        resp = self.client.post(f"/api/updates/deployments/{dep_id}/start")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "in_progress")

        # Device should be updating
        device = self.store.get_device("dev-001")
        self.assertEqual(device["status"], "updating")

        # Complete
        resp = self.client.post(f"/api/updates/deployments/{dep_id}/complete")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "completed")

        # Device should be active with new version
        device = self.store.get_device("dev-001")
        self.assertEqual(device["status"], "active")
        self.assertEqual(device["firmware_version"], "2.0.0")

    def test_cancel_deployment(self) -> None:
        """A pending deployment can be cancelled."""
        resp = self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        dep_id = resp.json()["deployment_id"]

        resp = self.client.post(
            f"/api/updates/deployments/{dep_id}/cancel",
            json={"reason": "Testing cancellation"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "failed")

    def test_get_deployment(self) -> None:
        """GET /api/updates/deployments/{id} returns the deployment."""
        resp = self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        dep_id = resp.json()["deployment_id"]

        resp = self.client.get(f"/api/updates/deployments/{dep_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["deployment_id"], dep_id)

    def test_get_deployment_not_found(self) -> None:
        """GET with a non-existent deployment ID returns 404."""
        resp = self.client.get("/api/updates/deployments/no-such-id")
        self.assertEqual(resp.status_code, 404)

    def test_list_deployments(self) -> None:
        """GET /api/updates/deployments returns all deployments."""
        self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        resp = self.client.get("/api/updates/deployments")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(resp.json(), list)
        self.assertGreaterEqual(len(resp.json()), 1)


# ── Staged Rollout Tests ────────────────────────────────────────────────────


class TestStagedRollout(unittest.TestCase):
    """Tests for staged rollout creation, advancement, and cancellation."""

    def setUp(self) -> None:
        reset_store()
        self.store = get_store()
        self.client = TestClient(app)

        # We need to reset the in-memory rollout tracker too.
        # Access the module-level singleton and clear its state.
        from app.routers.updates import _deployment_tracker
        _deployment_tracker._rollouts.clear()

    def tearDown(self) -> None:
        reset_store()

    def test_create_staged_rollout(self) -> None:
        """POST /api/updates/rollouts creates a rollout record."""
        resp = self.client.post(
            "/api/updates/rollouts",
            json={
                "firmware_id": "fw-001",
                "device_ids": ["d1", "d2", "d3", "d4", "d5"],
                "stages": [20, 60, 100],
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "active")
        self.assertEqual(data["current_stage"], 0)
        self.assertEqual(len(data["stages"]), 3)

    def test_advance_and_complete_rollout(self) -> None:
        """Advancing through all stages completes the rollout."""
        resp = self.client.post(
            "/api/updates/rollouts",
            json={
                "firmware_id": "fw-001",
                "device_ids": ["d1", "d2"],
                "stages": [50, 100],
            },
        )
        rollout_id = resp.json()["rollout_id"]

        # Advance to stage 1 (last stage)
        resp = self.client.post(f"/api/updates/rollouts/{rollout_id}/advance")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["current_stage"], 1)

        # Advance past last stage — should complete
        resp = self.client.post(f"/api/updates/rollouts/{rollout_id}/advance")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "completed")

    def test_cancel_rollout(self) -> None:
        """An active rollout can be cancelled."""
        resp = self.client.post(
            "/api/updates/rollouts",
            json={
                "firmware_id": "fw-001",
                "device_ids": ["d1"],
                "stages": [100],
            },
        )
        rollout_id = resp.json()["rollout_id"]

        resp = self.client.post(
            f"/api/updates/rollouts/{rollout_id}/cancel",
            json={"reason": "Defect found"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "cancelled")

    def test_rollout_summary(self) -> None:
        """GET /api/updates/rollouts/{id}/summary returns progress info."""
        resp = self.client.post(
            "/api/updates/rollouts",
            json={
                "firmware_id": "fw-001",
                "device_ids": ["d1", "d2", "d3"],
                "stages": [33, 66, 100],
            },
        )
        rollout_id = resp.json()["rollout_id"]

        resp = self.client.get(
            f"/api/updates/rollouts/{rollout_id}/summary",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total_devices"], 3)
        self.assertEqual(data["total_stages"], 3)
        self.assertEqual(data["status"], "active")


# ── Statistics Tests ─────────────────────────────────────────────────────────


class TestDeploymentStats(unittest.TestCase):
    """Tests for GET /api/updates/stats."""

    def setUp(self) -> None:
        reset_store()
        self.store = get_store()
        self.client = TestClient(app)

        _seed_firmware(self.store)
        _seed_device(self.store)

    def tearDown(self) -> None:
        reset_store()

    def test_stats_empty(self) -> None:
        """Stats with no deployments should show all zeros."""
        resp = self.client.get("/api/updates/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["pending"], 0)

    def test_stats_after_deployments(self) -> None:
        """Stats reflect the number and status of deployments."""
        # Create two deployments
        self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-001"},
        )
        _seed_device(
            self.store,
            device_id="dev-002",
            name="Device2",
        )
        self.client.post(
            "/api/updates/deployments",
            json={"firmware_id": "fw-001", "device_id": "dev-002"},
        )

        resp = self.client.get("/api/updates/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["pending"], 2)


if __name__ == "__main__":
    unittest.main()
