import os
os.environ.pop("STORE_MODE", None)

import io
import time
import json
import httpx
import tempfile
import shutil
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.db.store import get_store, reset_store
from device_simulator.device import IoTDevice
from app.pki.ca import CertificateAuthority
from app.config import settings
import app.routers.firmware as fw_router
import app.db.store as store_module

class TestEndToEndPipeline(unittest.TestCase):
    def setUp(self):
        self.pki_dir = tempfile.mkdtemp()
        self.fw_dir = tempfile.mkdtemp()
        
        self.old_pki_dir = settings.PKI_DATA_DIR
        self.old_fw_dir = settings.FIRMWARE_STORE_DIR
        
        settings.PKI_DATA_DIR = Path(self.pki_dir)
        settings.FIRMWARE_STORE_DIR = Path(self.fw_dir)
        
        self.old_store_dir = fw_router._firmware_storage._store_dir
        fw_router._firmware_storage._store_dir = Path(self.fw_dir)
        
        # Update PKI globals so the API endpoints use the right directory
        import app.routers.pki as pki_router
        self.old_pki_ca = pki_router._ca
        from app.pki.ca import CertificateAuthority
        from app.pki.key_manager import KeyManager
        km = KeyManager(self.pki_dir)
        pki_router._ca = CertificateAuthority(self.pki_dir, key_manager=km)

        # Need to create TestClient first to hit endpoints
        reset_store()
        self.db_path = os.path.join(self.pki_dir, "test.db")
        store_module.get_store(db_path=self.db_path)
        self.client = TestClient(app, base_url="http://testserver")

        # Initialize PKI (Root, Intermediate, Signing Certs) via API so they are in the DB
        r1 = self.client.post("/api/pki/ca/root", json={"common_name": "Test Root"})
        r1.raise_for_status()
        r2 = self.client.post("/api/pki/ca/intermediate", json={"common_name": "Test Intermediate"})
        r2.raise_for_status()
        r3 = self.client.post("/api/pki/certificates/signing", json={"common_name": "Test Signer", "device_id": "system"})
        r3.raise_for_status()

    def tearDown(self):
        settings.PKI_DATA_DIR = self.old_pki_dir
        settings.FIRMWARE_STORE_DIR = self.old_fw_dir
        fw_router._firmware_storage._store_dir = self.old_store_dir
        
        shutil.rmtree(self.pki_dir, ignore_errors=True)
        shutil.rmtree(self.fw_dir, ignore_errors=True)

    def _patch_device_client(self, device: IoTDevice):
        # The device simulator sends POST /api/updates/check, but the router expects GET /api/updates/check/{device_id}
        original_post = self.client.post
        
        def patched_post(url, json=None, **kwargs):
            if "/api/updates/check" in url and json and "device_id" in json:
                return self.client.get(f"/api/updates/check/{json['device_id']}")
            return original_post(url, json=json, **kwargs)
            
        device.client = self.client
        device.client.post = patched_post

    def test_full_ota_lifecycle(self):
        # 1. Register device
        reg_resp = self.client.post("/api/devices/register", json={
            "name": "test-device-1",
            "device_type": "generic",
            "firmware_version": "1.0.0"
        })
        self.assertEqual(reg_resp.status_code, 200, reg_resp.text)
        device_id = reg_resp.json()["device"]["device_id"]
        
        # 2. Upload FW
        fw_content = b"fake-firmware-content-v2"
        upl_resp = self.client.post(
            "/api/firmware/upload",
            files={"file": ("firmware_v2.bin", fw_content, "application/octet-stream")},
            data={"name": "v2 update", "version": "2.0.0", "device_type": "generic"}
        )
        self.assertEqual(upl_resp.status_code, 200, upl_resp.text)
        fw_id = upl_resp.json()["firmware_id"]

        # 3. Sign FW
        sign_resp = self.client.post("/api/firmware/sign", json={"firmware_id": fw_id})
        self.assertEqual(sign_resp.status_code, 200, sign_resp.text)
        
        # 4. Publish FW
        pub_resp = self.client.post(f"/api/firmware/publish/{fw_id}")
        self.assertEqual(pub_resp.status_code, 200, pub_resp.text)
        
        # 5. Create deployment
        dep_resp = self.client.post("/api/updates/deployments", json={
            "firmware_id": fw_id,
            "device_id": device_id
        })
        self.assertEqual(dep_resp.status_code, 200, dep_resp.text)
        dep_data = dep_resp.json()
        deployment_id = dep_data.get("id") or dep_data.get("deployment_id")

        # Start deployment
        start_resp = self.client.post(f"/api/updates/deployments/{deployment_id}/start")
        self.assertEqual(start_resp.status_code, 200, start_resp.text)

        # 6. Initialize IoTDevice simulator
        device = IoTDevice(
            server_url="http://testserver", 
            name="test-device-1",
            ca_cert_path=str(Path(self.pki_dir) / "certs" / "intermediate_ca.pem")
        )
        self._patch_device_client(device)
        device.device_id = device_id
        device.current_version = "1.0.0"
        
        # 7. Check Updates (device checks, gets new FW)
        update = device.check_for_updates()
        self.assertTrue(update.get("update_available"), "Update should be available")
        self.assertIn("2.0.0", str(update), "Version 2.0.0 should be in the update response")
        
        # 8. Device downloads manifest + binary, and verifies with SecureBoot
        device.download_and_install(fw_id)
        
        # Check if version was updated
        self.assertEqual(device.current_version, "2.0.0")
        
        # 9. Complete deployment
        comp_resp = self.client.post(f"/api/updates/deployments/{deployment_id}/complete")
        self.assertEqual(comp_resp.status_code, 200, comp_resp.text)

        stat_resp = self.client.get(f"/api/updates/deployments/{deployment_id}")
        self.assertEqual(stat_resp.status_code, 200)
        self.assertEqual(stat_resp.json()["status"], "completed")

    def test_tampered_firmware_rejected(self):
        # Register device
        reg_resp = self.client.post("/api/devices/register", json={
            "name": "test-device-tamper",
            "device_type": "generic",
            "firmware_version": "1.0.0"
        })
        device_id = reg_resp.json()["device"]["device_id"]
        
        # Upload FW
        fw_content = b"fake-firmware-content-v2"
        upl_resp = self.client.post(
            "/api/firmware/upload",
            files={"file": ("firmware_v2.bin", fw_content, "application/octet-stream")},
            data={"name": "v2 update", "version": "2.0.0", "device_type": "generic"}
        )
        fw_id = upl_resp.json()["firmware_id"]

        # Sign & Publish FW
        self.client.post("/api/firmware/sign", json={"firmware_id": fw_id})
        self.client.post(f"/api/firmware/publish/{fw_id}")
        
        # Deploy
        dep_resp = self.client.post("/api/updates/deployments", json={
            "firmware_id": fw_id,
            "device_id": device_id
        })
        dep_data = dep_resp.json()
        deployment_id = dep_data.get("id") or dep_data.get("deployment_id")
        self.client.post(f"/api/updates/deployments/{deployment_id}/start")

        # Tamper the firmware file on disk (simulating man-in-the-middle or server tampering)
        tampered = False
        for fw_path in Path(self.fw_dir).rglob("*.bin"):
            with open(fw_path, "ab") as f:
                f.write(b"tampered")
                tampered = True
        
        self.assertTrue(tampered, "Firmware binary should have been found and tampered")

        device = IoTDevice(
            server_url="http://testserver", 
            name="test-device-tamper", 
            ca_cert_path=str(Path(self.pki_dir) / "certs" / "intermediate_ca.pem")
        )
        self._patch_device_client(device)
        device.device_id = device_id
        device.current_version = "1.0.0"
        
        # It should fail verification and not update version
        device.download_and_install(fw_id)
        self.assertEqual(device.current_version, "1.0.0", "Version should not have updated due to tampered firmware")

if __name__ == '__main__':
    unittest.main()
