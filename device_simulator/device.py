import time
import httpx
import logging
import platform
import json
from pathlib import Path
from typing import Optional
from device_simulator.secure_boot import SecureBoot

class IoTDevice:
    def __init__(self, server_url: str, name: str, device_type: str = 'generic', current_version: str = '1.0.0', ca_cert_path: str = './pki_data/certs/intermediate_ca.pem'):
        self.server_url = server_url.rstrip('/')
        self.name = name
        self.device_type = device_type
        self.current_version = current_version
        self.device_id: Optional[str] = None
        self.ca_cert_path = ca_cert_path
        
        self.client = httpx.Client(timeout=10.0)
        self.logger = logging.getLogger(f"IoTDevice-{self.name}")
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
            self.logger.setLevel(logging.INFO)
    
    def register(self):
        """POST /api/devices/register. Save device_id."""
        url = f"{self.server_url}/api/devices/register"
        payload = {
            "name": self.name,
            "device_type": self.device_type,
            "current_version": self.current_version,
            "platform": platform.platform()
        }
        try:
            resp = self.client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            self.device_id = data.get("id")
            self.logger.info(f"Registered successfully. ID: {self.device_id}")
        except httpx.HTTPError as e:
            self.logger.error(f"Failed to register: {e}")
    
    def heartbeat(self):
        """POST /api/devices/heartbeat."""
        if not self.device_id:
            self.logger.warning("Cannot send heartbeat, device not registered.")
            return
            
        url = f"{self.server_url}/api/devices/heartbeat"
        payload = {
            "device_id": self.device_id,
            "status": "online",
            "current_version": self.current_version
        }
        try:
            resp = self.client.post(url, json=payload)
            resp.raise_for_status()
            self.logger.debug("Heartbeat sent.")
        except httpx.HTTPError as e:
            self.logger.error(f"Failed to send heartbeat: {e}")
    
    def check_for_updates(self) -> dict:
        """POST /api/updates/check. Return response dict."""
        if not self.device_id:
            self.logger.warning("Cannot check for updates, device not registered.")
            return {}
            
        url = f"{self.server_url}/api/updates/check"
        payload = {
            "device_id": self.device_id,
            "current_version": self.current_version,
            "device_type": self.device_type
        }
        try:
            resp = self.client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            if data.get('update_available'):
                self.logger.info(f"Update check result: {data}")
            return data
        except httpx.HTTPError as e:
            self.logger.error(f"Failed to check for updates: {e}")
            return {}
    
    def download_and_install(self, firmware_id: str):
        """Download, verify and install firmware update."""
        if not self.device_id:
            return
            
        try:
            self.logger.info(f"Downloading manifest for firmware {firmware_id}")
            manifest_url = f"{self.server_url}/api/firmware/{firmware_id}/manifest"
            resp = self.client.get(manifest_url)
            resp.raise_for_status()
            manifest_dict = resp.json()
            
            signer_cert_id = manifest_dict.get("signer_cert_id")
            if signer_cert_id:
                self.logger.info(f"Downloading signer certificate {signer_cert_id}")
                cert_url = f"{self.server_url}/api/pki/certificates/{signer_cert_id}"
                cert_resp = self.client.get(cert_url)
                if cert_resp.status_code == 200:
                    data = cert_resp.json()
                    manifest_dict["signer_certificate"] = data.get("pem", "")
                else:
                    self.logger.error(f"Failed to download cert: {cert_resp.status_code} - {cert_resp.text}")

            self.logger.info(f"Downloading firmware {firmware_id}")
            download_url = f"{self.server_url}/api/firmware/{firmware_id}/download"
            resp = self.client.get(download_url)
            resp.raise_for_status()
            firmware_bytes = resp.content
            
            self.logger.info("Running SecureBoot verification...")
            try:
                with open(self.ca_cert_path, "rb") as f:
                    ca_cert_pem = f.read()
                secure_boot = SecureBoot(ca_cert_pem)
            except Exception as e:
                self.logger.error(f"Failed to initialize SecureBoot: {e}")
                self._report_status(firmware_id, False, f"SecureBoot init failed: {e}")
                return
                
            if not secure_boot.verify_manifest(manifest_dict):
                self.logger.error("Manifest verification failed.")
                self._report_status(firmware_id, False, "Manifest verification failed.")
                return
                
            if not secure_boot.verify_firmware(firmware_bytes, manifest_dict):
                self.logger.error("Firmware verification failed.")
                self._report_status(firmware_id, False, "Firmware verification failed.")
                return
                
            self.logger.info("Firmware verified successfully. Installing...")
            # Simulate installation time
            time.sleep(2)
            self.current_version = manifest_dict.get('version', self.current_version)
            self.logger.info(f"Installation complete. New version: {self.current_version}")
            self._report_status(firmware_id, True, "Installation successful")
            
        except httpx.HTTPError as e:
            self.logger.error(f"HTTP error during download/install: {e}")
            self._report_status(firmware_id, False, f"HTTP error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error during install: {e}")
            self._report_status(firmware_id, False, f"Unexpected error: {str(e)}")

    def _report_status(self, firmware_id: str, success: bool, message: str):
        url = f"{self.server_url}/api/devices/{self.device_id}/update_status"
        payload = {
            "firmware_id": firmware_id,
            "success": success,
            "message": message,
            "current_version": self.current_version
        }
        try:
            self.client.post(url, json=payload)
            self.logger.info(f"Reported status: success={success}, msg={message}")
        except httpx.HTTPError as e:
            self.logger.error(f"Failed to report status: {e}")
