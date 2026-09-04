import sys
import threading
import time
import argparse
import logging
from device_simulator.device import IoTDevice

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FleetSimulator")

def run_device(name, version, server_url, ca_cert_path):
    device = IoTDevice(server_url, name, current_version=version, ca_cert_path=ca_cert_path)
    device.register()
    while True:
        device.heartbeat()
        update = device.check_for_updates()
        if update and update.get('update_available') and update.get('is_eligible'):
            firmware_id = update.get('firmware_id')
            if firmware_id:
                logger.info(f"Device {name} starting update to firmware {firmware_id}")
                device.download_and_install(firmware_id)
        time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description="IoT Fleet Simulator")
    parser.add_argument("--count", type=int, default=3, help="Number of devices to simulate")
    parser.add_argument("--server", type=str, default="http://localhost:8000", help="OTA Server URL")
    parser.add_argument("--version", type=str, default="1.0.0", help="Initial firmware version")
    parser.add_argument("--ca-cert", type=str, default="./pki_data/certs/intermediate_ca.pem", help="Path to CA cert")
    args = parser.parse_args()
    
    threads = []
    for i in range(args.count):
        name = f"sim-device-{i+1:03d}"
        t = threading.Thread(target=run_device, args=(name, args.version, args.server, args.ca_cert), daemon=True)
        threads.append(t)
        t.start()
        time.sleep(0.5) # Stagger startups
        
    logger.info(f"Started {args.count} simulated devices. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down simulator...")
        sys.exit(0)

if __name__ == "__main__":
    main()
