# Secure OTA Firmware Update Platform for IoT

A Python-based platform for secure over-the-air (OTA) firmware distribution to IoT devices. This platform features a full Public Key Infrastructure (PKI), cryptographic code signing, semantic firmware versioning, and an automated rollback system to ensure firmware authenticity, integrity, and safety.

## Architecture & Features

- **FastAPI Backend:** High-performance async API for firmware uploading, PKI management, and OTA deployments.
- **PKI Infrastructure:** Fully functional Certificate Authority (CA) with Root and Intermediate certificates. Issues device and code-signing certificates.
- **Code Signing:** Cryptographically signs firmware binaries using RSA-PSS or ECDSA algorithms.
- **Firmware Manifests:** Generates and validates JSON manifests containing SHA-256 hashes, digital signatures, and firmware metadata.
- **Semantic Versioning:** Strict SemVer 2.0 validation with upgrade/downgrade policies via a `VersionManager`.
- **Automated Rollbacks:** Dedicated `RollbackManager` to handle safe downgrades to previous valid firmware versions.
- **Storage & Database:** Thread-safe SQLite storage for metadata and local filesystem storage for binary blobs.

## Quickstart

### Prerequisites

- Python 3.13+
- `cryptography`
- `fastapi` and `uvicorn`

### Setup

```bash
# Clone the repository
git clone https://github.com/dipro20debnath/iot-ota-platform.git
cd iot-ota-platform

# Create a virtual environment and install dependencies
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Running the Server

Start the FastAPI development server:

```bash
venv\Scripts\uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API documentation will be available at `http://localhost:8000/docs`.

### Running Tests

The project includes an extensive test suite covering the PKI, code signing, and REST APIs.

```bash
venv\Scripts\pytest tests/ -v
```

## Project Structure (Weeks 1-2)

- `app/db/`: SQLite persistent storage and schemas.
- `app/firmware/`: Firmware storage, semantic versioning, and rollback logic.
- `app/models/`: Pydantic models for data validation.
- `app/pki/`: Key generation, Certificate Authority, and certificate validation.
- `app/routers/`: FastAPI endpoints (`/api/pki`, `/api/firmware`).
- `app/signing/`: Firmware cryptographic signing, verification, and JSON manifest handling.
- `tests/`: 180+ automated tests across all modules.

## Internship Milestone

This project is being developed as part of an internship. Weeks 1 and 2 (Days 1-10) focus on establishing the core PKI, code signing, and firmware management back-end systems.
