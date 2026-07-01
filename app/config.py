"""
Application Configuration
=========================

Centralised, type-safe configuration powered by Pydantic **BaseSettings**.

All values are loaded — in order of priority — from:

1. Environment variables already present in the process.
2. The ``.env`` file located in the project root.

Usage::

    from app.config import settings
    print(settings.SERVER_PORT)
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """IoT OTA Platform settings loaded from environment / ``.env`` file.

    Attributes
    ----------
    DEBUG : bool
        Enable verbose logging and development helpers.
    SERVER_HOST : str
        Host address the Uvicorn server will bind to.
    SERVER_PORT : int
        Port number the Uvicorn server will listen on.
    PKI_DATA_DIR : Path
        Directory where all PKI artefacts (keys, certs, CRLs) are stored.
    CA_KEY_SIZE : int
        RSA key size in bits for the Certificate Authority key-pair.
    DEVICE_KEY_SIZE : int
        RSA key size in bits for device key-pairs.
    CA_VALIDITY_DAYS : int
        Lifetime of the root / intermediate CA certificate in days.
    DEVICE_CERT_VALIDITY_DAYS : int
        Lifetime of individual device certificates in days.
    FIRMWARE_STORE_DIR : Path
        Directory where uploaded firmware binaries are stored.
    MAX_FIRMWARE_SIZE_MB : int
        Maximum allowed firmware file size in megabytes.
    KEEP_PREVIOUS_VERSIONS : int
        Number of previous firmware versions to retain before pruning.
    SIGNING_ALGORITHM : Literal["RSA_PSS", "ECDSA_P256"]
        Algorithm used for firmware code-signing.
    """

    # ── Server ───────────────────────────────────────────────────────────
    DEBUG: bool = True
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000

    # ── PKI ──────────────────────────────────────────────────────────────
    PKI_DATA_DIR: Path = Path("./pki_data")
    CA_KEY_SIZE: int = 4096
    DEVICE_KEY_SIZE: int = 2048
    CA_VALIDITY_DAYS: int = 3650
    DEVICE_CERT_VALIDITY_DAYS: int = 365

    # ── Firmware ─────────────────────────────────────────────────────────
    FIRMWARE_STORE_DIR: Path = Path("./firmware_store")
    MAX_FIRMWARE_SIZE_MB: int = 100
    KEEP_PREVIOUS_VERSIONS: int = 5

    # ── Signing ──────────────────────────────────────────────────────────
    SIGNING_ALGORITHM: Literal["RSA_PSS", "ECDSA_P256"] = "RSA_PSS"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
    }


# Singleton instance used throughout the application.
settings = Settings()
