"""
FastAPI Application Entry-Point
================================

Configures and exposes the top-level :class:`FastAPI` application instance
for the **IoT OTA Platform**.

Key responsibilities handled here:

* **Lifespan management** — creates required directories (``pki_data/``,
  ``firmware_store/``) on startup and runs any teardown logic on shutdown.
* **Middleware** — CORS is configured permissively for development; tighten
  ``allow_origins`` before deploying to production.
* **Root routes** — ``/`` (project info) and ``/health`` (liveness probe).

Run the server directly::

    python -m app.main          # uses Uvicorn programmatically
    uvicorn app.main:app --reload   # or via CLI for development
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("iot_ota_platform")

# ── Constants ────────────────────────────────────────────────────────────────

APP_VERSION = "0.1.0"
_startup_time: float = 0.0  # set during lifespan


# ── Lifespan ─────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager.

    **Startup** — ensures required storage directories exist and records the
    startup timestamp for the ``/health`` endpoint.

    **Shutdown** — placeholder for graceful teardown (DB connections, etc.).
    """
    global _startup_time
    _startup_time = time.time()

    # Ensure required directories exist
    pki_dir = settings.PKI_DATA_DIR
    firmware_dir = settings.FIRMWARE_STORE_DIR

    pki_dir.mkdir(parents=True, exist_ok=True)
    logger.info("PKI data directory ready: %s", pki_dir.resolve())

    firmware_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Firmware store directory ready: %s", firmware_dir.resolve())

    logger.info(
        "IoT OTA Platform v%s started — DEBUG=%s, host=%s, port=%s",
        APP_VERSION,
        settings.DEBUG,
        settings.SERVER_HOST,
        settings.SERVER_PORT,
    )

    yield  # ── application runs here ──

    logger.info("IoT OTA Platform shutting down …")


# ── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="IoT OTA Platform",
    description="Secure Over-the-Air Firmware Update Platform with PKI & Code Signing",
    version=APP_VERSION,
    lifespan=lifespan,
)

# ── Middleware ───────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────

from app.routers.pki import router as pki_router  # noqa: E402
from app.routers.firmware import router as firmware_router  # noqa: E402

app.include_router(pki_router)
app.include_router(firmware_router)

# ── Root Routes ──────────────────────────────────────────────────────────────


@app.get("/", tags=["General"])
async def root() -> dict:
    """Return basic project information and a map of available endpoints.

    Returns
    -------
    dict
        JSON object with project name, version, status, and endpoint listing.
    """
    return {
        "project": "IoT OTA Platform",
        "version": APP_VERSION,
        "status": "operational",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "docs": "/docs",
            "openapi": "/openapi.json",
            "pki": "/api/pki",
            "firmware": "/api/firmware",
        },
    }


@app.get("/health", tags=["General"])
async def health() -> dict:
    """Liveness / readiness probe for orchestrators and load-balancers.

    Returns
    -------
    dict
        JSON object containing service status, uptime in seconds, and the
        current UTC timestamp.
    """
    uptime_seconds = round(time.time() - _startup_time, 2) if _startup_time else 0.0
    return {
        "status": "healthy",
        "uptime_seconds": uptime_seconds,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Direct Execution ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.SERVER_HOST,
        port=settings.SERVER_PORT,
        reload=settings.DEBUG,
    )
