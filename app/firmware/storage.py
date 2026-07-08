"""
Firmware Binary Storage
=======================

Manages firmware binary file storage on the local filesystem.

Directory layout::

    <store_dir>/
        <device_type>/
            <firmware_id>/
                <version>.bin

Usage::

    from app.firmware.storage import FirmwareStorage

    storage = FirmwareStorage(store_dir="./firmware_store", max_size_mb=100)
    result = storage.save_firmware(data, firmware_id="fw-001", version="1.0.0")
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class FirmwareStorage:
    """Manages firmware binary file storage on the filesystem.

    Parameters
    ----------
    store_dir : str
        Root directory where firmware binaries are persisted.
        Created automatically if it does not already exist.
    max_size_mb : int
        Maximum allowed size of a single firmware binary in megabytes.
    """

    def __init__(self, store_dir: str = "./firmware_store", max_size_mb: int = 100) -> None:
        self._store_dir = Path(store_dir)
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._max_size_bytes: int = max_size_mb * 1024 * 1024
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._logger.info(
            "FirmwareStorage initialised – store_dir=%s, max_size_mb=%d",
            self._store_dir.resolve(),
            max_size_mb,
        )

    # ── Internal helpers ─────────────────────────────────────────────────

    def _firmware_path(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> Path:
        """Build the canonical path for a firmware binary."""
        return self._store_dir / device_type / firmware_id / f"{version}.bin"

    # ── Public API ───────────────────────────────────────────────────────

    def save_firmware(
        self,
        firmware_data: bytes,
        firmware_id: str,
        version: str,
        device_type: str = "generic",
    ) -> dict:
        """Save firmware binary to storage.

        The binary is written to::

            <store_dir>/<device_type>/<firmware_id>/<version>.bin

        Parameters
        ----------
        firmware_data : bytes
            Raw firmware binary content.
        firmware_id : str
            Unique identifier for the firmware product line.
        version : str
            Semantic version string (e.g. ``"1.2.3"``).
        device_type : str
            Device family / product line the firmware targets.

        Returns
        -------
        dict
            Metadata about the stored firmware with keys:
            ``firmware_id``, ``version``, ``device_type``, ``file_path``,
            ``file_hash_sha256``, ``file_size_bytes``, ``stored_at``.

        Raises
        ------
        ValueError
            If *firmware_data* exceeds the configured maximum size.
        FileExistsError
            If the same *firmware_id* + *version* already exists on disk.
        """
        data_size = len(firmware_data)

        # ── Size validation ──────────────────────────────────────────────
        if data_size > self._max_size_bytes:
            raise ValueError(
                f"Firmware size ({data_size} bytes) exceeds maximum "
                f"allowed size ({self._max_size_bytes} bytes / "
                f"{self._max_size_bytes // (1024 * 1024)} MB)."
            )

        # ── Duplicate check ──────────────────────────────────────────────
        file_path = self._firmware_path(firmware_id, version, device_type)
        if file_path.exists():
            raise FileExistsError(
                f"Firmware version '{version}' for ID '{firmware_id}' "
                f"(device_type='{device_type}') already exists at {file_path}."
            )

        # ── Write to disk ────────────────────────────────────────────────
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(firmware_data)

        # ── Compute hash ─────────────────────────────────────────────────
        file_hash = hashlib.sha256(firmware_data).hexdigest()
        stored_at = datetime.now(timezone.utc).isoformat()

        self._logger.info(
            "Saved firmware %s v%s (%s) – %d bytes, sha256=%s",
            firmware_id,
            version,
            device_type,
            data_size,
            file_hash,
        )

        return {
            "firmware_id": firmware_id,
            "version": version,
            "device_type": device_type,
            "file_path": str(file_path.relative_to(self._store_dir)),
            "file_hash_sha256": file_hash,
            "file_size_bytes": data_size,
            "stored_at": stored_at,
        }

    def get_firmware(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> Optional[bytes]:
        """Retrieve firmware binary data by ID and version.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string.
        device_type : str
            Device family.

        Returns
        -------
        bytes or None
            The raw binary content, or ``None`` if the file does not exist.
        """
        file_path = self._firmware_path(firmware_id, version, device_type)
        if not file_path.exists():
            self._logger.warning(
                "Firmware not found: %s v%s (%s)", firmware_id, version, device_type
            )
            return None
        return file_path.read_bytes()

    def get_firmware_path(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> Optional[Path]:
        """Get the filesystem path for a firmware binary.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string.
        device_type : str
            Device family.

        Returns
        -------
        Path or None
            Absolute path to the binary, or ``None`` if it does not exist.
        """
        file_path = self._firmware_path(firmware_id, version, device_type)
        return file_path if file_path.exists() else None

    def delete_firmware(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> bool:
        """Delete a specific firmware version from storage.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string.
        device_type : str
            Device family.

        Returns
        -------
        bool
            ``True`` if the file was successfully removed, ``False`` if it
            did not exist.
        """
        file_path = self._firmware_path(firmware_id, version, device_type)
        if not file_path.exists():
            self._logger.warning(
                "Cannot delete – firmware not found: %s v%s (%s)",
                firmware_id,
                version,
                device_type,
            )
            return False

        file_path.unlink()
        self._logger.info(
            "Deleted firmware %s v%s (%s)", firmware_id, version, device_type
        )

        # Clean up empty parent directories.
        parent = file_path.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()
            self._logger.debug("Removed empty directory: %s", parent)

        return True

    def list_firmware(self, device_type: Optional[str] = None) -> list[dict]:
        """List all stored firmware binaries.

        Parameters
        ----------
        device_type : str or None
            If provided, only list firmware for this device type.

        Returns
        -------
        list[dict]
            Each dict contains ``firmware_id``, ``version``, ``device_type``,
            ``file_size_bytes``, and ``stored_at`` (ISO-format mtime).
        """
        results: list[dict] = []
        search_dirs: list[Path] = []

        if device_type:
            dt_dir = self._store_dir / device_type
            if dt_dir.is_dir():
                search_dirs.append(dt_dir)
        else:
            search_dirs = [
                d for d in self._store_dir.iterdir() if d.is_dir()
            ]

        for dt_dir in search_dirs:
            dt_name = dt_dir.name
            for fw_dir in dt_dir.iterdir():
                if not fw_dir.is_dir():
                    continue
                for bin_file in fw_dir.glob("*.bin"):
                    stat = bin_file.stat()
                    results.append(
                        {
                            "firmware_id": fw_dir.name,
                            "version": bin_file.stem,
                            "device_type": dt_name,
                            "file_size_bytes": stat.st_size,
                            "stored_at": datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc
                            ).isoformat(),
                        }
                    )

        return results

    def get_firmware_info(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> Optional[dict]:
        """Get metadata about a stored firmware binary.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string.
        device_type : str
            Device family.

        Returns
        -------
        dict or None
            Metadata dict with ``firmware_id``, ``version``, ``device_type``,
            ``file_path``, ``file_hash_sha256``, ``file_size_bytes``; or
            ``None`` if the firmware does not exist.
        """
        file_path = self._firmware_path(firmware_id, version, device_type)
        if not file_path.exists():
            return None

        data = file_path.read_bytes()
        return {
            "firmware_id": firmware_id,
            "version": version,
            "device_type": device_type,
            "file_path": str(file_path.relative_to(self._store_dir)),
            "file_hash_sha256": hashlib.sha256(data).hexdigest(),
            "file_size_bytes": len(data),
        }

    def firmware_exists(
        self, firmware_id: str, version: str, device_type: str = "generic"
    ) -> bool:
        """Check if a firmware version exists in storage.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        version : str
            Semantic version string.
        device_type : str
            Device family.

        Returns
        -------
        bool
            ``True`` if the binary file exists on disk.
        """
        return self._firmware_path(firmware_id, version, device_type).exists()

    def get_storage_stats(self) -> dict:
        """Return aggregate storage statistics.

        Returns
        -------
        dict
            Keys: ``total_files`` (int), ``total_size_bytes`` (int),
            ``device_types`` (list[str]).
        """
        total_files = 0
        total_size = 0
        device_types: set[str] = set()

        for dt_dir in self._store_dir.iterdir():
            if not dt_dir.is_dir():
                continue
            device_types.add(dt_dir.name)
            for bin_file in dt_dir.rglob("*.bin"):
                total_files += 1
                total_size += bin_file.stat().st_size

        return {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "device_types": sorted(device_types),
        }

    def cleanup_old_versions(
        self,
        firmware_id: str,
        device_type: str = "generic",
        keep_count: int = 5,
    ) -> list[str]:
        """Remove old firmware versions, keeping only the *N* most recent.

        Versions are ordered by file modification time; the oldest beyond
        *keep_count* are deleted.

        Parameters
        ----------
        firmware_id : str
            Firmware product-line identifier.
        device_type : str
            Device family.
        keep_count : int
            Number of most-recent versions to retain.

        Returns
        -------
        list[str]
            Version strings that were deleted.
        """
        fw_dir = self._store_dir / device_type / firmware_id
        if not fw_dir.is_dir():
            return []

        # Collect bins sorted by modification time descending (newest first).
        bins = sorted(
            fw_dir.glob("*.bin"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        deleted_versions: list[str] = []
        for old_bin in bins[keep_count:]:
            version_str = old_bin.stem
            old_bin.unlink()
            deleted_versions.append(version_str)
            self._logger.info(
                "Cleaned up old firmware version: %s v%s (%s)",
                firmware_id,
                version_str,
                device_type,
            )

        return deleted_versions
