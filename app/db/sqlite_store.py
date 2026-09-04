"""
SQLite Persistent Storage
==========================

Thread-safe SQLite storage back-end for the IoT OTA Platform.

All CRUD operations for certificates, devices, firmware images, and
deployments are encapsulated here.  Each thread gets its own connection
via :data:`threading.local`, and every query uses parameterised
placeholders to prevent SQL injection.

Usage::

    from app.db.sqlite_store import SQLiteStore

    store = SQLiteStore("./pki_data/ota_platform.db")
    store.save_cert({...})
    cert = store.get_cert("some-cert-id")
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from app.db.models import ALL_TABLES

logger = logging.getLogger(__name__)


class SQLiteStore:
    """Thread-safe SQLite storage for the IoT OTA Platform.

    Each calling thread receives its own :class:`sqlite3.Connection` via
    a :class:`threading.local` instance.  Row results use
    :attr:`sqlite3.Row` so columns can be accessed by name.

    Parameters
    ----------
    db_path : str
        Filesystem path to the SQLite database file.  Parent directories
        are created automatically.  Use ``':memory:'`` for in-memory
        databases (useful in tests).
    """

    def __init__(self, db_path: str = "./pki_data/ota_platform.db") -> None:
        """Initialise the store, create directories, and set up tables.

        Args:
            db_path: Path to the SQLite database file.  ``':memory:'``
                creates an ephemeral in-memory database.
        """
        self.db_path: str = db_path

        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            self._keepalive = None
        else:
            # Hold a persistent connection to keep the shared in-memory DB alive
            self._keepalive = sqlite3.connect("file::memory:?cache=shared", uri=True)

        self._local: threading.local = threading.local()
        self._init_db()

        logger.info("SQLiteStore initialised – db_path=%s", self.db_path)

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        """Return a thread-local database connection.

        If the current thread does not yet have a connection, one is
        created and configured with :attr:`sqlite3.Row` row factory.

        Returns
        -------
        sqlite3.Connection
            The thread-local database connection.
        """
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is None:
            if self.db_path == ":memory:":
                # Use shared-cache URI so every thread sees the same
                # in-memory database (plain ':memory:' creates a
                # separate empty database per connection).
                conn = sqlite3.connect(
                    "file::memory:?cache=shared", uri=True,
                )
            else:
                conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        """Create all tables if they do not already exist.

        Iterates over :data:`~app.db.models.ALL_TABLES` and executes
        each ``CREATE TABLE IF NOT EXISTS`` statement.
        """
        conn = self._get_connection()
        for ddl in ALL_TABLES:
            conn.execute(ddl)
        conn.commit()
        logger.info("Database tables initialised.")

    # ==================================================================
    # Certificate operations
    # ==================================================================

    def save_cert(self, cert_data: dict[str, Any]) -> dict[str, Any]:
        """Insert a new certificate record into the database.

        If ``cert_data`` does not contain a ``cert_id``, one is generated
        automatically via :func:`uuid4`.

        Args:
            cert_data: Dictionary of certificate fields matching the
                ``certificates`` table columns.

        Returns
        -------
        dict
            The saved certificate record (including the generated
            ``cert_id`` and ``created_at``).

        Raises
        ------
        sqlite3.IntegrityError
            If the ``cert_id`` or ``serial_number`` already exist.
        """
        conn = self._get_connection()
        cert_id: str = cert_data.get("cert_id", str(uuid4()))
        now_iso: str = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO certificates (
                cert_id, serial_number, subject_cn, issuer_cn, cert_type,
                status, algorithm, not_before, not_after, fingerprint_sha256,
                parent_cert_id, pem_data, revoked_at, revocation_reason,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id,
                cert_data["serial_number"],
                cert_data["subject_cn"],
                cert_data["issuer_cn"],
                cert_data.get("cert_type", "device"),
                cert_data.get("status", "active"),
                cert_data["algorithm"],
                cert_data["not_before"],
                cert_data["not_after"],
                cert_data["fingerprint_sha256"],
                cert_data.get("parent_cert_id"),
                cert_data["pem_data"],
                cert_data.get("revoked_at"),
                cert_data.get("revocation_reason"),
                now_iso,
            ),
        )
        conn.commit()

        logger.info("Certificate saved – cert_id=%s, serial=%s", cert_id, cert_data["serial_number"])
        saved = dict(cert_data)
        saved["cert_id"] = cert_id
        saved["created_at"] = now_iso
        return saved

    def get_cert(self, cert_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a certificate record by its platform ``cert_id``.

        Args:
            cert_id: The unique certificate identifier.

        Returns
        -------
        dict or None
            The certificate record as a dictionary, or ``None`` if not
            found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM certificates WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_cert_by_serial(self, serial_number: str) -> Optional[dict[str, Any]]:
        """Retrieve a certificate record by its X.509 serial number.

        Args:
            serial_number: The hex-encoded certificate serial number.

        Returns
        -------
        dict or None
            The certificate record, or ``None`` if not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM certificates WHERE serial_number = ?",
            (serial_number,),
        ).fetchone()
        return dict(row) if row else None

    def list_certs(
        self,
        cert_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List certificates with optional filtering.

        Args:
            cert_type: Filter by certificate type (e.g. ``'root_ca'``,
                ``'device'``, ``'signing'``).
            status: Filter by status (e.g. ``'active'``, ``'revoked'``).

        Returns
        -------
        list[dict]
            A list of matching certificate records.
        """
        conn = self._get_connection()
        query = "SELECT * FROM certificates WHERE 1=1"
        params: list[Any] = []

        if cert_type is not None:
            query += " AND cert_type = ?"
            params.append(cert_type)
        if status is not None:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_cert_status(
        self,
        cert_id: str,
        status: str,
        revocation_reason: Optional[str] = None,
    ) -> bool:
        """Update a certificate's lifecycle status.

        When *status* is ``'revoked'``, the ``revoked_at`` timestamp is
        set to the current UTC time and the optional *revocation_reason*
        is recorded.

        Args:
            cert_id: The certificate to update.
            status: New status value.
            revocation_reason: Human-readable revocation reason (only
                meaningful when revoking).

        Returns
        -------
        bool
            ``True`` if a row was updated, ``False`` otherwise.
        """
        conn = self._get_connection()
        now_iso: str = datetime.now(timezone.utc).isoformat()

        if status == "revoked":
            cursor = conn.execute(
                """
                UPDATE certificates
                SET status = ?, revoked_at = ?, revocation_reason = ?
                WHERE cert_id = ?
                """,
                (status, now_iso, revocation_reason, cert_id),
            )
        else:
            cursor = conn.execute(
                "UPDATE certificates SET status = ? WHERE cert_id = ?",
                (status, cert_id),
            )

        conn.commit()
        updated: bool = cursor.rowcount > 0
        if updated:
            logger.info("Certificate status updated – cert_id=%s, status=%s", cert_id, status)
        return updated

    # ==================================================================
    # Device operations
    # ==================================================================

    def save_device(self, device_data: dict[str, Any]) -> dict[str, Any]:
        """Insert or replace a device record.

        If the ``device_id`` already exists, the existing row is replaced
        (``INSERT OR REPLACE``).  A ``device_id`` is generated via
        :func:`uuid4` when not provided.

        Args:
            device_data: Dictionary of device fields matching the
                ``devices`` table columns.

        Returns
        -------
        dict
            The saved device record.
        """
        conn = self._get_connection()
        device_id: str = device_data.get("device_id", str(uuid4()))
        now_iso: str = datetime.now(timezone.utc).isoformat()
        metadata_str: str = device_data.get("metadata", "{}")
        if isinstance(metadata_str, dict):
            metadata_str = json.dumps(metadata_str)

        conn.execute(
            """
            INSERT OR REPLACE INTO devices (
                device_id, name, device_type, group_name, firmware_version,
                status, certificate_id, ip_address, last_heartbeat,
                registered_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                device_data["name"],
                device_data.get("device_type", "generic"),
                device_data.get("group_name"),
                device_data.get("firmware_version"),
                device_data.get("status", "registered"),
                device_data.get("certificate_id"),
                device_data.get("ip_address"),
                device_data.get("last_heartbeat"),
                now_iso,
                metadata_str,
            ),
        )
        conn.commit()

        logger.info("Device saved – device_id=%s, name=%s", device_id, device_data["name"])
        saved = dict(device_data)
        saved["device_id"] = device_id
        saved["registered_at"] = now_iso
        return saved

    def get_device(self, device_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a device record by ``device_id``.

        Args:
            device_id: The unique device identifier.

        Returns
        -------
        dict or None
            The device record, or ``None`` if not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_devices(
        self,
        status: Optional[str] = None,
        device_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List devices with optional filtering.

        Args:
            status: Filter by device status.
            device_type: Filter by device type.

        Returns
        -------
        list[dict]
            A list of matching device records.
        """
        conn = self._get_connection()
        query = "SELECT * FROM devices WHERE 1=1"
        params: list[Any] = []

        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if device_type is not None:
            query += " AND device_type = ?"
            params.append(device_type)

        query += " ORDER BY registered_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_device(self, device_id: str, updates: dict[str, Any]) -> bool:
        """Update specific fields on a device record.

        Only the keys present in *updates* are modified; all other
        columns remain unchanged.

        Args:
            device_id: The device to update.
            updates: Mapping of column-name → new-value.

        Returns
        -------
        bool
            ``True`` if a row was updated, ``False`` otherwise.
        """
        if not updates:
            return False

        conn = self._get_connection()
        set_clauses: list[str] = []
        params: list[Any] = []

        for key, value in updates.items():
            set_clauses.append(f"{key} = ?")
            if isinstance(value, dict):
                params.append(json.dumps(value))
            else:
                params.append(value)

        params.append(device_id)
        query = f"UPDATE devices SET {', '.join(set_clauses)} WHERE device_id = ?"
        cursor = conn.execute(query, params)
        conn.commit()

        updated: bool = cursor.rowcount > 0
        if updated:
            logger.info("Device updated – device_id=%s, fields=%s", device_id, list(updates.keys()))
        return updated

    # ==================================================================
    # Firmware operations
    # ==================================================================

    def save_firmware(self, fw_data: dict[str, Any]) -> dict[str, Any]:
        """Insert a new firmware record.

        A ``firmware_id`` is generated via :func:`uuid4` if not present
        in *fw_data*.

        Args:
            fw_data: Dictionary of firmware fields matching the
                ``firmware`` table columns.

        Returns
        -------
        dict
            The saved firmware record.

        Raises
        ------
        sqlite3.IntegrityError
            If the ``firmware_id`` already exists.
        """
        conn = self._get_connection()
        firmware_id: str = fw_data.get("firmware_id", str(uuid4()))
        now_iso: str = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO firmware (
                firmware_id, version, name, description, file_hash_sha256,
                file_size_bytes, signature, signer_cert_id, status,
                target_device_type, min_version, release_notes,
                created_at, published_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                firmware_id,
                fw_data["version"],
                fw_data["name"],
                fw_data.get("description", ""),
                fw_data.get("file_hash_sha256"),
                fw_data.get("file_size_bytes"),
                fw_data.get("signature"),
                fw_data.get("signer_cert_id"),
                fw_data.get("status", "draft"),
                fw_data.get("target_device_type", "generic"),
                fw_data.get("min_version"),
                fw_data.get("release_notes", ""),
                now_iso,
                fw_data.get("published_at"),
            ),
        )
        conn.commit()

        logger.info("Firmware saved – firmware_id=%s, version=%s", firmware_id, fw_data["version"])
        saved = dict(fw_data)
        saved["firmware_id"] = firmware_id
        saved["created_at"] = now_iso
        return saved

    def get_firmware(self, firmware_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a firmware record by ``firmware_id``.

        Args:
            firmware_id: The unique firmware identifier.

        Returns
        -------
        dict or None
            The firmware record, or ``None`` if not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM firmware WHERE firmware_id = ?",
            (firmware_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_firmware(
        self,
        status: Optional[str] = None,
        device_type: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List firmware with optional filtering.

        Args:
            status: Filter by firmware status (e.g. ``'draft'``,
                ``'published'``).
            device_type: Filter by target device type.

        Returns
        -------
        list[dict]
            A list of matching firmware records.
        """
        conn = self._get_connection()
        query = "SELECT * FROM firmware WHERE 1=1"
        params: list[Any] = []

        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if device_type is not None:
            query += " AND target_device_type = ?"
            params.append(device_type)

        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_firmware_status(self, firmware_id: str, status: str) -> bool:
        """Update a firmware record's status.

        When *status* is ``'published'``, the ``published_at`` column
        is set to the current UTC time.

        Args:
            firmware_id: The firmware to update.
            status: New status value.

        Returns
        -------
        bool
            ``True`` if a row was updated, ``False`` otherwise.
        """
        conn = self._get_connection()
        now_iso: str = datetime.now(timezone.utc).isoformat()

        if status == "published":
            cursor = conn.execute(
                "UPDATE firmware SET status = ?, published_at = ? WHERE firmware_id = ?",
                (status, now_iso, firmware_id),
            )
        else:
            cursor = conn.execute(
                "UPDATE firmware SET status = ? WHERE firmware_id = ?",
                (status, firmware_id),
            )

        conn.commit()
        updated: bool = cursor.rowcount > 0
        if updated:
            logger.info("Firmware status updated – firmware_id=%s, status=%s", firmware_id, status)
        return updated

    # ==================================================================
    # Deployment operations
    # ==================================================================

    def save_deployment(self, deployment_data: dict[str, Any]) -> dict[str, Any]:
        """Insert a new deployment record.

        A ``deployment_id`` is generated via :func:`uuid4` if not present.

        Args:
            deployment_data: Dictionary of deployment fields matching the
                ``deployments`` table columns.

        Returns
        -------
        dict
            The saved deployment record.

        Raises
        ------
        sqlite3.IntegrityError
            If the ``deployment_id`` already exists.
        """
        conn = self._get_connection()
        deployment_id: str = deployment_data.get("deployment_id", str(uuid4()))
        now_iso: str = datetime.now(timezone.utc).isoformat()

        conn.execute(
            """
            INSERT INTO deployments (
                deployment_id, firmware_id, device_id, status,
                started_at, completed_at, error_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                deployment_id,
                deployment_data["firmware_id"],
                deployment_data["device_id"],
                deployment_data.get("status", "pending"),
                deployment_data.get("started_at"),
                deployment_data.get("completed_at"),
                deployment_data.get("error_message"),
                now_iso,
            ),
        )
        conn.commit()

        logger.info(
            "Deployment saved – deployment_id=%s, firmware=%s, device=%s",
            deployment_id,
            deployment_data["firmware_id"],
            deployment_data["device_id"],
        )
        saved = dict(deployment_data)
        saved["deployment_id"] = deployment_id
        saved["created_at"] = now_iso
        return saved

    def get_deployment(self, deployment_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a deployment record by ``deployment_id``.

        Args:
            deployment_id: The unique deployment identifier.

        Returns
        -------
        dict or None
            The deployment record, or ``None`` if not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM deployments WHERE deployment_id = ?",
            (deployment_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_deployments(
        self,
        device_id: Optional[str] = None,
        firmware_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List deployments with optional filtering.

        Args:
            device_id: Filter by target device.
            firmware_id: Filter by firmware image.

        Returns
        -------
        list[dict]
            A list of matching deployment records.
        """
        conn = self._get_connection()
        query = "SELECT * FROM deployments WHERE 1=1"
        params: list[Any] = []

        if device_id is not None:
            query += " AND device_id = ?"
            params.append(device_id)
        if firmware_id is not None:
            query += " AND firmware_id = ?"
            params.append(firmware_id)

        query += " ORDER BY created_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_deployment_status(
        self,
        deployment_id: str,
        status: str,
        error_message: Optional[str] = None,
    ) -> bool:
        """Update a deployment's status.

        Automatically sets ``started_at`` when transitioning to
        ``'in_progress'`` and ``completed_at`` when transitioning to
        ``'completed'`` or ``'failed'``.

        Args:
            deployment_id: The deployment to update.
            status: New status value.
            error_message: Optional error description (for ``'failed'``
                status).

        Returns
        -------
        bool
            ``True`` if a row was updated, ``False`` otherwise.
        """
        conn = self._get_connection()
        now_iso: str = datetime.now(timezone.utc).isoformat()

        if status == "in_progress":
            cursor = conn.execute(
                "UPDATE deployments SET status = ?, started_at = ? WHERE deployment_id = ?",
                (status, now_iso, deployment_id),
            )
        elif status in ("completed", "failed"):
            cursor = conn.execute(
                """
                UPDATE deployments
                SET status = ?, completed_at = ?, error_message = ?
                WHERE deployment_id = ?
                """,
                (status, now_iso, error_message, deployment_id),
            )
        else:
            cursor = conn.execute(
                "UPDATE deployments SET status = ? WHERE deployment_id = ?",
                (status, deployment_id),
            )

        conn.commit()
        updated: bool = cursor.rowcount > 0
        if updated:
            logger.info("Deployment status updated – deployment_id=%s, status=%s", deployment_id, status)
        return updated

    # ==================================================================
    # Utility
    # ==================================================================

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics across all tables.

        Returns
        -------
        dict
            A dictionary with ``total_certificates``, ``active_certificates``,
            ``revoked_certificates``, ``total_devices``, ``total_firmware``,
            ``total_deployments``, and ``pending_deployments`` counts.
        """
        conn = self._get_connection()

        def _count(query: str) -> int:
            row = conn.execute(query).fetchone()
            return row[0] if row else 0

        return {
            "total_certificates": _count("SELECT COUNT(*) FROM certificates"),
            "active_certificates": _count(
                "SELECT COUNT(*) FROM certificates WHERE status = 'active'"
            ),
            "revoked_certificates": _count(
                "SELECT COUNT(*) FROM certificates WHERE status = 'revoked'"
            ),
            "total_devices": _count("SELECT COUNT(*) FROM devices"),
            "total_firmware": _count("SELECT COUNT(*) FROM firmware"),
            "total_deployments": _count("SELECT COUNT(*) FROM deployments"),
            "pending_deployments": _count(
                "SELECT COUNT(*) FROM deployments WHERE status = 'pending'"
            ),
        }

    def close(self) -> None:
        """Close the current thread's database connection.

        Safe to call multiple times — subsequent calls are no-ops if the
        connection is already closed.
        """
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
            logger.info("SQLiteStore connection closed.")
