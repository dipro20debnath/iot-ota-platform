"""
Database Schema Definitions
============================

SQL table creation statements for the IoT OTA Platform's SQLite database.

Each constant holds a ``CREATE TABLE IF NOT EXISTS`` statement for one of the
platform's core entities.  The :data:`ALL_TABLES` list is consumed at startup
by :class:`~app.db.sqlite_store.SQLiteStore` to initialise the database.

.. note::
   Timestamps are stored as ISO-8601 ``TEXT`` columns because SQLite has
   no native ``DATETIME`` type.  The ``DEFAULT (datetime('now'))`` clause
   ensures new rows receive a UTC timestamp automatically.
"""

CREATE_CERTIFICATES_TABLE: str = """
CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cert_id TEXT UNIQUE NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    subject_cn TEXT NOT NULL,
    issuer_cn TEXT NOT NULL,
    cert_type TEXT NOT NULL DEFAULT 'device',
    status TEXT NOT NULL DEFAULT 'active',
    algorithm TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    parent_cert_id TEXT,
    pem_data TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

CREATE_DEVICES_TABLE: str = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT 'generic',
    group_name TEXT,
    firmware_version TEXT,
    status TEXT NOT NULL DEFAULT 'registered',
    certificate_id TEXT,
    ip_address TEXT,
    last_heartbeat TEXT,
    registered_at TEXT NOT NULL DEFAULT (datetime('now')),
    metadata TEXT DEFAULT '{}'
);
"""

CREATE_FIRMWARE_TABLE: str = """
CREATE TABLE IF NOT EXISTS firmware (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firmware_id TEXT UNIQUE NOT NULL,
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    file_hash_sha256 TEXT,
    file_size_bytes INTEGER,
    signature TEXT,
    signer_cert_id TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    target_device_type TEXT NOT NULL DEFAULT 'generic',
    min_version TEXT,
    release_notes TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    published_at TEXT
);
"""

CREATE_DEPLOYMENTS_TABLE: str = """
CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id TEXT UNIQUE NOT NULL,
    firmware_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

ALL_TABLES: list[str] = [
    CREATE_CERTIFICATES_TABLE,
    CREATE_DEVICES_TABLE,
    CREATE_FIRMWARE_TABLE,
    CREATE_DEPLOYMENTS_TABLE,
]
