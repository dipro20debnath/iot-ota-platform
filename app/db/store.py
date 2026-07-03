"""
Store Factory
==============

Provides a singleton :class:`~app.db.sqlite_store.SQLiteStore` instance
for the application.

The singleton pattern ensures a single database connection pool is shared
across all modules, while :func:`reset_store` allows tests to tear down
and recreate the store between runs.

Usage::

    from app.db.store import get_store

    store = get_store()
    store.save_cert({...})

Environment Variables
---------------------
STORE_MODE
    Set to ``'memory'`` to use an in-memory SQLite database (useful for
    automated tests).
"""

from __future__ import annotations

import os
from typing import Optional

from app.db.sqlite_store import SQLiteStore

_store_instance: Optional[SQLiteStore] = None


def get_store(db_path: Optional[str] = None) -> SQLiteStore:
    """Get or create the singleton :class:`SQLiteStore` instance.

    On the first call the store is initialised.  Subsequent calls return
    the same instance.

    If the ``STORE_MODE`` environment variable is set to ``'memory'``,
    an in-memory database (``':memory:'``) is used — handy for unit and
    integration tests that should not touch the filesystem.

    Args:
        db_path: Optional override for the database file path.  Ignored
            after the singleton has been created.

    Returns
    -------
    SQLiteStore
        The global store instance.
    """
    global _store_instance
    if _store_instance is None:
        if os.environ.get("STORE_MODE") == "memory":
            _store_instance = SQLiteStore(":memory:")
        else:
            _store_instance = SQLiteStore(db_path or "./pki_data/ota_platform.db")
    return _store_instance


def reset_store() -> None:
    """Tear down and discard the singleton store.

    Closes the underlying database connection and sets the module-level
    reference to ``None`` so that the next :func:`get_store` call creates
    a fresh instance.

    Primarily intended for test fixtures.
    """
    global _store_instance
    if _store_instance is not None:
        _store_instance.close()
    _store_instance = None
