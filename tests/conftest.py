"""Shared test configuration and fixtures."""

import os

# Force in-memory storage mode for all tests so no external
# database or filesystem state is required.
os.environ["STORE_MODE"] = "memory"
