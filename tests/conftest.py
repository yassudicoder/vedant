"""
Shared pytest configuration.

Environment variables are set BEFORE any backend module is imported so the
test-suite uses an isolated temporary SQLite database and a fixed JWT secret.

Tests that need real Internet access are marked ``@pytest.mark.network`` and
are skipped unless ``--run-network`` is passed:

    python -m pytest -q                 # offline, deterministic
    python -m pytest -q --run-network   # also run live-network tests
"""
from __future__ import annotations

import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="phishguard-test-")
os.environ["PHISHGUARD_TESTING"] = "1"
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_TMP_DIR, 'test.db').replace(os.sep, '/')}"
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production-0123456789abcdef")
os.environ.setdefault("ADMIN_EMAIL", "")
os.environ.setdefault("ADMIN_PASSWORD", "")

import pytest  # noqa: E402


def pytest_addoption(parser):
    parser.addoption("--run-network", action="store_true", default=False, help="run tests that need Internet access")


def pytest_configure(config):
    config.addinivalue_line("markers", "network: test requires Internet access (use --run-network)")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-network"):
        return
    skip_network = pytest.mark.skip(reason="needs --run-network")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip_network)
