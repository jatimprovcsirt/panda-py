"""
Shared pytest fixtures for test modules.
"""

import os

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture(autouse=True)
def _skip_online_token_validation(monkeypatch):
    """
    Keep the token gate offline for every test.

    `init` now validates the token against the live portal, so without this
    every CLI test would make a real HTTPS request to the production portal,
    wait five seconds for it to fail, and then assert against the wrong
    outcome. It would also mean a test suite whose result depended on whether
    the portal happened to be reachable.

    The same escape hatch the other three SDKs' test suites use. It is set
    here as an autouse fixture rather than in each test so that a new test
    cannot forget it — which is how the gateway would end up being tested by
    accident, or not at all.
    """
    monkeypatch.setenv("PANDA_SKIP_ONLINE_VALIDATION", "1")
    # And keep is_local_environment() predictable: an inherited APP_ENV from
    # the developer's shell would otherwise change whether the demo-token
    # warning appears.
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.delenv("NODE_ENV", raising=False)


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)
