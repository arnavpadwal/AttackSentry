"""Pytest fixtures: isolate DB and data dirs to /tmp."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="attacksentry-test-"))
os.environ["SENTRY_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP / 'test.db'}"
os.environ["SENTRY_DATA_DIR"] = str(_TMP / "data")
os.environ["SENTRY_MODELS_DIR"] = str(_TMP / "models")
os.environ["SENTRY_BOOTSTRAP_ADMIN_PASSWORD"] = "test-password-123"
os.environ["SENTRY_LLM_PROVIDER"] = "none"
os.environ["SENTRY_COOKIE_SECURE"] = "false"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def tmp_dir(tmp_path):
    return tmp_path
