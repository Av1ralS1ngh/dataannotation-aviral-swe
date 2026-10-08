from __future__ import annotations

import os

import pytest


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        f"sqlite+pysqlite:///{tmp_path / 'audit.db'}",
    )
    monkeypatch.setenv("OPERATOR_DIR", str(tmp_path / "operator"))
    monkeypatch.setenv("STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ONLINE_KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin")
    monkeypatch.setenv("PUBLISHER_TOKEN", "test-publisher")

    from release_trust.config import get_settings
    from release_trust.db import get_engine, get_session_factory

    get_settings.cache_clear()
    get_engine.cache_clear()
    get_session_factory.cache_clear()
    yield tmp_path
    get_session_factory.cache_clear()
    get_engine.cache_clear()
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def deterministic_environment(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", os.getenv("LOG_LEVEL", "WARNING"))
