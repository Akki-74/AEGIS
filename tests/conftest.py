"""
tests.conftest — Shared test fixtures for AEGIS test suite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.config import AegisConfig
from aegis.correlate.schema import Alert

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture(rel_path: str) -> list[dict[str, Any]]:
    """Load JSON fixture file relative to tests/fixtures/."""
    file_path = FIXTURE_DIR / rel_path
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        return data.get("alerts", [data])
    return data


try:
    import pytest

    @pytest.fixture
    def sample_config() -> AegisConfig:
        """Return default AegisConfig instance."""
        return AegisConfig()

    @pytest.fixture
    def full_attack_chain_alerts() -> list[Alert]:
        """Return Alert objects from malicious/full_attack_chain.json."""
        raw = load_fixture("malicious/full_attack_chain.json")
        return [Alert.from_dict(item) for item in raw]

    @pytest.fixture
    def benign_alerts() -> list[Alert]:
        """Return Alert objects from benign baseline fixtures."""
        raw = load_fixture("benign/admin_powershell_session.json")
        return [Alert.from_dict(item) for item in raw]

except ImportError:
    pass
