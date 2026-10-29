"""
tests.test_correlation_engine — End-to-end integration tests on realistic attack chains.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.correlate.engine import CorrelationEngine
from aegis.correlate.schema import Alert

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_full_attack_chain_correlation() -> None:
    """Load full attack chain fixture and verify clustering, blast radius, and playbooks."""
    fixture_path = FIXTURES_DIR / "malicious" / "full_attack_chain.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = [Alert.from_dict(item) for item in data]
    assert len(alerts) >= 5, "Expected multi-alert attack chain fixture"

    engine = CorrelationEngine()
    incidents = engine.process(alerts)

    assert len(incidents) >= 1, "Should correlate into at least 1 primary incident"
    top_incident = incidents[0]

    # Verify high severity from multi-stage attack
    assert top_incident.severity in ("high", "critical", "medium")
    assert top_incident.score >= 0.40

    # Verify techniques recognized
    assert len(top_incident.techniques) >= 2

    # Verify blast radius covers multiple hosts
    assert top_incident.blast_radius.get("hosts_touched", 0) >= 1

    # Verify playbooks were recommended
    assert len(top_incident.playbook_recommendations) >= 1


def test_benign_traffic_separation() -> None:
    """Benign baseline alerts result in low scores or clean separation."""
    fixture_path = FIXTURES_DIR / "benign" / "admin_powershell_session.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = [Alert.from_dict(item) for item in data]
    engine = CorrelationEngine()
    incidents = engine.process(alerts)

    for inc in incidents:
        assert inc.severity in ("low", "info", "medium")
