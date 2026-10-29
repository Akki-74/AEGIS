"""
tests.test_graph — Cytoscape JSON generation and HTML report rendering tests.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from aegis.correlate.schema import Alert, Incident, Severity
from aegis.graph.builder import AttackGraphBuilder
from aegis.graph.renderer import HTMLReportRenderer


def _make_incident() -> Incident:
    now = datetime.now(timezone.utc)
    a1 = Alert(
        rule_id="r1",
        rule_name="PowerShell Execution",
        mitre_technique="T1059.001",
        mitre_tactic="execution",
        timestamp=now,
        hostname="WKS01",
        username="CORP\\attacker",
        severity=Severity.HIGH,
    )
    a2 = Alert(
        rule_id="r2",
        rule_name="LSASS Access",
        mitre_technique="T1003.001",
        mitre_tactic="credential_access",
        timestamp=now,
        hostname="WKS01",
        username="CORP\\attacker",
        severity=Severity.CRITICAL,
    )
    return Incident(
        alerts=[a1, a2],
        tactics={"execution", "credential_access"},
        techniques={"T1059.001", "T1003.001"},
        hosts={"WKS01"},
        users={"CORP\\attacker"},
        score=0.85,
        severity="critical",
        playbook_recommendations=["playbooks/credential_theft.yml"],
    )


def test_build_cytoscape_elements() -> None:
    """Verify builder produces nodes and edges in Cytoscape.js format."""
    incident = _make_incident()
    builder = AttackGraphBuilder()
    data = builder.build(incident)

    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) >= 2
    assert len(data["edges"]) >= 1

    node_data = data["nodes"][0]["data"]
    assert "id" in node_data
    assert "label" in node_data
    assert "colour" in node_data


def test_build_timeline() -> None:
    """Verify timeline is ordered chronologically."""
    incident = _make_incident()
    builder = AttackGraphBuilder()
    timeline = builder.build_timeline(incident)

    assert len(timeline) == 2
    assert timeline[0]["rule_name"] == "PowerShell Execution"
    assert timeline[1]["rule_name"] == "LSASS Access"


def test_render_html_report() -> None:
    """Verify HTMLReportRenderer creates a non-empty self-contained HTML file."""
    incident = _make_incident()
    builder = AttackGraphBuilder()
    graph_data = builder.build(incident)

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_file = Path(tmp_dir) / "test_report.html"
        renderer = HTMLReportRenderer()
        res = renderer.render(incident, graph_data, out_file)

        assert res.exists()
        content = res.read_text(encoding="utf-8")
        assert "AEGIS ATTACK GRAPH" in content
        assert "Cytoscape" in content or "cytoscape" in content
        assert "T1003.001" in content
