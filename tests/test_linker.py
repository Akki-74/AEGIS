"""
tests.test_linker — Semantic alert linking tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.linker import AlertLinker
from aegis.correlate.schema import Alert, Severity


def _make_alert(
    aid: str,
    ts: datetime,
    hostname: str = "HOST01",
    username: str = "CORP\\user",
    process_guid: str = "",
    parent_process_guid: str = "",
    logon_id: str = "",
    source_ip: str = "",
    dest_ip: str = "",
    mitre_technique: str = "T1059.001",
) -> Alert:
    return Alert(
        alert_id=aid,
        rule_id=f"r-{aid}",
        rule_name=f"Rule {aid}",
        mitre_technique=mitre_technique,
        mitre_tactic="execution",
        timestamp=ts,
        hostname=hostname,
        username=username,
        process_guid=process_guid,
        parent_process_guid=parent_process_guid,
        logon_id=logon_id,
        source_ip=source_ip,
        dest_ip=dest_ip,
        severity=Severity.HIGH,
    )


def test_process_lineage_linking() -> None:
    """Parent-child ProcessGuid creates process_lineage link."""
    now = datetime.now(timezone.utc)
    a1 = _make_alert("a1", now, process_guid="{PARENT-GUID-100}")
    a2 = _make_alert("a2", now + timedelta(seconds=5), process_guid="{CHILD-GUID-200}", parent_process_guid="{PARENT-GUID-100}")

    resolver = EntityResolver()
    graph = resolver.build_entity_graph([a1, a2])

    linker = AlertLinker()
    linked = linker.link(graph, [a1, a2])

    # Check for process_lineage edge
    lineage_edges = [
        (u, v, d)
        for u, v, d in linked.edges(data=True)
        if d.get("link_type") == "process_lineage"
    ]
    assert len(lineage_edges) >= 1
    assert lineage_edges[0][2].get("confidence", 0) >= 0.90


def test_session_continuity_linking() -> None:
    """Alerts sharing the same LogonId on same host produce session continuity."""
    now = datetime.now(timezone.utc)
    a1 = _make_alert("a1", now, logon_id="0xABC123")
    a2 = _make_alert("a2", now + timedelta(seconds=30), logon_id="0xABC123")

    resolver = EntityResolver()
    graph = resolver.build_entity_graph([a1, a2])

    linker = AlertLinker()
    linked = linker.link(graph, [a1, a2])

    session_edges = [
        (u, v, d)
        for u, v, d in linked.edges(data=True)
        if d.get("link_type") == "session_continuity"
    ]
    assert len(session_edges) >= 1
    assert session_edges[0][2].get("confidence", 0) >= 0.85


def test_lateral_movement_linking() -> None:
    """Network connection from Host A to Host B followed by logon on Host B links lateral movement."""
    now = datetime.now(timezone.utc)
    # Host A connects to Host B
    a1 = _make_alert("a1", now, hostname="WKS01", source_ip="10.0.1.50", dest_ip="10.0.1.100")
    # Host B receives logon within 15 seconds
    a2 = _make_alert("a2", now + timedelta(seconds=15), hostname="SRV01", logon_id="0x999", source_ip="10.0.1.50", dest_ip="10.0.1.100")

    resolver = EntityResolver()
    graph = resolver.build_entity_graph([a1, a2])

    linker = AlertLinker(lateral_movement_window_s=60)
    linked = linker.link(graph, [a1, a2])

    lat_edges = [
        (u, v, d)
        for u, v, d in linked.edges(data=True)
        if d.get("link_type") == "lateral_movement"
    ]
    assert len(lat_edges) >= 1
