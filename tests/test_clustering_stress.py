"""
tests.test_clustering_stress — Stress testing temporal clustering resilience against:
1. Overlapping attacks
2. Delayed lateral movement
3. Host reboots
4. Duplicate telemetry
5. Out-of-order event streams
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.linker import AlertLinker
from aegis.correlate.schema import Alert, Severity
from aegis.correlate.windowing import TemporalClusterer


def _create_dummy_alert(
    *,
    alert_id: str,
    timestamp: datetime,
    hostname: str = "WS01",
    username: str = "victim_user",
    process_guid: str = "",
    parent_process_guid: str = "",
    logon_id: str = "",
    source_ip: str = "",
    dest_ip: str = "",
    rule_id: str = "rule_dummy",
    raw_event: dict | None = None,
) -> Alert:
    return Alert(
        rule_id=rule_id,
        rule_name=rule_id.replace("_", " ").title(),
        mitre_technique="T1059.001",
        mitre_tactic="execution",
        timestamp=timestamp,
        hostname=hostname,
        username=username,
        severity=Severity.HIGH,
        raw_event=raw_event or {},
        process_guid=process_guid,
        parent_process_guid=parent_process_guid,
        logon_id=logon_id,
        source_ip=source_ip,
        dest_ip=dest_ip,
        alert_id=alert_id,
    )


def test_duplicate_telemetry_handling() -> None:
    """Duplicate alerts ingested twice do not inflate cluster size."""
    base_t = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    a1 = _create_dummy_alert(
        alert_id="A1",
        timestamp=base_t,
        process_guid="{P1}",
    )
    a2 = _create_dummy_alert(
        alert_id="A2",
        timestamp=base_t + timedelta(seconds=30),
        process_guid="{P2}",
        parent_process_guid="{P1}",
    )
    # Exact duplicate of A1
    a1_dup = _create_dummy_alert(
        alert_id="A1",
        timestamp=base_t,
        process_guid="{P1}",
    )

    alerts = [a1, a2, a1_dup]
    resolver = EntityResolver()
    graph = resolver.build_entity_graph(alerts)
    linker = AlertLinker()
    linked_graph = linker.link(graph, alerts)

    clusterer = TemporalClusterer(window_minutes=30, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked_graph, alerts)

    assert len(clusters) == 1
    # Should only contain 2 unique alerts, deduplicating a1_dup
    assert len(clusters[0]) == 2


def test_out_of_order_event_stream() -> None:
    """Out-of-order events are ordered chronologically and produce consistent clusters."""
    base_t = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _create_dummy_alert(
            alert_id=f"A{i}",
            timestamp=base_t + timedelta(minutes=i * 2),
            process_guid=f"{{P{i}}}",
            parent_process_guid=f"{{P{i-1}}}" if i > 0 else "",
        )
        for i in range(5)
    ]

    shuffled = list(alerts)
    random.seed(42)
    random.shuffle(shuffled)

    resolver = EntityResolver()
    graph = resolver.build_entity_graph(shuffled)
    linker = AlertLinker()
    linked_graph = linker.link(graph, shuffled)

    clusterer = TemporalClusterer(window_minutes=30, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked_graph, shuffled)

    assert len(clusters) == 1
    assert len(clusters[0]) == 5
    # Verify chronological ordering in output
    for idx in range(1, len(clusters[0])):
        assert clusters[0][idx].timestamp >= clusters[0][idx - 1].timestamp


def test_delayed_lateral_movement_split() -> None:
    """Lateral movement delayed by hours splits into discrete temporal attack phases."""
    base_t = datetime(2026, 10, 29, 10, 0, 0, tzinfo=timezone.utc)
    # Phase 1: Ingress & discovery on WS01
    phase1 = [
        _create_dummy_alert(
            alert_id="P1_A",
            timestamp=base_t,
            hostname="WS01",
            process_guid="{P1}",
        ),
        _create_dummy_alert(
            alert_id="P1_B",
            timestamp=base_t + timedelta(minutes=2),
            hostname="WS01",
            process_guid="{P2}",
            parent_process_guid="{P1}",
        ),
    ]

    # Phase 2: Lateral jump to DC01 delayed by 5 hours (300 minutes)
    phase2_t = base_t + timedelta(hours=5)
    phase2 = [
        _create_dummy_alert(
            alert_id="P2_A",
            timestamp=phase2_t,
            hostname="DC01",
            process_guid="{P3}",
        ),
        _create_dummy_alert(
            alert_id="P2_B",
            timestamp=phase2_t + timedelta(minutes=1),
            hostname="DC01",
            process_guid="{P4}",
            parent_process_guid="{P3}",
        ),
    ]

    alerts = phase1 + phase2
    resolver = EntityResolver()
    graph = resolver.build_entity_graph(alerts)
    linker = AlertLinker()
    linked_graph = linker.link(graph, alerts)

    clusterer = TemporalClusterer(window_minutes=30, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked_graph, alerts)

    # Must split into two distinct temporal clusters due to 5-hour gap
    assert len(clusters) == 2
    assert [a.alert_id for a in clusters[0]] == ["P1_A", "P1_B"]
    assert [a.alert_id for a in clusters[1]] == ["P2_A", "P2_B"]


def test_host_reboot_boundary_split() -> None:
    """A system restart event splits temporal continuity on the affected host."""
    base_t = datetime(2026, 10, 29, 14, 0, 0, tzinfo=timezone.utc)
    alerts = [
        _create_dummy_alert(
            alert_id="PRE_1",
            timestamp=base_t,
            hostname="SRV01",
            process_guid="{OLD_PROC}",
        ),
        _create_dummy_alert(
            alert_id="REBOOT",
            timestamp=base_t + timedelta(minutes=2),
            hostname="SRV01",
            rule_id="system_restart_event",
            raw_event={"winlog": {"event_id": 1074}},
        ),
        _create_dummy_alert(
            alert_id="POST_1",
            timestamp=base_t + timedelta(minutes=4),
            hostname="SRV01",
            process_guid="{NEW_PROC}",
        ),
    ]

    resolver = EntityResolver()
    graph = resolver.build_entity_graph(alerts)
    linker = AlertLinker()
    linked_graph = linker.link(graph, alerts)

    clusterer = TemporalClusterer(window_minutes=30, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked_graph, alerts)

    # Reboot triggers a cluster boundary split
    assert len(clusters) >= 2
