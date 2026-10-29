"""
tests.test_windowing — DisjointSet data structure and temporal clustering tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.linker import AlertLinker
from aegis.correlate.schema import Alert, Severity
from aegis.correlate.windowing import DisjointSet, TemporalClusterer


def test_disjoint_set_union_and_find() -> None:
    """Test DisjointSet correctness: make_set, union, find, and components."""
    ds = DisjointSet()
    for item in ("a", "b", "c", "d", "e"):
        ds.make_set(item)

    ds.union("a", "b")
    ds.union("b", "c")
    assert ds.find("a") == ds.find("c")
    assert ds.find("a") != ds.find("d")

    ds.union("d", "e")
    groups = ds.components()
    assert len(groups) == 2


def _make_alert(aid: str, ts: datetime, host: str = "H1") -> Alert:
    return Alert(
        alert_id=aid,
        rule_id=f"r-{aid}",
        rule_name="Test Rule",
        mitre_technique="T1059.001",
        mitre_tactic="execution",
        timestamp=ts,
        hostname=host,
        username="user",
        severity=Severity.HIGH,
    )


def test_single_temporal_cluster() -> None:
    """Alerts occurring within 5 minutes of each other on same host merge into 1 cluster."""
    now = datetime.now(timezone.utc)
    a1 = _make_alert("a1", now)
    a2 = _make_alert("a2", now + timedelta(minutes=2))
    a3 = _make_alert("a3", now + timedelta(minutes=4))

    resolver = EntityResolver()
    graph = resolver.build_entity_graph([a1, a2, a3])
    linker = AlertLinker()
    linked = linker.link(graph, [a1, a2, a3])

    clusterer = TemporalClusterer(window_minutes=30, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked, [a1, a2, a3])

    assert len(clusters) == 1
    assert len(clusters[0]) == 3


def test_gap_timeout_splits_clusters() -> None:
    """A 25-minute silence gap between alerts splits them into 2 distinct incidents."""
    now = datetime.now(timezone.utc)
    a1 = _make_alert("a1", now)
    a2 = _make_alert("a2", now + timedelta(minutes=3))
    # 25 minute gap exceeds gap_timeout_minutes=10
    a3 = _make_alert("a3", now + timedelta(minutes=28))

    resolver = EntityResolver()
    graph = resolver.build_entity_graph([a1, a2, a3])
    linker = AlertLinker()
    linked = linker.link(graph, [a1, a2, a3])

    clusterer = TemporalClusterer(window_minutes=60, gap_timeout_minutes=10)
    clusters = clusterer.cluster(linked, [a1, a2, a3])

    assert len(clusters) == 2
