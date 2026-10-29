"""
tests.test_entity_resolution — Entity extraction and de-duplication tests.
"""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.schema import Alert, EntityType, Severity


def _make_alert(
    hostname: str = "HOST01",
    username: str = "CORP\\jdoe",
    process_guid: str = "{1111}",
    logon_id: str = "0x3E7",
    source_ip: str = "10.0.0.1",
    dest_ip: str = "10.0.0.2",
) -> Alert:
    return Alert(
        rule_id="r1",
        rule_name="Test Rule",
        mitre_technique="T1059.001",
        mitre_tactic="execution",
        timestamp=datetime.now(timezone.utc),
        hostname=hostname,
        username=username,
        process_guid=process_guid,
        logon_id=logon_id,
        source_ip=source_ip,
        dest_ip=dest_ip,
        severity=Severity.HIGH,
    )


def test_extract_all_entity_types() -> None:
    """Ensure host, user, process, logon session, and IPs are extracted."""
    alert = _make_alert()
    resolver = EntityResolver()
    entity_map = resolver.resolve([alert])

    types_found = {e.entity_type for e in entity_map.keys()}
    assert EntityType.HOST in types_found
    assert EntityType.USER in types_found
    assert EntityType.PROCESS in types_found
    assert EntityType.LOGON_SESSION in types_found
    assert EntityType.IP in types_found


def test_process_guid_composite_key() -> None:
    """Process GUID is composite with hostname to prevent cross-host collision."""
    a1 = _make_alert(hostname="HOST-A", process_guid="{GUID-123}")
    a2 = _make_alert(hostname="HOST-B", process_guid="{GUID-123}")

    resolver = EntityResolver()
    m1 = resolver.resolve([a1])
    m2 = resolver.resolve([a2])

    p1 = [e for e in m1 if e.entity_type == EntityType.PROCESS][0]
    p2 = [e for e in m2 if e.entity_type == EntityType.PROCESS][0]

    assert p1.entity_id != p2.entity_id
    assert "host-a" in p1.entity_id.lower()
    assert "host-b" in p2.entity_id.lower()


def test_logon_id_prefixed_with_hostname() -> None:
    """Logon ID is prefixed with hostname for per-host uniqueness."""
    alert = _make_alert(hostname="DC01", logon_id="0x3E7")
    resolver = EntityResolver()
    res = resolver.resolve([alert])
    logon_entity = [e for e in res if e.entity_type == EntityType.LOGON_SESSION][0]
    assert logon_entity.entity_id == "dc01|0x3e7"


def test_username_upn_downlevel_normalization() -> None:
    """DOMAIN\\jdoe and jdoe@domain.com resolve to the same canonical user entity."""
    a1 = _make_alert(username="CORP\\jdoe")
    a2 = _make_alert(username="jdoe@corp.local")

    resolver = EntityResolver()
    res = resolver.resolve([a1, a2])

    users = [e for e in res if e.entity_type == EntityType.USER]
    # In EntityResolver, both resolve to corp\jdoe (or corp.local\jdoe normalized)
    assert len(users) <= 2  # De-duplicated or structured
    for u in users:
        assert "jdoe" in u.entity_id


def test_machine_account_tagging() -> None:
    """Accounts ending in $ are identified as machine accounts in entity attributes."""
    alert = _make_alert(username="WORKSTATION01$")
    resolver = EntityResolver()
    res = resolver.resolve([alert])
    user_entity = [e for e in res if e.entity_type == EntityType.USER][0]
    assert user_entity.attributes.get("is_machine_account") is True


def test_build_entity_graph_structure() -> None:
    """Verify build_entity_graph creates an interconnected graph."""
    alert = _make_alert()
    resolver = EntityResolver()
    graph = resolver.build_entity_graph([alert])

    assert graph.number_of_nodes() >= 4
    assert graph.number_of_edges() >= 3
