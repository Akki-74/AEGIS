"""
Attack-graph builder — converts AEGIS Incidents into Cytoscape.js graphs.

The ``AttackGraphBuilder`` transforms the entity-alert structure of a
correlated Incident into a JSON dict that can be fed directly to
Cytoscape.js for interactive, browser-based visualisation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


# ── Colour palettes ────────────────────────────────────────────────────
NODE_COLOURS: dict[str, str] = {
    "host": "#4A90D9",
    "user": "#E67E22",
    "process": "#27AE60",
    "ip": "#8E44AD",
    "session": "#F39C12",
    "logon_session": "#F39C12",
    "network_session": "#8E44AD",
}

EDGE_COLOURS: dict[str, str] = {
    "critical": "#E74C3C",
    "high": "#E67E22",
    "medium": "#F1C40F",
    "low": "#3498DB",
    "info": "#95A5A6",
}


def _iso(dt: datetime | None) -> str | None:
    """Return an ISO-8601 string or None."""
    return dt.isoformat() if dt else None


class AttackGraphBuilder:
    """Convert an Incident into Cytoscape.js graph structures."""

    def build(self, incident: Any) -> dict[str, Any]:
        """Build a Cytoscape.js-compatible JSON graph from *incident*."""
        nodes = self._build_nodes(incident)
        edges = self._build_edges(incident)
        return {"nodes": nodes, "edges": edges}

    def build_timeline(self, incident: Any) -> list[dict[str, Any]]:
        """Return a chronological list of alert events for *incident*."""
        timeline: list[dict[str, Any]] = []
        alerts = sorted(incident.alerts, key=lambda a: a.timestamp)
        for alert in alerts:
            # Technique list
            techs = getattr(alert, "mitre_techniques", None)
            if not techs and getattr(alert, "mitre_technique", None):
                techs = [alert.mitre_technique]
            elif not techs:
                techs = []

            # Severity str
            sev = alert.severity
            sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()

            # Entities list
            entities_desc: list[str] = []
            if hasattr(alert, "entities") and alert.entities:
                for e in alert.entities:
                    label = getattr(e, "label", getattr(e, "entity_id", str(e)))
                    entities_desc.append(str(label))
            else:
                for f in ("hostname", "username", "process_guid", "source_ip", "dest_ip"):
                    val = getattr(alert, f, "")
                    if val:
                        entities_desc.append(f"{f}:{val}")

            link_type = getattr(alert, "link_type", "")
            aid = getattr(alert, "alert_id", getattr(alert, "id", ""))

            timeline.append({
                "timestamp": _iso(alert.timestamp),
                "rule_name": alert.rule_name,
                "severity": sev_str,
                "techniques": techs,
                "entities": entities_desc,
                "link_type": link_type,
                "alert_id": aid,
            })
        return timeline

    def _build_nodes(self, incident: Any) -> list[dict[str, Any]]:
        """Produce Cytoscape node elements from incident entities."""
        nodes: list[dict[str, Any]] = []
        raw_entities = incident.entities
        if isinstance(raw_entities, dict):
            entity_list = list(raw_entities.values())
        elif isinstance(raw_entities, (set, list)):
            entity_list = list(raw_entities)
        else:
            entity_list = []

        seen_ids: set[str] = set()

        for entity in entity_list:
            eid = getattr(entity, "entity_id", getattr(entity, "id", str(entity)))
            if eid in seen_ids:
                continue
            seen_ids.add(eid)

            etype_obj = getattr(entity, "entity_type", getattr(entity, "type", "host"))
            etype_str = etype_obj.value if hasattr(etype_obj, "value") else str(etype_obj).lower()

            label = getattr(entity, "label", eid)
            first_seen = getattr(entity, "first_seen", None)
            last_seen = getattr(entity, "last_seen", None)

            nodes.append({
                "data": {
                    "id": eid,
                    "label": label,
                    "type": etype_str,
                    "colour": NODE_COLOURS.get(etype_str, "#64748B"),
                    "first_seen": _iso(first_seen),
                    "last_seen": _iso(last_seen),
                }
            })

        # Also ensure hosts and users from alerts exist as nodes if not present
        for alert in incident.alerts:
            host = getattr(alert, "hostname", "")
            user = getattr(alert, "username", "")
            if host and host not in seen_ids:
                seen_ids.add(host)
                nodes.append({
                    "data": {
                        "id": host,
                        "label": host,
                        "type": "host",
                        "colour": NODE_COLOURS["host"],
                    }
                })
            if user and user not in seen_ids:
                seen_ids.add(user)
                nodes.append({
                    "data": {
                        "id": user,
                        "label": user,
                        "type": "user",
                        "colour": NODE_COLOURS["user"],
                    }
                })

        return nodes

    def _build_edges(self, incident: Any) -> list[dict[str, Any]]:
        """Produce Cytoscape edge elements from incident alerts."""
        edges: list[dict[str, Any]] = []
        sorted_alerts = sorted(incident.alerts, key=lambda a: a.timestamp)

        for idx, alert in enumerate(sorted_alerts):
            source, target = self._resolve_edge_endpoints(alert)
            if not source or not target:
                continue

            techs = getattr(alert, "mitre_techniques", None)
            if not techs and getattr(alert, "mitre_technique", None):
                techs = [alert.mitre_technique]
            elif not techs:
                techs = []
            technique_label = ", ".join(techs) if techs else alert.rule_name

            sev = alert.severity
            sev_str = sev.value if hasattr(sev, "value") else str(sev).lower()
            aid = getattr(alert, "alert_id", getattr(alert, "id", f"a{idx}"))

            edges.append({
                "data": {
                    "id": f"e{idx}-{aid[:8]}",
                    "source": source,
                    "target": target,
                    "label": technique_label,
                    "link_type": getattr(alert, "link_type", ""),
                    "timestamp": _iso(alert.timestamp),
                    "severity": sev_str,
                    "colour": EDGE_COLOURS.get(sev_str, "#95A5A6"),
                }
            })
        return edges

    @staticmethod
    def _resolve_edge_endpoints(alert: Any) -> tuple[str | None, str | None]:
        """Determine source and target entity IDs for an edge."""
        source = getattr(alert, "source_entity_id", None)
        target = getattr(alert, "target_entity_id", None)
        if source and target:
            return source, target

        # Check hostname and username
        host = getattr(alert, "hostname", "")
        user = getattr(alert, "username", "")
        proc = getattr(alert, "process_guid", "")
        sip = getattr(alert, "source_ip", "")
        dip = getattr(alert, "dest_ip", "")

        if sip and dip:
            return sip, dip
        if host and user:
            return user, host
        if host and proc:
            return proc, host

        # Fall back to entities list if available
        entities = getattr(alert, "entities", [])
        if len(entities) >= 2:
            s_id = getattr(entities[0], "entity_id", getattr(entities[0], "id", None))
            t_id = getattr(entities[1], "entity_id", getattr(entities[1], "id", None))
            return s_id, t_id
        elif len(entities) == 1:
            eid = getattr(entities[0], "entity_id", getattr(entities[0], "id", None))
            return eid, eid

        if host:
            return host, host
        return None, None
