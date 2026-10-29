"""
aegis.correlate.linker
======================

Enrich the entity graph with typed, confidence-weighted edges that
capture the *semantic reason* two alerts are related.

Link types
----------
1. **Process lineage** — ``parent_process_guid`` ↔ ``process_guid``
   chains.  Confidence: 0.95 (deterministic link, slight discount for
   potential GUID reuse despite our composite-key mitigation).

2. **Session continuity** — Same Logon ID on the same host.
   Confidence: 0.90.

3. **Network session / lateral movement** — A process on host A opens a
   connection to host B (``source_ip`` → ``dest_ip``), then a logon
   appears on host B within *N* seconds.  This is the classic
   lateral-movement indicator.  Confidence: 0.75 (heuristic, may be
   coincidental).

4. **User activity** — Same normalised user active on multiple hosts
   within a configurable time window.  Confidence: 0.60 (weak — normal
   for admins).

Edge attributes
~~~~~~~~~~~~~~~
Every edge added by the linker carries:

* ``link_type`` — one of ``"process_lineage"``, ``"session_continuity"``,
  ``"lateral_movement"``, ``"user_activity"``.
* ``confidence`` — float in ``[0.0, 1.0]``.
* ``temporal_distance_seconds`` — absolute seconds between the two
  alerts that motivated the edge.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx  # type: ignore[import-untyped]

from aegis.correlate.schema import Alert, Entity, EntityType

logger = logging.getLogger(__name__)

# Default lateral-movement window (seconds).  Overridable via config.
_DEFAULT_LATERAL_WINDOW_S: int = 120

# Default user-activity window (seconds).
_DEFAULT_USER_ACTIVITY_WINDOW_S: int = 1800  # 30 minutes


class AlertLinker:
    """Enrich an entity graph with semantically-typed edges.

    Parameters
    ----------
    lateral_movement_window_s:
        Maximum seconds between a network connection from host A → B
        and a logon on host B for us to infer lateral movement.
    user_activity_window_s:
        Maximum seconds between two alerts sharing the same user on
        different hosts for us to add a ``user_activity`` edge.
    """

    def __init__(
        self,
        lateral_movement_window_s: int = _DEFAULT_LATERAL_WINDOW_S,
        user_activity_window_s: int = _DEFAULT_USER_ACTIVITY_WINDOW_S,
    ) -> None:
        self.lateral_movement_window_s = lateral_movement_window_s
        self.user_activity_window_s = user_activity_window_s

    # ── Public API ─────────────────────────────────────────────────

    def link(
        self,
        entity_graph: nx.Graph,
        alerts: list[Alert],
    ) -> nx.Graph:
        """Return a copy of *entity_graph* enriched with link-type edges.

        The original graph is **not** mutated; a deep copy is returned.

        Parameters
        ----------
        entity_graph:
            The entity graph produced by
            :meth:`EntityResolver.build_entity_graph`.
        alerts:
            The same flat alert list used to build the graph.

        Returns
        -------
        nx.Graph
            Enriched graph with ``link_type``, ``confidence``, and
            ``temporal_distance_seconds`` edge attributes.
        """
        graph: nx.Graph = entity_graph.copy()

        # Sort alerts once for temporal comparisons.
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        # Build lookup indices for each linking strategy.
        self._link_process_lineage(graph, sorted_alerts)
        self._link_session_continuity(graph, sorted_alerts)
        self._link_lateral_movement(graph, sorted_alerts)
        self._link_user_activity(graph, sorted_alerts)

        logger.info(
            "Linker produced graph with %d nodes, %d edges",
            graph.number_of_nodes(),
            graph.number_of_edges(),
        )
        return graph

    # ── Linking strategies ─────────────────────────────────────────

    def _link_process_lineage(
        self,
        graph: nx.Graph,
        alerts: list[Alert],
    ) -> None:
        """Link child → parent process entities.

        If alert A has ``process_guid = X`` and alert B has
        ``parent_process_guid = X`` (on the same host), we add an edge
        between the two *process* entities.
        """
        # Index: composite process key → list[Alert]
        proc_index: dict[str, list[Alert]] = {}
        for alert in alerts:
            if alert.process_guid:
                key = f"{alert.hostname.lower().strip()}|{alert.process_guid}"
                proc_index.setdefault(key, []).append(alert)

        for alert in alerts:
            if not alert.parent_process_guid:
                continue

            parent_key = (
                f"{alert.hostname.lower().strip()}"
                f"|{alert.parent_process_guid}"
            )
            child_key = (
                f"{alert.hostname.lower().strip()}"
                f"|{alert.process_guid}"
            )
            if not alert.process_guid:
                continue

            parent_entity = Entity(
                entity_type=EntityType.PROCESS,
                entity_id=parent_key,
            )
            child_entity = Entity(
                entity_type=EntityType.PROCESS,
                entity_id=child_key,
            )

            if parent_entity not in graph or child_entity not in graph:
                continue

            # Temporal distance: use the earliest alert referencing each
            # entity.
            parent_alerts = proc_index.get(parent_key, [])
            if not parent_alerts:
                continue

            td = abs(
                (alert.timestamp - parent_alerts[0].timestamp).total_seconds()
            )

            self._add_link_edge(
                graph,
                parent_entity,
                child_entity,
                link_type="process_lineage",
                confidence=0.95,
                temporal_distance_seconds=td,
            )

        logger.debug("Process-lineage linking complete.")

    def _link_session_continuity(
        self,
        graph: nx.Graph,
        alerts: list[Alert],
    ) -> None:
        """Link alerts that share the same Logon ID on the same host.

        The logon-session entity is already composite
        (``hostname|logon_id``), so we just look for co-occurrence.
        """
        session_index: dict[str, list[Alert]] = {}
        for alert in alerts:
            if alert.logon_id:
                key = f"{alert.hostname.lower().strip()}|{alert.logon_id.lower().strip()}"
                session_index.setdefault(key, []).append(alert)

        for session_key, session_alerts in session_index.items():
            if len(session_alerts) < 2:
                continue

            session_entity = Entity(
                entity_type=EntityType.LOGON_SESSION,
                entity_id=session_key,
            )

            if session_entity not in graph:
                continue

            # Connect host entity to session entity (reinforce).
            hostname = session_key.split("|")[0]
            host_entity = Entity(
                entity_type=EntityType.HOST,
                entity_id=hostname,
            )

            if host_entity in graph:
                td = abs(
                    (
                        session_alerts[-1].timestamp
                        - session_alerts[0].timestamp
                    ).total_seconds()
                )
                self._add_link_edge(
                    graph,
                    host_entity,
                    session_entity,
                    link_type="session_continuity",
                    confidence=0.90,
                    temporal_distance_seconds=td,
                )

        logger.debug("Session-continuity linking complete.")

    def _link_lateral_movement(
        self,
        graph: nx.Graph,
        alerts: list[Alert],
    ) -> None:
        """Detect lateral-movement edges.

        Heuristic:
        1. Find alerts with a ``dest_ip`` (outbound connection from
           host A).
        2. Find subsequent alerts on the destination host (matched by
           IP) that contain a logon event within
           ``lateral_movement_window_s``.
        3. Add an edge between the source-host entity and the
           destination-host entity with ``link_type="lateral_movement"``.
        """
        # Build a reverse index: IP → hostname(s) observed for that IP.
        ip_to_hosts: dict[str, set[str]] = {}
        for alert in alerts:
            host = alert.hostname.lower().strip()
            if alert.source_ip:
                ip_to_hosts.setdefault(alert.source_ip, set()).add(host)
            if alert.dest_ip:
                ip_to_hosts.setdefault(alert.dest_ip, set()).add(host)

        # Build index: hostname → sorted alerts with logon_id set
        host_logon_alerts: dict[str, list[Alert]] = {}
        for alert in alerts:
            if alert.logon_id:
                host = alert.hostname.lower().strip()
                host_logon_alerts.setdefault(host, []).append(alert)

        for alert in alerts:
            if not alert.dest_ip:
                continue

            src_host = alert.hostname.lower().strip()
            dest_hosts = ip_to_hosts.get(alert.dest_ip, set()) - {src_host}

            for dest_host in dest_hosts:
                logon_alerts = host_logon_alerts.get(dest_host, [])
                for logon_alert in logon_alerts:
                    td = (
                        logon_alert.timestamp - alert.timestamp
                    ).total_seconds()
                    if 0 <= td <= self.lateral_movement_window_s:
                        src_entity = Entity(
                            entity_type=EntityType.HOST,
                            entity_id=src_host,
                        )
                        dst_entity = Entity(
                            entity_type=EntityType.HOST,
                            entity_id=dest_host,
                        )
                        # Ensure both nodes exist.
                        if src_entity in graph and dst_entity in graph:
                            self._add_link_edge(
                                graph,
                                src_entity,
                                dst_entity,
                                link_type="lateral_movement",
                                confidence=0.75,
                                temporal_distance_seconds=td,
                            )

        logger.debug("Lateral-movement linking complete.")

    def _link_user_activity(
        self,
        graph: nx.Graph,
        alerts: list[Alert],
    ) -> None:
        """Link hosts where the same user is active within a time window.

        This is a *weak* signal — administrators routinely log into many
        hosts — so confidence is lower (0.60).
        """
        from aegis.correlate.entity_resolution import EntityResolver

        resolver = EntityResolver()

        # user_entity_id → list[(host_entity, alert)]
        user_index: dict[str, list[tuple[Entity, Alert]]] = {}
        for alert in alerts:
            if not alert.username:
                continue
            user_ent = resolver._normalise_user(alert.username)
            if user_ent is None:
                continue
            host_ent = Entity(
                entity_type=EntityType.HOST,
                entity_id=alert.hostname.lower().strip(),
            )
            user_index.setdefault(user_ent.entity_id, []).append(
                (host_ent, alert)
            )

        for user_id, entries in user_index.items():
            # Sort by timestamp.
            entries.sort(key=lambda x: x[1].timestamp)
            for i in range(len(entries)):
                for j in range(i + 1, len(entries)):
                    host_a, alert_a = entries[i]
                    host_b, alert_b = entries[j]
                    if host_a == host_b:
                        continue  # same host — not interesting here
                    td = abs(
                        (
                            alert_b.timestamp - alert_a.timestamp
                        ).total_seconds()
                    )
                    if td > self.user_activity_window_s:
                        break  # sorted — no point checking further
                    if host_a in graph and host_b in graph:
                        self._add_link_edge(
                            graph,
                            host_a,
                            host_b,
                            link_type="user_activity",
                            confidence=0.60,
                            temporal_distance_seconds=td,
                        )

        logger.debug("User-activity linking complete.")

    # ── Edge helper ────────────────────────────────────────────────

    @staticmethod
    def _add_link_edge(
        graph: nx.Graph,
        u: Entity,
        v: Entity,
        *,
        link_type: str,
        confidence: float,
        temporal_distance_seconds: float,
    ) -> None:
        """Add or update a semantically-typed edge between *u* and *v*.

        If an edge already exists, we keep the one with the *higher*
        confidence and add the new ``link_type`` to a set of types on
        the edge (an edge can be explained by more than one heuristic).
        """
        if graph.has_edge(u, v):
            data: dict[str, Any] = graph[u][v]
            existing_types: set[str] = data.setdefault(
                "link_types", {data.get("link_type", "unknown")}
            )
            existing_types.add(link_type)
            data["link_types"] = existing_types
            # Keep highest confidence.
            data["confidence"] = max(
                data.get("confidence", 0.0), confidence
            )
            # Keep smallest temporal distance.
            data["temporal_distance_seconds"] = min(
                data.get("temporal_distance_seconds", float("inf")),
                temporal_distance_seconds,
            )
            # Preserve backward-compat single link_type as the dominant.
            data["link_type"] = max(
                existing_types,
                key=lambda lt: {
                    "process_lineage": 4,
                    "session_continuity": 3,
                    "lateral_movement": 2,
                    "user_activity": 1,
                }.get(lt, 0),
            )
        else:
            graph.add_edge(
                u,
                v,
                link_type=link_type,
                link_types={link_type},
                confidence=confidence,
                temporal_distance_seconds=temporal_distance_seconds,
            )
