"""
aegis.correlate.entity_resolution
=================================

Extract typed entities from normalised alerts and build a bipartite
entity–alert graph that downstream modules use for linking, clustering,
and scoring.

Normalisation rules
-------------------
The following edge-cases are handled by :class:`EntityResolver`:

1. **Process GUID reuse across reboots** — Sysmon reuses process GUIDs
   after a reboot.  We build a *composite* process key:
   ``"{hostname}|{process_guid}"`` so that the same GUID on different
   hosts or after a reboot (when the hostname changes or a boot-time
   marker differs) does not falsely link unrelated processes.

2. **Logon ID uniqueness is per-host only** — Windows Logon IDs (e.g.
   ``0x3E7``) are recycled and only unique *within* a single boot
   session on a single host.  We prefix with the hostname:
   ``"{hostname}|{logon_id}"``.

3. **DOMAIN\\user vs user@domain.com UPN normalisation** — Active
   Directory can represent the same account as ``CORP\\jdoe`` or
   ``jdoe@corp.local``.  We canonicalise to lower-case
   ``"{domain}\\{samaccountname}"`` wherever possible.

4. **Machine accounts (trailing ``$``)** — Accounts ending with ``$``
   (e.g. ``HOST01$``) are computer accounts and are tagged with
   ``is_machine_account=True`` in the entity attributes so that
   analysts can filter or weight them differently.
"""

from __future__ import annotations

import logging
import re

import networkx as nx  # type: ignore[import-untyped]

from aegis.correlate.schema import Alert, Entity, EntityType

logger = logging.getLogger(__name__)

# Pre-compiled patterns for username normalisation.
_UPN_RE = re.compile(r"^(?P<user>[^@]+)@(?P<domain>[^@]+)$")
_DOWNLEVEL_RE = re.compile(r"^(?P<domain>[^\\]+)\\(?P<user>.+)$")


class EntityResolver:
    """Extract and normalise entities from raw alerts.

    Usage::

        resolver = EntityResolver()
        entity_map = resolver.resolve(alerts)
        graph      = resolver.build_entity_graph(alerts)
    """

    # ── Public API ─────────────────────────────────────────────────

    def resolve(
        self,
        alerts: list[Alert],
    ) -> dict[Entity, list[Alert]]:
        """Map every resolvable entity to the alerts that mention it.

        Parameters
        ----------
        alerts:
            Flat list of normalised alerts.

        Returns
        -------
        dict[Entity, list[Alert]]
            Mapping from each unique entity to the list of alerts that
            reference it (an alert can appear under multiple entities).
        """
        entity_map: dict[Entity, list[Alert]] = {}

        for alert in alerts:
            entities = self._extract_entities(alert)
            for entity in entities:
                entity_map.setdefault(entity, []).append(alert)

        logger.info(
            "Resolved %d unique entities from %d alerts",
            len(entity_map),
            len(alerts),
        )
        return entity_map

    def build_entity_graph(
        self,
        alerts: list[Alert],
    ) -> nx.Graph:
        """Build an entity-centric graph from alerts.

        Nodes
        ~~~~~
        Every unique :class:`Entity` becomes a node.  Node attributes
        include ``entity_type`` and anything in ``entity.attributes``.

        Edges
        ~~~~~
        Two entities share an edge **iff** at least one alert references
        both of them.  Edge attributes:

        * ``alert_ids`` — ``set[str]`` of alert IDs that co-reference
          the two entities.
        * ``weight`` — number of shared alerts (useful for graph
          algorithms that accept numeric weights).

        Parameters
        ----------
        alerts:
            Flat list of normalised alerts.

        Returns
        -------
        nx.Graph
            Undirected entity graph.
        """
        entity_map = self.resolve(alerts)
        graph = nx.Graph()

        # Add every entity as a node.
        for entity in entity_map:
            graph.add_node(
                entity,
                entity_type=entity.entity_type.value,
                **entity.attributes,
            )

        # For each alert, all of its entities are pair-wise connected.
        for alert in alerts:
            entities = self._extract_entities(alert)
            for i, e1 in enumerate(entities):
                for e2 in entities[i + 1 :]:
                    if graph.has_edge(e1, e2):
                        graph[e1][e2]["alert_ids"].add(alert.alert_id)
                        graph[e1][e2]["weight"] += 1
                    else:
                        graph.add_edge(
                            e1,
                            e2,
                            alert_ids={alert.alert_id},
                            weight=1,
                        )

        logger.info(
            "Entity graph: %d nodes, %d edges",
            graph.number_of_nodes(),
            graph.number_of_edges(),
        )
        return graph

    # ── Internal helpers ───────────────────────────────────────────

    def _extract_entities(self, alert: Alert) -> list[Entity]:
        """Return all entities that can be extracted from *alert*.

        The order is deterministic (host → user → process →
        logon_session → IP → network_session) so that pair-wise edge
        creation is reproducible.
        """
        entities: list[Entity] = []

        # 1. Host entity
        if alert.hostname:
            entities.append(
                Entity(
                    entity_type=EntityType.HOST,
                    entity_id=alert.hostname.lower().strip(),
                )
            )

        # 2. User entity (normalised)
        if alert.username:
            user_entity = self._normalise_user(alert.username)
            if user_entity is not None:
                entities.append(user_entity)

        # 3. Process entity (composite key to avoid GUID reuse)
        if alert.process_guid:
            composite_id = (
                f"{alert.hostname.lower().strip()}|{alert.process_guid}"
            )
            entities.append(
                Entity(
                    entity_type=EntityType.PROCESS,
                    entity_id=composite_id,
                    attributes={
                        "hostname": alert.hostname,
                        "raw_guid": alert.process_guid,
                    },
                )
            )

        # 3b. Parent process entity (same composite key logic)
        if alert.parent_process_guid:
            composite_id = (
                f"{alert.hostname.lower().strip()}"
                f"|{alert.parent_process_guid}"
            )
            entities.append(
                Entity(
                    entity_type=EntityType.PROCESS,
                    entity_id=composite_id,
                    attributes={
                        "hostname": alert.hostname,
                        "raw_guid": alert.parent_process_guid,
                        "is_parent": True,
                    },
                )
            )

        # 4. Logon session entity (prefixed with hostname)
        if alert.logon_id:
            session_id = (
                f"{alert.hostname.lower().strip()}|{alert.logon_id.lower().strip()}"
            )
            entities.append(
                Entity(
                    entity_type=EntityType.LOGON_SESSION,
                    entity_id=session_id,
                    attributes={"hostname": alert.hostname},
                )
            )

        # 5. IP entities (source and destination)
        if alert.source_ip:
            entities.append(
                Entity(
                    entity_type=EntityType.IP,
                    entity_id=alert.source_ip,
                    attributes={"direction": "source"},
                )
            )
        if alert.dest_ip:
            entities.append(
                Entity(
                    entity_type=EntityType.IP,
                    entity_id=alert.dest_ip,
                    attributes={"direction": "destination"},
                )
            )

        # 6. Network session entity
        if alert.network_session_id:
            entities.append(
                Entity(
                    entity_type=EntityType.NETWORK_SESSION,
                    entity_id=alert.network_session_id,
                )
            )

        return entities

    @staticmethod
    def _normalise_user(raw: str) -> Entity | None:
        """Normalise a username string to a canonical ``Entity``.

        Handles:
        * ``DOMAIN\\user``  → ``domain\\user``
        * ``user@domain``   → ``domain\\user``
        * bare ``user``     → ``_local\\user``
        * Machine accounts  → flagged via ``is_machine_account`` attr.

        Returns ``None`` when the raw string is empty or whitespace-only.
        """
        raw = raw.strip()
        if not raw:
            return None

        domain: str = "_local"
        user: str = raw

        # Try UPN format first: user@domain
        m = _UPN_RE.match(raw)
        if m:
            user = m.group("user")
            domain = m.group("domain").split(".")[0]  # corp.local → corp
        else:
            # Try down-level format: DOMAIN\user
            m = _DOWNLEVEL_RE.match(raw)
            if m:
                domain = m.group("domain")
                user = m.group("user")

        domain = domain.lower()
        user = user.lower()

        is_machine = user.endswith("$")

        entity_id = f"{domain}\\{user}"
        return Entity(
            entity_type=EntityType.USER,
            entity_id=entity_id,
            attributes={
                "domain": domain,
                "samaccountname": user,
                "is_machine_account": is_machine,
            },
        )
