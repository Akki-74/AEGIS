"""
aegis.correlate.windowing
=========================

Temporal clustering of linked alerts into discrete incidents using a
Union-Find (Disjoint Set) data structure with temporal constraints.

Algorithm
---------
1. Assign each alert its own singleton cluster.
2. Walk every edge in the linked entity graph.  For each edge that
   connects two alerts:
   - If both alerts fall within ``window_minutes`` of each other →
     **merge** their clusters (Union).
3. After merging, examine each cluster for temporal *gaps*.  Within a
   cluster, sort alerts by timestamp.  If any consecutive pair has a
   gap ≥ ``gap_timeout_minutes`` → **split** the cluster at that
   boundary.
4. Return the final list of alert groups, each of which becomes an
   :class:`~aegis.correlate.schema.Incident`.
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd  # type: ignore[import-untyped]

from aegis.correlate.schema import Alert

try:
    import networkx as nx  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    raise ImportError("networkx is required: pip install networkx") from None

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Disjoint Set (Union-Find) with path compression & union by rank
# ────────────────────────────────────────────────────────────────────

class DisjointSet:
    """A simple Union-Find / Disjoint Set data structure.

    Supports arbitrary hashable elements, path compression, and union
    by rank for near-O(α(n)) amortised operations.
    """

    def __init__(self) -> None:
        self._parent: dict[Any, Any] = {}
        self._rank: dict[Any, int] = {}

    def make_set(self, x: Any) -> None:
        """Create a singleton set containing *x* (idempotent)."""
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: Any) -> Any:
        """Return the representative (root) of the set containing *x*.

        Uses **path compression** to flatten the tree.
        """
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: Any, y: Any) -> None:
        """Merge the sets containing *x* and *y* (union by rank)."""
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        # Attach smaller tree under root of larger tree.
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def components(self) -> dict[Any, list[Any]]:
        """Return a mapping of root → list of members."""
        groups: dict[Any, list[Any]] = {}
        for item in self._parent:
            root = self.find(item)
            groups.setdefault(root, []).append(item)
        return groups


# ────────────────────────────────────────────────────────────────────
# Temporal clusterer
# ────────────────────────────────────────────────────────────────────

class TemporalClusterer:
    """Cluster linked alerts into incident-sized groups.

    Parameters
    ----------
    window_minutes:
        Two alerts are eligible for merging only if their timestamps
        are within this many minutes of each other.
    gap_timeout_minutes:
        After initial merging, clusters are split at any point where
        consecutive (sorted) alerts are more than this many minutes
        apart.
    """

    def __init__(
        self,
        window_minutes: int = 30,
        gap_timeout_minutes: int = 10,
    ) -> None:
        self.window_minutes = window_minutes
        self.gap_timeout_minutes = gap_timeout_minutes

    # ── Public API ─────────────────────────────────────────────────

    def cluster(
        self,
        linked_graph: nx.Graph,
        alerts: list[Alert],
    ) -> list[list[Alert]]:
        """Cluster alerts into incident groups with robust stress resilience.

        Handles:
        1. Duplicate telemetry de-duplication.
        2. Out-of-order arriving events (sorted chronologically).
        3. Excludes weak contextual edges from forced hard clustering.
        4. Inactivity gap splits (timeout).
        5. Host reboot boundaries (resets process/session continuity).

        Parameters
        ----------
        linked_graph:
            The enriched entity graph from :class:`AlertLinker`.
        alerts:
            The flat list of normalised alerts.

        Returns
        -------
        list[list[Alert]]
            Each inner list is a temporally-coherent group of alerts
            that will become one incident.  Groups are sorted by
            earliest alert timestamp (ascending).
        """
        if not alerts:
            return []

        # Deduplicate alerts based on alert_id or semantic fingerprint
        seen_keys: set[str] = set()
        deduped_alerts: list[Alert] = []
        for a in alerts:
            # Semantic fingerprint: host + rule + timestamp + process_guid
            fingerprint = f"{a.alert_id}|{a.hostname}|{a.rule_id}|{a.timestamp.isoformat()}|{a.process_guid}"
            if fingerprint not in seen_keys:
                seen_keys.add(fingerprint)
                deduped_alerts.append(a)

        # Ensure alerts are sorted chronologically regardless of ingest arrival order
        sorted_alerts = sorted(deduped_alerts, key=lambda a: a.timestamp)
        alert_by_id: dict[str, Alert] = {a.alert_id: a for a in sorted_alerts}

        # Collect which alerts touch each entity-graph edge, skipping weak contextual edges
        alert_pairs: set[tuple[str, str]] = set()

        for _u, _v, data in linked_graph.edges(data=True):
            if data.get("exclude_from_hard_clustering", False):
                continue
            aid_set: set[str] = data.get("alert_ids", set())
            aid_list = sorted(aid_set)
            for i, id1 in enumerate(aid_list):
                for id2 in aid_list[i + 1 :]:
                    if id1 in alert_by_id and id2 in alert_by_id:
                        alert_pairs.add((id1, id2))

        # Union-Find with temporal window constraint
        ds = DisjointSet()
        for alert in sorted_alerts:
            ds.make_set(alert.alert_id)

        window_s = self.window_minutes * 60

        for a1_id, a2_id in alert_pairs:
            alert_1 = alert_by_id[a1_id]
            alert_2 = alert_by_id[a2_id]
            td = abs((alert_1.timestamp - alert_2.timestamp).total_seconds())
            if td <= window_s:
                ds.union(a1_id, a2_id)

        # Extract components and split on gaps and reboot boundaries
        raw_groups = ds.components()
        final_groups: list[list[Alert]] = []

        gap_s = self.gap_timeout_minutes * 60

        for _root, member_ids in raw_groups.items():
            group_alerts = sorted(
                [alert_by_id[mid] for mid in member_ids if mid in alert_by_id],
                key=lambda a: a.timestamp,
            )
            if not group_alerts:
                continue

            # Split at gaps and reboot events
            current_subgroup: list[Alert] = [group_alerts[0]]
            for i in range(1, len(group_alerts)):
                prev_a = group_alerts[i - 1]
                curr_a = group_alerts[i]
                td = (curr_a.timestamp - prev_a.timestamp).total_seconds()

                # Check if current or previous event indicates a system reboot on the same host
                is_reboot = (
                    "reboot" in curr_a.rule_id.lower()
                    or "system_restart" in curr_a.rule_id.lower()
                    or curr_a.raw_event.get("winlog", {}).get("event_id") in (1074, 6005, 6006)
                )

                if td > gap_s or is_reboot:
                    if current_subgroup:
                        final_groups.append(current_subgroup)
                    current_subgroup = []
                current_subgroup.append(curr_a)
            if current_subgroup:
                final_groups.append(current_subgroup)

        # Sort groups by earliest timestamp.
        final_groups.sort(key=lambda g: g[0].timestamp)

        logger.info(
            "Temporal clustering produced %d incident groups from %d alerts "
            "(window=%d min, gap=%d min).",
            len(final_groups),
            len(alerts),
            self.window_minutes,
            self.gap_timeout_minutes,
        )
        return final_groups

    # ── Sensitivity analysis ───────────────────────────────────────

    def sweep_windows(
        self,
        linked_graph: nx.Graph,
        alerts: list[Alert],
        window_range: range | list[int] | None = None,
        gap_range: range | list[int] | None = None,
    ) -> pd.DataFrame:
        """Run the clusterer across a grid of (window, gap) parameters
        and return a DataFrame showing how incident count varies.

        This is a *developer / tuning* utility — not part of the
        production pipeline.

        Parameters
        ----------
        linked_graph:
            The enriched entity graph.
        alerts:
            The flat alert list.
        window_range:
            Iterable of ``window_minutes`` values to test.
            Defaults to ``range(10, 121, 10)``.
        gap_range:
            Iterable of ``gap_timeout_minutes`` values to test.
            Defaults to ``range(5, 61, 5)``.

        Returns
        -------
        pd.DataFrame
            Columns: ``window_minutes``, ``gap_timeout_minutes``,
            ``incident_count``, ``avg_alerts_per_incident``,
            ``max_alerts_per_incident``.
        """
        if window_range is None:
            window_range = range(10, 121, 10)
        if gap_range is None:
            gap_range = range(5, 61, 5)

        rows: list[dict[str, Any]] = []

        for w in window_range:
            for g in gap_range:
                clusterer = TemporalClusterer(
                    window_minutes=w, gap_timeout_minutes=g
                )
                groups = clusterer.cluster(linked_graph, alerts)
                n_incidents = len(groups)
                sizes = [len(grp) for grp in groups] if groups else [0]
                rows.append(
                    {
                        "window_minutes": w,
                        "gap_timeout_minutes": g,
                        "incident_count": n_incidents,
                        "avg_alerts_per_incident": (
                            sum(sizes) / len(sizes) if sizes else 0
                        ),
                        "max_alerts_per_incident": max(sizes) if sizes else 0,
                    }
                )

        return pd.DataFrame(rows)
