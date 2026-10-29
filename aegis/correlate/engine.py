"""
aegis.correlate.engine
======================

Orchestration pipeline for the AEGIS correlation engine.

Coordinates:
1. Entity resolution (:class:`~aegis.correlate.entity_resolution.EntityResolver`)
2. Alert linking via semantic relations (:class:`~aegis.correlate.linker.AlertLinker`)
3. Temporal sliding-window clustering (:class:`~aegis.correlate.windowing.TemporalClusterer`)
4. Multi-factor scoring and blast-radius assessment (:class:`~aegis.correlate.scoring.IncidentScorer`)
5. Playbook recommendation mapping
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis.config import AegisConfig
from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.linker import AlertLinker
from aegis.correlate.schema import Alert, Entity, Incident
from aegis.correlate.scoring import IncidentScorer
from aegis.correlate.windowing import TemporalClusterer

logger = logging.getLogger(__name__)


# Default playbook recommendation heuristics based on observed tactics / techniques
_TACTIC_PLAYBOOK_MAP: dict[str, str] = {
    "credential_access": "playbooks/credential_theft.yml",
    "lateral_movement": "playbooks/lateral_movement.yml",
    "execution": "playbooks/malware_execution.yml",
    "defense_evasion": "playbooks/malware_execution.yml",
}

_TECHNIQUE_PLAYBOOK_MAP: dict[str, str] = {
    "T1003.001": "playbooks/credential_theft.yml",  # LSASS dump
    "T1558.003": "playbooks/credential_theft.yml",  # Kerberoasting
    "T1558.004": "playbooks/credential_theft.yml",  # AS-REP Roasting
    "T1649": "playbooks/ad_compromise.yml",          # AD CS abuse
    "T1021": "playbooks/lateral_movement.yml",      # Remote Services
    "T1055": "playbooks/malware_execution.yml",      # Process Injection
    "T1059.001": "playbooks/malware_execution.yml",  # PowerShell ScriptBlock
}


class CorrelationEngine:
    """End-to-end incident correlation orchestrator.

    Parameters
    ----------
    config:
        Top-level AEGIS configuration.  Defaults to :class:`AegisConfig()` if omitted.
    """

    def __init__(self, config: AegisConfig | None = None) -> None:
        self.config = config or AegisConfig()
        
        self.resolver = EntityResolver()
        self.linker = AlertLinker()
        self.clusterer = TemporalClusterer(
            window_minutes=self.config.correlation.window_minutes,
            gap_timeout_minutes=self.config.correlation.gap_timeout_minutes,
        )
        self.scorer = IncidentScorer(
            weight_kill_chain=self.config.scoring.kill_chain_weight,
            weight_technique_diversity=self.config.scoring.technique_diversity_weight,
            weight_priv_esc=self.config.scoring.privilege_escalation_weight,
            weight_asset_criticality=self.config.scoring.asset_criticality_weight,
        )

    def process(
        self,
        alerts: list[Alert],
        asset_tags: dict[str, list[str]] | None = None,
        filter_min_techniques: bool = False,
    ) -> list[Incident]:
        """Correlate a list of normalised alerts into ranked incidents.

        Parameters
        ----------
        alerts:
            Flat list of :class:`Alert` instances.
        asset_tags:
            Optional mapping of ``hostname -> list[tag]`` for criticality weighting.
        filter_min_techniques:
            If ``True``, drops clusters with fewer distinct ATT&CK techniques
            than ``config.correlation.min_techniques``.

        Returns
        -------
        list[Incident]
            Correlated incidents sorted descending by composite score.
        """
        if not alerts:
            logger.info("No alerts provided to correlation engine.")
            return []

        logger.info("Processing %d raw alerts through correlation pipeline...", len(alerts))

        # 1. Entity resolution & graph construction
        entity_map = self.resolver.resolve(alerts)
        entity_graph = self.resolver.build_entity_graph(alerts)
        logger.debug("Resolved %d distinct entities.", len(entity_map))

        # 2. Semantic linking
        linked_graph = self.linker.link(entity_graph, alerts)

        # 3. Temporal windowing and clustering
        raw_clusters = self.clusterer.cluster(linked_graph, alerts)
        logger.info("Clustered %d alerts into %d candidate incident groups.", len(alerts), len(raw_clusters))

        # 4. Construct Incident objects
        incidents: list[Incident] = []
        for cluster_alerts in raw_clusters:
            if not cluster_alerts:
                continue

            # Sort alerts chronologically
            sorted_alerts = sorted(cluster_alerts, key=lambda a: a.timestamp)
            
            # Aggregate metadata
            techniques = {a.mitre_technique for a in sorted_alerts if a.mitre_technique}
            tactics = {a.mitre_tactic for a in sorted_alerts if a.mitre_tactic}
            hosts = {a.hostname for a in sorted_alerts if a.hostname}
            users = {a.username for a in sorted_alerts if a.username}

            if filter_min_techniques and len(techniques) < self.config.correlation.min_techniques:
                logger.debug(
                    "Filtering out cluster with %d techniques (< min %d)",
                    len(techniques),
                    self.config.correlation.min_techniques,
                )
                continue

            # Identify entities touched by this cluster's alerts
            cluster_alert_ids = {a.alert_id for a in sorted_alerts}
            cluster_entities: set[Entity] = set()
            for entity, associated_alerts in entity_map.items():
                if any(a.alert_id in cluster_alert_ids for a in associated_alerts):
                    cluster_entities.add(entity)

            # Recommend playbooks
            playbook_recs: set[str] = set()
            for tech in techniques:
                if tech in _TECHNIQUE_PLAYBOOK_MAP:
                    playbook_recs.add(_TECHNIQUE_PLAYBOOK_MAP[tech])
            for tactic in tactics:
                if tactic in _TACTIC_PLAYBOOK_MAP:
                    playbook_recs.add(_TACTIC_PLAYBOOK_MAP[tactic])

            incident = Incident(
                alerts=sorted_alerts,
                entities=cluster_entities,
                techniques=techniques,
                tactics=tactics,
                hosts=hosts,
                users=users,
                start_time=sorted_alerts[0].timestamp,
                end_time=sorted_alerts[-1].timestamp,
                playbook_recommendations=sorted(playbook_recs),
            )

            # Score incident and assess blast radius
            incident.score = self.scorer.score(incident, asset_tags)
            incident.severity = self.scorer.classify_severity(incident.score)
            incident.blast_radius = self.scorer.compute_blast_radius(incident)

            incidents.append(incident)

        # Sort incidents by score descending
        incidents.sort(key=lambda inc: inc.score, reverse=True)
        logger.info("Successfully produced %d correlated incidents.", len(incidents))
        return incidents

    def process_from_file(
        self,
        path: Path | str,
        asset_tags: dict[str, list[str]] | None = None,
        filter_min_techniques: bool = False,
    ) -> list[Incident]:
        """Load alerts from a JSON file and run correlation.

        The JSON file may be either:
        - A JSON array of alert dicts: ``[{...}, {...}]``
        - An object containing an ``"alerts"`` list: ``{"alerts": [...]}``
        """
        file_path = Path(path)
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        raw_alerts = data.get("alerts", data) if isinstance(data, dict) else data
        if not isinstance(raw_alerts, list):
            raise ValueError(f"Expected JSON array or dict with 'alerts' key in {file_path}")

        alerts = [Alert.from_dict(item) for item in raw_alerts]
        return self.process(alerts, asset_tags=asset_tags, filter_min_techniques=filter_min_techniques)

    def export_incidents(
        self,
        incidents: list[Incident],
        output_dir: Path | str,
        prefix: str = "incident",
    ) -> list[Path]:
        """Export correlated incidents as individual JSON files and a combined summary.

        Parameters
        ----------
        incidents:
            List of incidents to export.
        output_dir:
            Target directory.
        prefix:
            File prefix for individual incident files.

        Returns
        -------
        list[Path]
            Paths to the written JSON files.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        written_paths: list[Path] = []

        summary_data = []
        for idx, inc in enumerate(incidents, start=1):
            file_name = f"{prefix}_{idx}_{inc.incident_id[:8]}.json"
            file_path = out / file_name
            with file_path.open("w", encoding="utf-8") as f:
                json.dump(inc.to_dict(), f, indent=2, default=str)
            written_paths.append(file_path)

            summary_data.append({
                "incident_id": inc.incident_id,
                "score": round(inc.score, 4),
                "severity": inc.severity,
                "alert_count": len(inc.alerts),
                "tactics": sorted(inc.tactics),
                "techniques": sorted(inc.techniques),
                "hosts": sorted(inc.hosts),
                "users": sorted(inc.users),
                "start_time": inc.start_time.isoformat(),
                "end_time": inc.end_time.isoformat(),
                "file": str(file_name),
            })

        summary_path = out / "incidents_summary.json"
        with summary_path.open("w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)
        written_paths.append(summary_path)

        logger.info("Exported %d incidents to %s", len(incidents), out)
        return written_paths
