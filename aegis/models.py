"""
Core data models for the AEGIS platform.

Defines the domain objects used across all AEGIS subsystems:
correlation engine, graph visualization, evaluation, and playbooks.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Alert / incident severity levels aligned with Sigma rule severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EntityType(str, Enum):
    """Types of observable entities extracted from alerts."""
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    IP = "ip"
    SESSION = "session"


@dataclass
class Entity:
    """An observable entity (host, user, process, IP, session)."""
    id: str
    type: EntityType
    label: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """A single detection alert produced by a Sigma rule match."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_name: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: Severity = Severity.MEDIUM
    mitre_techniques: list[str] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    raw_event: dict[str, Any] = field(default_factory=dict)
    link_type: str = ""
    source_entity_id: str = ""
    target_entity_id: str = ""

    @property
    def technique_ids(self) -> list[str]:
        """Return only the T-code portion of MITRE references."""
        return [t for t in self.mitre_techniques if t.startswith("T")]


@dataclass
class Incident:
    """
    A correlated incident grouping multiple related alerts.

    Attributes:
        id: Unique incident identifier.
        alerts: Ordered list of correlated alerts.
        entities: De-duplicated entity map (entity_id → Entity).
        score: Composite risk score (0–100).
        severity: Highest severity among constituent alerts.
        blast_radius: Number of unique hosts/users impacted.
        mitre_techniques: Union of all ATT&CK technique IDs.
        created_at: Incident creation timestamp.
        updated_at: Timestamp of last alert addition.
        playbook_recommendations: Suggested response playbook names.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alerts: list[Alert] = field(default_factory=list)
    entities: dict[str, Entity] = field(default_factory=dict)
    score: float = 0.0
    severity: Severity = Severity.MEDIUM
    blast_radius: int = 0
    mitre_techniques: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    playbook_recommendations: list[str] = field(default_factory=list)

    @property
    def time_range(self) -> tuple[datetime, datetime]:
        """Return (earliest_alert_timestamp, latest_alert_timestamp)."""
        if not self.alerts:
            return (self.created_at, self.updated_at)
        timestamps = [a.timestamp for a in self.alerts]
        return (min(timestamps), max(timestamps))

    @property
    def duration_seconds(self) -> float:
        """Total incident duration in seconds."""
        start, end = self.time_range
        return (end - start).total_seconds()
