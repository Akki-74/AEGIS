"""
aegis.correlate.schema
======================

Normalized alert, entity, and incident data models for the AEGIS
correlation engine.

Design notes
------------
* **Alert** is an immutable-ish record of a *single* detection rule
  firing.  ``raw_event`` keeps the original log; ``extra`` allows
  pipeline-specific enrichment without schema changes.
* **Entity** is a typed identifier extracted *from* one or more alerts.
  It is hashable so it can serve as both a ``set`` element and a
  ``networkx`` graph node.
* **Incident** aggregates alerts that are linked by shared entities and
  temporal proximity.  It carries the composite score, blast-radius
  metrics, and (optionally) playbook recommendations.

JSON round-trip
---------------
Every data-class exposes ``to_dict()`` → ``dict`` and a classmethod
``from_dict(d)`` → instance.  ``datetime`` objects are serialised as
ISO-8601 strings; ``Enum`` members as their *value* (lower-case
string).
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


# ────────────────────────────────────────────────────────────────────
# Enumerations
# ────────────────────────────────────────────────────────────────────

class Severity(enum.Enum):
    """Alert / incident severity level (ascending order)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # Allow ordering so we can compute max-severity for an incident.
    def __lt__(self, other: Severity) -> bool:  # type: ignore[override]
        order = list(Severity)
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:  # type: ignore[override]
        return self == other or self < other


class EntityType(enum.Enum):
    """Categories of entities extracted from alerts."""

    HOST = "host"
    USER = "user"
    PROCESS = "process"
    LOGON_SESSION = "logon_session"
    IP = "ip"
    NETWORK_SESSION = "network_session"


class EvidenceType(enum.Enum):
    """Categorisation of correlation edge evidence distinguishing direct causation from association."""

    DIRECT_CAUSAL = "direct_causal"  # Deterministic lineage (e.g. parent_guid -> process_guid)
    SESSION_CONTINUITY = "session_continuity"  # Shared logon session ID on same host
    INFERRED_ASSOCIATION = "inferred_association"  # Temporal sequence (e.g. network connection -> logon)
    CONTEXTUAL_ASSOCIATION = "contextual_association"  # Shared user across hosts (weak signal)


@dataclass
class LinkEvidence:
    """Detailed causal or associative evidence justifying a correlation edge."""

    evidence_type: EvidenceType
    is_direct_causal: bool
    confidence: float
    source_alert_id: str
    target_alert_id: str
    reason: str
    timestamp_delta_seconds: float
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dictionary."""
        return {
            "evidence_type": self.evidence_type.value,
            "is_direct_causal": self.is_direct_causal,
            "confidence": self.confidence,
            "source_alert_id": self.source_alert_id,
            "target_alert_id": self.target_alert_id,
            "reason": self.reason,
            "timestamp_delta_seconds": self.timestamp_delta_seconds,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LinkEvidence:
        """Reconstruct a LinkEvidence instance from a dictionary."""
        return cls(
            evidence_type=EvidenceType(d.get("evidence_type", "inferred_association")),
            is_direct_causal=bool(d.get("is_direct_causal", False)),
            confidence=float(d.get("confidence", 0.5)),
            source_alert_id=str(d.get("source_alert_id", "")),
            target_alert_id=str(d.get("target_alert_id", "")),
            reason=str(d.get("reason", "")),
            timestamp_delta_seconds=float(d.get("timestamp_delta_seconds", 0.0)),
            attributes=dict(d.get("attributes", {})),
        )


# ────────────────────────────────────────────────────────────────────
# Alert
# ────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    """A single detection-rule firing, normalised to a common schema.

    Parameters
    ----------
    rule_id : str
        Unique identifier for the Sigma / detection rule that fired.
    rule_name : str
        Human-readable rule title.
    mitre_technique : str
        MITRE ATT&CK technique ID (e.g. ``"T1059.001"``).
    mitre_tactic : str
        MITRE ATT&CK tactic name (lower-case, e.g.
        ``"execution"``).
    timestamp : datetime
        Wall-clock time the event was observed (UTC recommended).
    hostname : str
        Hostname / FQDN where the event was recorded.
    username : str
        Account name associated with the event
        (``DOMAIN\\user`` or ``user@domain.com``).
    severity : Severity
        Rule-assigned severity.
    raw_event : dict[str, Any]
        Original log event preserved verbatim.

    Optional Fields
    ~~~~~~~~~~~~~~~
    process_guid, parent_process_guid, logon_id, source_ip, dest_ip,
    network_session_id — set to ``""`` when not applicable.
    extra — arbitrary enrichment bag.
    alert_id — auto-generated UUID4 if not supplied.
    """

    rule_id: str
    rule_name: str
    mitre_technique: str
    mitre_tactic: str
    timestamp: datetime
    hostname: str
    username: str
    severity: Severity
    raw_event: dict[str, Any] = field(default_factory=dict)

    # Optional linking fields (empty string = not present)
    process_guid: str = ""
    parent_process_guid: str = ""
    logon_id: str = ""
    source_ip: str = ""
    dest_ip: str = ""
    network_session_id: str = ""

    # Extension bag
    extra: dict[str, Any] = field(default_factory=dict)

    # Auto-generated unique alert identifier
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # ── Serialisation ──────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise the alert to a JSON-safe dictionary.

        * ``datetime`` → ISO-8601 string
        * ``Severity`` → its lower-case string value
        """
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Alert:
        """Reconstruct an ``Alert`` from a dictionary (e.g. parsed JSON).

        Handles both fully normalised alerts and raw / Sysmon event formats.
        """
        data = dict(d)

        # ── Field alias resolution ──
        raw_ts = data.get("timestamp") or data.get("TimeCreated") or data.get("@timestamp")
        if raw_ts is None:
            raw_ts = datetime.now(timezone.utc)
        elif isinstance(raw_ts, str):
            # Clean trailing Z or nanoseconds for Python datetime
            clean_ts = raw_ts.replace("Z", "+00:00")
            # If sub-second precision is > 6 digits (e.g. 7 digits from Windows .0000000), truncate to 6
            if "." in clean_ts and "+" in clean_ts:
                dot_idx = clean_ts.index(".")
                plus_idx = clean_ts.index("+")
                frac = clean_ts[dot_idx + 1:plus_idx]
                if len(frac) > 6:
                    clean_ts = clean_ts[:dot_idx + 7] + clean_ts[plus_idx:]
            try:
                raw_ts = datetime.fromisoformat(clean_ts)
            except Exception:
                raw_ts = datetime.now(timezone.utc)

        hostname = (
            data.get("hostname")
            or data.get("Computer")
            or (data["host"]["name"] if isinstance(data.get("host"), dict) else data.get("host", ""))
            or ""
        )
        username = (
            data.get("username")
            or data.get("User")
            or data.get("TargetUserName")
            or (data["user"]["name"] if isinstance(data.get("user"), dict) else data.get("user", ""))
            or ""
        )
        process_guid = (
            data.get("process_guid")
            or data.get("ProcessGUID")
            or data.get("ProcessGuid")
            or ""
        )
        parent_process_guid = (
            data.get("parent_process_guid")
            or data.get("ParentProcessGUID")
            or data.get("ParentProcessGuid")
            or ""
        )
        logon_id = str(data.get("logon_id") or data.get("LogonId") or "")
        source_ip = str(data.get("source_ip") or data.get("SourceIp") or data.get("IpAddress") or "")
        dest_ip = str(data.get("dest_ip") or data.get("DestinationIp") or "")

        rule_id = str(data.get("rule_id") or data.get("RuleId") or str(uuid.uuid4()))
        rule_name = str(data.get("rule_name") or data.get("RuleName") or "Security Alert")

        # ── MITRE technique / tactic resolution ──
        mitre_tech = data.get("mitre_technique", "")
        mitre_tactic = data.get("mitre_tactic", "")

        if not mitre_tech and "technique_id=" in rule_name:
            # Parse from format: technique_id=T1218.005,technique_name=Mshta
            parts = rule_name.split(",")
            for p in parts:
                if p.startswith("technique_id="):
                    mitre_tech = p.split("technique_id=")[1].strip()
                elif p.startswith("technique_name="):
                    mitre_tactic = p.split("technique_name=")[1].strip().lower()

        # ── Canonical tactic mapping based on technique ID ──
        _TECH_TACTIC_MAP: dict[str, tuple[str, Severity]] = {
            "T1003.001": ("credential_access", Severity.CRITICAL),
            "T1003": ("credential_access", Severity.CRITICAL),
            "T1558.003": ("credential_access", Severity.HIGH),
            "T1558.004": ("credential_access", Severity.HIGH),
            "T1649": ("credential_access", Severity.CRITICAL),
            "T1055.003": ("defense_evasion", Severity.HIGH),
            "T1055.012": ("defense_evasion", Severity.CRITICAL),
            "T1055": ("defense_evasion", Severity.HIGH),
            "T1134.004": ("defense_evasion", Severity.HIGH),
            "T1134": ("defense_evasion", Severity.HIGH),
            "T1218.005": ("defense_evasion", Severity.HIGH),
            "T1218.011": ("defense_evasion", Severity.MEDIUM),
            "T1218": ("defense_evasion", Severity.MEDIUM),
            "T1105": ("command_and_control", Severity.HIGH),
            "T1059.001": ("execution", Severity.HIGH),
            "T1059": ("execution", Severity.MEDIUM),
            "T1204.002": ("execution", Severity.MEDIUM),
            "T1204": ("execution", Severity.MEDIUM),
            "T1021.002": ("lateral_movement", Severity.HIGH),
            "T1021.006": ("lateral_movement", Severity.HIGH),
            "T1021": ("lateral_movement", Severity.HIGH),
        }

        raw_sev: Any = "medium"
        if mitre_tech in _TECH_TACTIC_MAP:
            inferred_tactic, inferred_sev = _TECH_TACTIC_MAP[mitre_tech]
            mitre_tactic = inferred_tactic
            raw_sev = inferred_sev

        if "severity" in data:
            raw_sev = data["severity"]
        elif "Severity" in data:
            raw_sev = data["Severity"]

        if isinstance(raw_sev, Severity):
            severity = raw_sev
        else:
            try:
                severity = Severity(str(raw_sev).lower())
            except ValueError:
                severity = Severity.MEDIUM

        alert_id = str(data.get("alert_id") or data.get("id") or str(uuid.uuid4()))

        return cls(
            rule_id=rule_id,
            rule_name=rule_name,
            mitre_technique=mitre_tech,
            mitre_tactic=mitre_tactic,
            timestamp=raw_ts,
            hostname=hostname,
            username=username,
            severity=severity,
            raw_event=data.get("raw_event", data),
            process_guid=process_guid,
            parent_process_guid=parent_process_guid,
            logon_id=logon_id,
            source_ip=source_ip,
            dest_ip=dest_ip,
            alert_id=alert_id,
        )


# ────────────────────────────────────────────────────────────────────
# Entity
# ────────────────────────────────────────────────────────────────────

@dataclass
class Entity:
    """A resolved entity (host, user, process …) that can appear in a
    graph as a node.

    Identity is defined by ``(entity_type, entity_id)`` so that two
    ``Entity`` objects referring to the same real-world object compare
    equal and hash the same way, regardless of differing *attributes*.

    Parameters
    ----------
    entity_type : EntityType
        Category of the entity.
    entity_id : str
        Canonical, de-duplicated identifier.  How this is built depends
        on the entity type — see :mod:`entity_resolution` for the
        normalisation rules.
    attributes : dict[str, Any]
        Optional descriptive metadata (e.g. domain, SID, IP version).
    """

    entity_type: EntityType
    entity_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    # ── Identity / hashing ─────────────────────────────────────────

    def __hash__(self) -> int:
        return hash((self.entity_type, self.entity_id))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Entity):
            return NotImplemented
        return (
            self.entity_type == other.entity_type
            and self.entity_id == other.entity_id
        )

    def __repr__(self) -> str:
        return (
            f"Entity(type={self.entity_type.value!r}, "
            f"id={self.entity_id!r})"
        )

    # ── Serialisation ──────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-safe dictionary."""
        return {
            "entity_type": self.entity_type.value,
            "entity_id": self.entity_id,
            "attributes": dict(self.attributes),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Entity:
        """Reconstruct an ``Entity`` from a dictionary."""
        return cls(
            entity_type=EntityType(d["entity_type"]),
            entity_id=d["entity_id"],
            attributes=d.get("attributes", {}),
        )


# ────────────────────────────────────────────────────────────────────
# Incident
# ────────────────────────────────────────────────────────────────────

@dataclass
class Incident:
    """A correlated group of alerts linked by shared entities and
    temporal proximity.

    Parameters
    ----------
    alerts : list[Alert]
        The constituent alerts (ordered by timestamp ascending).
    entities : set[Entity]
        All resolved entities touched by the alerts.
    techniques : set[str]
        Distinct MITRE ATT&CK technique IDs.
    tactics : set[str]
        Distinct MITRE ATT&CK tactic names.
    hosts : set[str]
        Hostnames involved.
    users : set[str]
        User accounts involved.
    score : float
        Composite severity score in ``[0.0, 1.0]``.
    severity : str
        Classified severity label (critical / high / medium / low / info).
    start_time : datetime
        Earliest alert timestamp.
    end_time : datetime
        Latest alert timestamp.
    blast_radius : dict[str, Any]
        Output of :meth:`IncidentScorer.compute_blast_radius`.
    playbook_recommendations : list[str]
        Suggested response playbooks based on detected tactics.
    incident_id : str
        Auto-generated UUID4 unless explicitly supplied.
    """

    alerts: list[Alert] = field(default_factory=list)
    entities: set[Entity] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    tactics: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    score: float = 0.0
    severity: str = "info"
    start_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    end_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    blast_radius: dict[str, Any] = field(default_factory=dict)
    playbook_recommendations: list[str] = field(default_factory=list)
    incident_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # ── Serialisation ──────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise the incident to a JSON-safe dictionary.

        Sets are converted to sorted lists for deterministic output.
        """
        return {
            "incident_id": self.incident_id,
            "score": round(self.score, 4),
            "severity": self.severity,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "techniques": sorted(self.techniques),
            "tactics": sorted(self.tactics),
            "hosts": sorted(self.hosts),
            "users": sorted(self.users),
            "alert_count": len(self.alerts),
            "alerts": [a.to_dict() for a in self.alerts],
            "entities": [e.to_dict() for e in self.entities],
            "blast_radius": self.blast_radius,
            "playbook_recommendations": self.playbook_recommendations,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Incident:
        """Reconstruct an ``Incident`` from a dictionary (e.g. parsed
        JSON)."""
        return cls(
            incident_id=d.get("incident_id", str(uuid.uuid4())),
            alerts=[Alert.from_dict(a) for a in d.get("alerts", [])],
            entities={Entity.from_dict(e) for e in d.get("entities", [])},
            techniques=set(d.get("techniques", [])),
            tactics=set(d.get("tactics", [])),
            hosts=set(d.get("hosts", [])),
            users=set(d.get("users", [])),
            score=float(d.get("score", 0.0)),
            severity=d.get("severity", "info"),
            start_time=datetime.fromisoformat(d["start_time"])
            if isinstance(d.get("start_time"), str)
            else d.get("start_time", datetime.now(timezone.utc)),
            end_time=datetime.fromisoformat(d["end_time"])
            if isinstance(d.get("end_time"), str)
            else d.get("end_time", datetime.now(timezone.utc)),
            blast_radius=d.get("blast_radius", {}),
            playbook_recommendations=d.get("playbook_recommendations", []),
        )
