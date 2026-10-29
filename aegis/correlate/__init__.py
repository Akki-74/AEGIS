"""
aegis.correlate – Alert correlation engine.

Public API
----------
- :class:`~aegis.correlate.schema.Alert`
- :class:`~aegis.correlate.schema.Entity`
- :class:`~aegis.correlate.schema.Incident`
- :class:`~aegis.correlate.entity_resolution.EntityResolver`
- :class:`~aegis.correlate.linker.AlertLinker`
- :class:`~aegis.correlate.windowing.TemporalClusterer`
- :class:`~aegis.correlate.scoring.IncidentScorer`
- :class:`~aegis.correlate.engine.CorrelationEngine`
"""

from aegis.correlate.schema import (
    Alert,
    Entity,
    EntityType,
    Incident,
    Severity,
)
from aegis.correlate.entity_resolution import EntityResolver
from aegis.correlate.linker import AlertLinker
from aegis.correlate.windowing import TemporalClusterer
from aegis.correlate.scoring import IncidentScorer
from aegis.correlate.engine import CorrelationEngine

__all__ = [
    "Alert",
    "Entity",
    "EntityType",
    "Incident",
    "Severity",
    "EntityResolver",
    "AlertLinker",
    "TemporalClusterer",
    "IncidentScorer",
    "CorrelationEngine",
]
