"""AEGIS configuration management.

Provides dataclass-based configuration for the AEGIS platform, including
Elasticsearch/OpenSearch connection parameters, correlation engine settings,
and incident scoring weights.  Configuration is loaded from a YAML file with
sensible defaults applied for any missing keys.

Usage::

    from aegis.config import AegisConfig

    # Load from a YAML file (falls back to defaults for missing keys)
    cfg = AegisConfig.from_yaml("config.yaml")

    # Or use pure defaults
    cfg = AegisConfig()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# =============================================================================
# Elasticsearch / OpenSearch connection config
# =============================================================================
@dataclass(frozen=True)
class ElasticsearchConfig:
    """Connection parameters for the Elasticsearch / OpenSearch cluster.

    Attributes:
        host: Hostname or IP address of the cluster.
        port: REST API port (default 9200).
        index_pattern: Wildcard index pattern for security alert indices.
        api_key: Base64-encoded ``id:api_key`` for API-key authentication.
            Leave empty to fall back to basic auth or anonymous access.
    """

    host: str = "localhost"
    port: int = 9200
    index_pattern: str = "winlogbeat-*"
    api_key: str = ""


# =============================================================================
# Correlation engine config
# =============================================================================
@dataclass(frozen=True)
class CorrelationConfig:
    """Parameters governing the sliding-window correlation engine.

    Attributes:
        window_minutes: Maximum time span (minutes) within which alerts are
            grouped into a single incident.
        gap_timeout_minutes: If no new alert arrives within this many minutes
            the current correlation session for that entity is closed.
        min_techniques: Minimum distinct ATT&CK techniques required to
            promote an alert cluster to a correlated incident.
    """

    window_minutes: int = 30
    gap_timeout_minutes: int = 10
    min_techniques: int = 2


# =============================================================================
# Incident scoring weights
# =============================================================================
@dataclass(frozen=True)
class ScoringConfig:
    """Weights for the multi-factor incident severity scoring model.

    All weights **must** sum to ``1.0``.  Each weight controls how heavily
    the corresponding factor contributes to the final score.

    Attributes:
        kill_chain_weight: Weight for kill-chain phase progression.
        technique_diversity_weight: Weight for unique technique count.
        privilege_escalation_weight: Weight for privilege-escalation indicators.
        asset_criticality_weight: Weight for the criticality of the affected asset.
    """

    kill_chain_weight: float = 0.30
    technique_diversity_weight: float = 0.25
    privilege_escalation_weight: float = 0.25
    asset_criticality_weight: float = 0.20

    def __post_init__(self) -> None:
        """Validate that scoring weights sum to 1.0 (±0.001 tolerance)."""
        total = (
            self.kill_chain_weight
            + self.technique_diversity_weight
            + self.privilege_escalation_weight
            + self.asset_criticality_weight
        )
        if abs(total - 1.0) > 0.001:
            msg = (
                f"Scoring weights must sum to 1.0, got {total:.4f}. "
                f"Current weights: kill_chain={self.kill_chain_weight}, "
                f"technique_diversity={self.technique_diversity_weight}, "
                f"privilege_escalation={self.privilege_escalation_weight}, "
                f"asset_criticality={self.asset_criticality_weight}"
            )
            raise ValueError(msg)


# =============================================================================
# Top-level AEGIS config
# =============================================================================
@dataclass(frozen=True)
class AegisConfig:
    """Root configuration container for the AEGIS platform.

    Composes all sub-configs and provides a factory method to load from YAML.

    Attributes:
        elasticsearch: ES/OS connection parameters.
        correlation: Correlation engine parameters.
        scoring: Incident scoring weights.
    """

    elasticsearch: ElasticsearchConfig = field(default_factory=ElasticsearchConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)

    # --------------------------------------------------------------------- #
    # Factory — load from YAML
    # --------------------------------------------------------------------- #
    @classmethod
    def from_yaml(cls, path: str | Path) -> AegisConfig:
        """Load configuration from a YAML file.

        Missing top-level sections or individual keys fall back to the
        dataclass defaults defined above, so a minimal YAML file (or even an
        empty one) is perfectly valid.

        Args:
            path: Filesystem path to the YAML configuration file.

        Returns:
            A fully populated ``AegisConfig`` instance.

        Raises:
            FileNotFoundError: If *path* does not exist.
            yaml.YAMLError: If the file contains invalid YAML.
        """
        config_path = Path(path)
        if not config_path.exists():
            msg = f"Configuration file not found: {config_path}"
            raise FileNotFoundError(msg)

        logger.info("Loading configuration from %s", config_path)

        with config_path.open("r", encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        return cls._from_dict(raw)

    # --------------------------------------------------------------------- #
    # Factory — load from dict (useful for tests & programmatic use)
    # --------------------------------------------------------------------- #
    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> AegisConfig:
        """Build an ``AegisConfig`` from a plain dictionary.

        Args:
            data: Dictionary with optional ``elasticsearch``, ``correlation``,
                and ``scoring`` sub-dicts.

        Returns:
            A fully populated ``AegisConfig`` instance.
        """
        es_data: dict[str, Any] = data.get("elasticsearch", {})
        corr_data: dict[str, Any] = data.get("correlation", {})
        score_data: dict[str, Any] = data.get("scoring", {})

        return cls(
            elasticsearch=ElasticsearchConfig(**es_data),
            correlation=CorrelationConfig(**corr_data),
            scoring=ScoringConfig(**score_data),
        )
