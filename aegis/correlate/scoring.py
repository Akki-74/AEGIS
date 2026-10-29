"""
aegis.correlate.scoring
=======================

Multi-dimensional incident scoring and severity classification.

Score dimensions (configurable weights)
---------------------------------------
1. **Kill-chain coverage** (default 0.30)
   Fraction of the MITRE ATT&CK kill-chain stages represented by the
   incident's tactics.

2. **Technique diversity** (default 0.25)
   Number of distinct techniques / ``max_expected_techniques``.

3. **Privilege escalation** (default 0.25)
   Binary + severity: does any alert involve a privilege-escalation
   technique?  Was a high-privilege account used?

4. **Asset criticality** (default 0.20)
   Maximum criticality tag across all hosts in the incident, looked up
   from a caller-supplied ``asset_tags`` dictionary.

All individual dimension scores are clamped to ``[0.0, 1.0]``.  The
composite score is the weighted sum, also clamped.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.correlate.schema import Entity, EntityType, Incident, Severity

logger = logging.getLogger(__name__)

# ── Canonical MITRE ATT&CK kill-chain stages (ordered) ────────────
KILL_CHAIN_TACTICS: list[str] = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# Technique IDs considered privilege-escalation or credential dumping related.
_PRIV_ESC_TECHNIQUE_PREFIXES: tuple[str, ...] = (
    "T1003",  # OS Credential Dumping (LSASS)
    "T1134",  # Access Token Manipulation
    "T1548",  # Abuse Elevation Control Mechanism
    "T1068",  # Exploitation for Privilege Escalation
    "T1574",  # Hijack Execution Flow
    "T1055",  # Process Injection
    "T1053",  # Scheduled Task/Job
    "T1078",  # Valid Accounts (when context = priv esc)
)

# Usernames / patterns that indicate high-privilege accounts.
_HIGH_PRIV_PATTERNS: tuple[str, ...] = (
    "administrator",
    "admin",
    "system",
    "root",
    "domain admin",
    "enterprise admin",
    "da_",
    "svc_",
)


class IncidentScorer:
    """Score and classify incidents.

    Parameters
    ----------
    weight_kill_chain:
        Weight for the kill-chain coverage dimension.
    weight_technique_diversity:
        Weight for the technique diversity dimension.
    weight_priv_esc:
        Weight for the privilege-escalation dimension.
    weight_asset_criticality:
        Weight for the asset-criticality dimension.
    max_expected_techniques:
        Denominator for normalising technique-diversity count.
    severity_thresholds:
        Mapping of severity labels to their *lower-bound* score.
        Defaults to ``critical≥0.80, high≥0.60, medium≥0.40,
        low≥0.20``.
    asset_criticality_map:
        Default tag → score mapping when callers don't supply one.
    """

    def __init__(
        self,
        *,
        weight_kill_chain: float = 0.30,
        weight_technique_diversity: float = 0.25,
        weight_priv_esc: float = 0.25,
        weight_asset_criticality: float = 0.20,
        max_expected_techniques: int = 10,
        severity_thresholds: dict[str, float] | None = None,
        asset_criticality_map: dict[str, float] | None = None,
    ) -> None:
        self.w_kc = weight_kill_chain
        self.w_td = weight_technique_diversity
        self.w_pe = weight_priv_esc
        self.w_ac = weight_asset_criticality
        self.max_techniques = max_expected_techniques

        self.severity_thresholds: dict[str, float] = severity_thresholds or {
            "critical": 0.70,
            "high": 0.50,
            "medium": 0.30,
            "low": 0.15,
        }

        self.asset_criticality_map: dict[str, float] = (
            asset_criticality_map
            or {
                "domain_controller": 1.0,
                "dc": 1.0,
                "admin_workstation": 0.8,
                "server": 0.6,
                "workstation": 0.3,
            }
        )

    # ── Public API ─────────────────────────────────────────────────

    def score(
        self,
        incident: Incident,
        asset_tags: dict[str, list[str]] | None = None,
    ) -> float:
        """Compute a composite score for *incident*.

        Parameters
        ----------
        incident:
            The incident to score (must already have ``tactics``,
            ``techniques``, ``hosts``, ``users``, ``alerts`` populated).
        asset_tags:
            Optional mapping of ``hostname → list[tag]``.  Tags are
            looked up in ``asset_criticality_map`` to derive the
            asset-criticality sub-score.

        Returns
        -------
        float
            Composite score in ``[0.0, 1.0]``.
        """
        if asset_tags is None:
            asset_tags = {}

        s_kc = self._score_kill_chain(incident)
        s_td = self._score_technique_diversity(incident)
        s_pe = self._score_priv_esc(incident)
        s_ac = self._score_asset_criticality(incident, asset_tags)

        composite = (
            self.w_kc * s_kc
            + self.w_td * s_td
            + self.w_pe * s_pe
            + self.w_ac * s_ac
        )
        composite = max(0.0, min(1.0, composite))

        logger.debug(
            "Incident %s scored %.4f "
            "(kc=%.2f td=%.2f pe=%.2f ac=%.2f)",
            incident.incident_id[:8],
            composite,
            s_kc,
            s_td,
            s_pe,
            s_ac,
        )
        return composite

    def classify_severity(self, score: float) -> str:
        """Map a numeric score to a severity label.

        Parameters
        ----------
        score:
            Composite score in ``[0.0, 1.0]``.

        Returns
        -------
        str
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``,
            ``"info"``.
        """
        # Walk thresholds from highest to lowest.
        for label in ("critical", "high", "medium", "low"):
            if score >= self.severity_thresholds.get(label, 0.0):
                return label
        return "info"

    def compute_blast_radius(self, incident: Incident) -> dict[str, Any]:
        """Estimate the *blast radius* of an incident.

        Returns
        -------
        dict
            ``hosts_touched``  – number of distinct hosts.
            ``accounts_used``  – number of distinct user accounts.
            ``privilege_level_reached`` – ``"high"`` if any high-priv
            account is involved, else ``"standard"``.
            ``lateral_movement_hops`` – count of distinct host pairs
            (lower bound on hop count).
        """
        hosts_touched = len(incident.hosts)
        accounts_used = len(incident.users)

        # Privilege level
        priv_level = "standard"
        for user in incident.users:
            if any(pat in user.lower() for pat in _HIGH_PRIV_PATTERNS):
                priv_level = "high"
                break

        # Lateral-movement hops: count distinct ordered host pairs
        # where we see outbound-network + logon.
        host_list = sorted(incident.hosts)
        lateral_hops = max(0, len(host_list) - 1)

        return {
            "hosts_touched": hosts_touched,
            "accounts_used": accounts_used,
            "privilege_level_reached": priv_level,
            "lateral_movement_hops": lateral_hops,
        }

    # ── Dimension scorers ──────────────────────────────────────────

    @staticmethod
    def _score_kill_chain(incident: Incident) -> float:
        """Fraction of the canonical kill-chain covered by the
        incident's tactics.

        A higher coverage means the attacker has progressed further
        through the kill-chain → higher risk.
        """
        covered = sum(
            1
            for t in KILL_CHAIN_TACTICS
            if t in incident.tactics
        )
        return min(1.0, covered / len(KILL_CHAIN_TACTICS))

    def _score_technique_diversity(self, incident: Incident) -> float:
        """Number of distinct techniques normalised by
        ``max_expected_techniques``."""
        return min(1.0, len(incident.techniques) / self.max_techniques)

    @staticmethod
    def _score_priv_esc(incident: Incident) -> float:
        """Score the privilege-escalation dimension.

        Components:
        * 0.5 if any technique is a known priv-esc technique.
        * 0.3 if a high-severity alert is present.
        * 0.2 if a high-privilege account is involved.

        The sub-scores are summed and clamped to [0, 1].
        """
        score = 0.0

        # Check for priv-esc techniques.
        for tech in incident.techniques:
            if tech.startswith(_PRIV_ESC_TECHNIQUE_PREFIXES):
                score += 0.5
                break

        # Check for priv-esc tactic in the incident.
        if "privilege_escalation" in incident.tactics:
            score += 0.5

        # High-severity alert present?
        max_sev = max(
            (a.severity for a in incident.alerts),
            default=Severity.INFO,
        )
        if max_sev >= Severity.HIGH:
            score = max(score, 0.3)  # floor — don't reduce
            score += 0.3

        # High-privilege account?
        for user in incident.users:
            if any(pat in user.lower() for pat in _HIGH_PRIV_PATTERNS):
                score += 0.2
                break

        return min(1.0, score)

    def _score_asset_criticality(
        self,
        incident: Incident,
        asset_tags: dict[str, list[str]],
    ) -> float:
        """Maximum asset-criticality score across all incident hosts.

        For each host, we look up its tags and take the highest
        criticality value from ``asset_criticality_map``. If no explicit
        tags are provided, infer from hostname conventions.
        """
        max_crit = 0.0

        for host in incident.hosts:
            host_lower = host.lower()
            tags = asset_tags.get(host, [])
            if tags:
                for tag in tags:
                    crit = self.asset_criticality_map.get(tag.lower(), 0.0)
                    if crit > max_crit:
                        max_crit = crit
            else:
                # Infer default asset criticality based on standard naming
                if "dc" in host_lower or "domain" in host_lower:
                    crit = 1.0
                elif "srv" in host_lower or "server" in host_lower or "fs" in host_lower:
                    crit = 0.6
                elif "admin" in host_lower:
                    crit = 0.8
                else:
                    crit = 0.4  # Baseline workstation
                if crit > max_crit:
                    max_crit = crit

        return min(1.0, max_crit)
