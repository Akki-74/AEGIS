"""
aegis.eval.noise
================

Noise reduction and clustering purity evaluation metrics.

Metrics implemented:
1. **Noise Reduction Ratio**:
   ``Noise Reduction = 1 - (Incidents / Raw Alerts)``
2. **Window Sensitivity Sweep**:
   Evaluates incident count and alert distribution across varying
   temporal window sizes (e.g. 10m, 20m, 30m, 60m) and gap timeouts.
3. **Clustering Purity**:
   Measures whether malicious alerts are partitioned cleanly without
   swallowing unrelated benign activities (over-merging risk).
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from aegis.correlate.engine import CorrelationEngine
from aegis.correlate.schema import Alert, Incident

logger = logging.getLogger(__name__)


class NoiseAnalyzer:
    """Evaluate noise reduction and sensitivity for the correlation engine."""

    @staticmethod
    def calculate_reduction(raw_alert_count: int, incident_count: int) -> float:
        """Calculate compression / noise reduction ratio.

        Formula: 1 - (incidents / raw_alerts)
        Returns 0.0 if raw_alert_count <= 0.
        """
        if raw_alert_count <= 0:
            return 0.0
        return max(0.0, 1.0 - (incident_count / raw_alert_count))

    def analyze_window_sensitivity(
        self,
        alerts: list[Alert],
        windows_minutes: list[int] | None = None,
        gap_timeouts_minutes: list[int] | None = None,
    ) -> pd.DataFrame:
        """Run parameter sweep over sliding-window settings.

        Parameters
        ----------
        alerts:
            List of Alert instances to cluster.
        windows_minutes:
            List of window sizes in minutes to test (default: [10, 20, 30, 45, 60]).
        gap_timeouts_minutes:
            List of gap timeout values in minutes to test (default: [5, 10, 15, 20]).

        Returns
        -------
        pd.DataFrame
            Columns: window_min, gap_min, incident_count, noise_reduction, max_alerts_per_incident
        """
        windows = windows_minutes or [10, 20, 30, 45, 60]
        gaps = gap_timeouts_minutes or [5, 10, 15, 20]

        rows: list[dict[str, Any]] = []
        raw_count = len(alerts)

        for w in windows:
            for g in gaps:
                if g > w:
                    continue  # Gap timeout cannot exceed window

                engine = CorrelationEngine()
                engine.clusterer.window_minutes = w
                engine.clusterer.gap_timeout_minutes = g

                incidents = engine.process(alerts)
                inc_count = len(incidents)
                reduction = self.calculate_reduction(raw_count, inc_count)
                max_size = max([len(i.alerts) for i in incidents], default=0)

                rows.append({
                    "window_minutes": w,
                    "gap_timeout_minutes": g,
                    "incident_count": inc_count,
                    "noise_reduction_pct": round(reduction * 100, 2),
                    "max_alerts_per_incident": max_size,
                })

        return pd.DataFrame(rows)

    @staticmethod
    def measure_purity(
        incidents: list[Incident],
        ground_truth_labels: dict[str, str],
    ) -> float:
        """Calculate incident purity against ground truth attack run labels.

        Parameters
        ----------
        incidents:
            List of correlated incidents.
        ground_truth_labels:
            Mapping of alert_id -> campaign_id or attack_run_id.

        Returns
        -------
        float
            Weighted average purity across all incidents in [0.0, 1.0].
        """
        if not incidents or not ground_truth_labels:
            return 1.0

        total_alerts = 0
        correctly_assigned = 0

        for inc in incidents:
            if not inc.alerts:
                continue
            counts: dict[str, int] = {}
            for a in inc.alerts:
                label = ground_truth_labels.get(a.alert_id, "unknown")
                counts[label] = counts.get(label, 0) + 1

            majority_count = max(counts.values()) if counts else 0
            correctly_assigned += majority_count
            total_alerts += len(inc.alerts)

        return (correctly_assigned / total_alerts) if total_alerts > 0 else 1.0
