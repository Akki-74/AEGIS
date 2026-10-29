"""
aegis.eval.false_positives
==========================

False positive rate analysis and tuning changelog manager.

Computes:
- Alerts per host-day on benign baseline telemetry
- Pre-tuning vs. Post-tuning FP rate comparisons
- Tuning changelog tracking
"""

from __future__ import annotations

import logging
from typing import Any

import pandas as pd

from aegis.correlate.schema import Alert

logger = logging.getLogger(__name__)


class FPAnalyzer:
    """Analyze false positive rates on benign baseline datasets."""

    @staticmethod
    def analyze_baseline(
        alerts_on_benign: list[Alert],
        baseline_host_count: int,
        baseline_duration_days: float,
    ) -> pd.DataFrame:
        """Compute alerts per host-day per rule on benign telemetry.

        Parameters
        ----------
        alerts_on_benign:
            List of alerts that fired during benign baseline execution.
        baseline_host_count:
            Number of monitored hosts in the baseline environment.
        baseline_duration_days:
            Total duration of the baseline capture in days (e.g. 7.0 days).

        Returns
        -------
        pd.DataFrame
            Columns: rule_id, rule_name, alert_count, alerts_per_host_day
        """
        if baseline_host_count <= 0 or baseline_duration_days <= 0:
            raise ValueError("Host count and baseline duration must be > 0")

        host_days = baseline_host_count * baseline_duration_days

        rule_counts: dict[str, dict[str, Any]] = {}
        for a in alerts_on_benign:
            if a.rule_id not in rule_counts:
                rule_counts[a.rule_id] = {
                    "rule_id": a.rule_id,
                    "rule_name": a.rule_name,
                    "alert_count": 0,
                }
            rule_counts[a.rule_id]["alert_count"] += 1

        records = []
        for r_id, info in rule_counts.items():
            count = info["alert_count"]
            fp_rate = count / host_days
            records.append({
                "rule_id": r_id,
                "rule_name": info["rule_name"],
                "alert_count": count,
                "alerts_per_host_day": round(fp_rate, 4),
            })

        df = pd.DataFrame(records)
        if df.empty:
            return pd.DataFrame(columns=["rule_id", "rule_name", "alert_count", "alerts_per_host_day"])
        return df.sort_values(by="alerts_per_host_day", reverse=True)

    @staticmethod
    def compare_tuning(
        before_df: pd.DataFrame,
        after_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """Compare FP metrics before and after rule tuning.

        Returns merged DataFrame with delta calculations.
        """
        merged = pd.merge(
            before_df,
            after_df,
            on="rule_id",
            how="outer",
            suffixes=("_pre_tuning", "_post_tuning"),
        ).fillna(0)

        merged["delta_rate"] = (
            merged["alerts_per_host_day_post_tuning"] - merged["alerts_per_host_day_pre_tuning"]
        )
        merged["reduction_pct"] = (
            (merged["alerts_per_host_day_pre_tuning"] - merged["alerts_per_host_day_post_tuning"])
            / merged["alerts_per_host_day_pre_tuning"].replace(0, 1)
        ) * 100.0

        return merged
