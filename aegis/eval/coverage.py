"""
aegis.eval.coverage
===================

ATT&CK coverage evaluation and ATT&CK Navigator layer generator.

Analyzes Sigma detection rules, extracts MITRE ATT&CK technique tags,
computes technique and tactic coverage metrics, and exports ATT&CK Navigator
layer files (v4.5).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

logger = logging.getLogger(__name__)


class CoverageAnalyzer:
    """Analyze Sigma detection rule repository against MITRE ATT&CK."""

    def __init__(self, rules_dir: Path | str = "rules") -> None:
        self.rules_dir = Path(rules_dir)

    def analyze(self) -> pd.DataFrame:
        """Scan rule files and build a DataFrame of rules and ATT&CK mappings.

        Returns
        -------
        pd.DataFrame
            Columns: rule_file, title, id, level, tactic, technique_id, status
        """
        records: list[dict[str, Any]] = []

        for yml_path in sorted(self.rules_dir.rglob("*.yml")):
            try:
                with yml_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception as e:
                logger.warning("Could not read rule %s: %e", yml_path, e)
                continue

            if not isinstance(data, dict):
                continue

            title = data.get("title", yml_path.stem)
            rule_id = data.get("id", "")
            level = data.get("level", "medium")
            status = data.get("status", "experimental")
            tags = data.get("tags", [])

            attack_techs: list[str] = []
            attack_tactics: list[str] = []

            for tag in tags:
                tag_lower = str(tag).lower()
                if tag_lower.startswith("attack.t"):
                    tech_id = tag_lower.split("attack.")[1].upper()
                    attack_techs.append(tech_id)
                elif tag_lower.startswith("attack."):
                    tactic_name = tag_lower.split("attack.")[1]
                    attack_tactics.append(tactic_name)

            if not attack_techs:
                attack_techs = ["UNMAPPED"]

            for tech in attack_techs:
                records.append({
                    "rule_file": str(yml_path.relative_to(self.rules_dir)).replace("\\", "/"),
                    "title": title,
                    "id": rule_id,
                    "level": level,
                    "technique_id": tech,
                    "tactics": ", ".join(attack_tactics) if attack_tactics else "unspecified",
                    "status": status,
                })

        df = pd.DataFrame(records)
        logger.info("Parsed %d rule-technique mappings across %s", len(df), self.rules_dir)
        return df

    def generate_navigator_layer(
        self,
        coverage_df: pd.DataFrame,
        output_path: Path | str,
        layer_name: str = "AEGIS Detection Coverage",
    ) -> Path:
        """Export an ATT&CK Navigator v4.5 layer JSON file.

        Parameters
        ----------
        coverage_df:
            Output from :meth:`analyze`.
        output_path:
            Target JSON path.
        layer_name:
            Layer display name in ATT&CK Navigator.
        """
        techniques_list = []
        counts = coverage_df["technique_id"].value_counts().to_dict()

        for tech_id, count in counts.items():
            if tech_id == "UNMAPPED":
                continue
            techniques_list.append({
                "techniqueID": tech_id,
                "score": int(count),
                "color": "#38BDF8" if count == 1 else "#0284C7",
                "comment": f"Covered by {count} AEGIS Sigma rule(s)",
                "enabled": True,
            })

        layer = {
            "name": layer_name,
            "versions": {
                "attack": "14",
                "navigator": "4.5",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "AEGIS Detection Engineering & Automated Incident Correlation Coverage",
            "filters": {
                "platforms": ["windows", "linux"],
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
            },
            "gradient": {
                "colors": ["#1E293B", "#0284C7", "#38BDF8"],
                "minValue": 0,
                "maxValue": max(counts.values()) if counts else 1,
            },
            "legendItems": [
                {"label": "1 Rule", "color": "#0284C7"},
                {"label": "Multiple Rules", "color": "#38BDF8"},
            ],
            "techniques": techniques_list,
        }

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            json.dump(layer, f, indent=2)

        logger.info("Wrote ATT&CK Navigator layer to %s", out)
        return out

    def coverage_report(self, coverage_df: pd.DataFrame) -> str:
        """Generate a markdown report of ATT&CK coverage."""
        unique_techs = coverage_df[coverage_df["technique_id"] != "UNMAPPED"]["technique_id"].nunique()
        total_rules = coverage_df["rule_file"].nunique()

        lines = [
            "# AEGIS ATT&CK Coverage Summary",
            "",
            f"- **Total Sigma Rules**: {total_rules}",
            f"- **Distinct ATT&CK Techniques Covered**: {unique_techs}",
            "",
            "## Technique Breakdown",
            "",
            "| Technique ID | Rule Title | Severity | File |",
            "|--------------|------------|----------|------|",
        ]

        for _, row in coverage_df.sort_values(by=["technique_id", "level"]).iterrows():
            lines.append(
                f"| `{row['technique_id']}` | {row['title']} | `{row['level']}` | `{row['rule_file']}` |"
            )

        return "\n".join(lines)
