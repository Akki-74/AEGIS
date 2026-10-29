"""
aegis.pipelines.compile
=======================

Sigma rule compilation engine for Elasticsearch and OpenSearch backends.

Converts Sigma detection rules into SIEM queries using either pySigma
(when available with the appropriate backend plugins) or an internal
AST-based Lucene/ES query generator.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class RuleCompiler:
    """Compile Sigma rule YAML files into Elasticsearch / OpenSearch queries.

    Parameters
    ----------
    pipeline_name:
        Optional pipeline name ('sysmon_ecs', 'ecs_windows', etc.).
    """

    def __init__(self, pipeline_name: str = "sysmon_ecs") -> None:
        self.pipeline_name = pipeline_name
        self._pysigma_available = False
        try:
            import sigma  # noqa: F401  # type: ignore[import-untyped]
            from sigma.backends.elasticsearch import (  # noqa: F401  # type: ignore[import-untyped]
                ElasticsearchQuerystringBackend,
            )
            self._pysigma_available = True
            logger.info("pySigma backend loaded successfully.")
        except ImportError:
            logger.debug("pySigma backend not installed; using native Sigma-to-Lucene compiler.")

    def compile_rule(self, rule_path: Path | str, backend: str = "elasticsearch") -> str:
        """Compile a single Sigma rule file to a query string.

        Parameters
        ----------
        rule_path:
            Path to the .yml rule file.
        backend:
            Target backend ('elasticsearch' or 'opensearch').

        Returns
        -------
        str
            Compiled query string (Lucene / ES Query DSL).
        """
        path = Path(rule_path)
        with path.open("r", encoding="utf-8") as f:
            content = f.read()

        if self._pysigma_available:
            try:
                from sigma.collection import SigmaCollection  # type: ignore[import-untyped]
                from sigma.backends.elasticsearch import ElasticsearchQuerystringBackend  # type: ignore[import-untyped]
                from aegis.pipelines.sysmon_ecs import sysmon_ecs_pipeline

                collection = SigmaCollection.from_yaml(content)
                pipeline = sysmon_ecs_pipeline()
                es_backend = ElasticsearchQuerystringBackend(processing_pipeline=pipeline)
                queries = es_backend.convert(collection)
                if queries:
                    return str(queries[0])
            except Exception as exc:
                logger.warning(
                    "pySigma compilation failed for %s (%s); falling back to native compiler",
                    path.name,
                    exc,
                )

        # Native fallback compiler
        rule_data = yaml.safe_load(content)
        return self._native_compile(rule_data, backend)

    def compile_all(self, rules_dir: Path | str, backend: str = "elasticsearch") -> dict[str, str]:
        """Compile all .yml rules in a directory recursively.

        Parameters
        ----------
        rules_dir:
            Root directory to scan for rules.
        backend:
            Target backend ('elasticsearch' or 'opensearch').

        Returns
        -------
        dict[str, str]
            Mapping of relative rule path to compiled query string.
        """
        root = Path(rules_dir)
        results: dict[str, str] = {}
        for rule_file in sorted(root.rglob("*.yml")):
            rel_name = str(rule_file.relative_to(root)).replace("\\", "/")
            try:
                query = self.compile_rule(rule_file, backend=backend)
                results[rel_name] = query
            except Exception as e:
                logger.error("Failed to compile %s: %s", rel_name, e)
                results[rel_name] = f"ERROR: {e}"
        return results

    def export_ndjson(self, compiled: dict[str, str], output_path: Path | str) -> Path:
        """Export compiled queries as NDJSON for Elasticsearch / OpenSearch indexing.

        Parameters
        ----------
        compiled:
            Mapping of rule name to query string.
        output_path:
            Target NDJSON file path.
        """
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for rule_name, query in compiled.items():
                record = {
                    "rule": rule_name,
                    "query": query,
                    "type": "saved_query",
                    "tags": ["aegis", "sigma"],
                }
                f.write(json.dumps(record) + "\n")
        logger.info("Exported %d compiled rules to %s", len(compiled), out)
        return out

    def _native_compile(self, rule_data: dict[str, Any], backend: str) -> str:
        """Native lightweight Sigma-to-Lucene compiler."""
        if not rule_data or "detection" not in rule_data:
            return "*"

        detection = rule_data["detection"]
        condition = detection.get("condition", "selection")

        # Map common Sysmon fields to ECS
        field_map = {
            "Image": "process.executable",
            "CommandLine": "process.command_line",
            "ParentImage": "process.parent.executable",
            "ParentCommandLine": "process.parent.command_line",
            "User": "user.name",
            "TargetImage": "winlog.event_data.TargetImage",
            "GrantedAccess": "winlog.event_data.GrantedAccess",
            "SourceImage": "process.executable",
            "SourceIp": "source.ip",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
            "EventID": "winlog.event_id",
            "TicketEncryptionType": "winlog.event_data.TicketEncryptionType",
            "ServiceName": "winlog.event_data.ServiceName",
            "PreAuthType": "winlog.event_data.PreAuthType",
            "LogonType": "winlog.event_data.LogonType",
        }

        sub_queries: dict[str, str] = {}
        for key, value in detection.items():
            if key == "condition" or key.startswith("timeframe"):
                continue

            terms: list[str] = []
            if isinstance(value, dict):
                for raw_field, field_val in value.items():
                    # Handle field modifiers (e.g., Image|endswith, CommandLine|contains)
                    field_name = raw_field
                    modifier = ""
                    if "|" in raw_field:
                        field_name, modifier = raw_field.split("|", 1)

                    mapped_field = field_map.get(field_name, field_name)

                    if isinstance(field_val, list):
                        or_terms = []
                        for item in field_val:
                            formatted = self._format_val(item, modifier)
                            or_terms.append(f"{mapped_field}:{formatted}")
                        terms.append(f"({' OR '.join(or_terms)})")
                    else:
                        formatted = self._format_val(field_val, modifier)
                        terms.append(f"{mapped_field}:{formatted}")

            elif isinstance(value, list):
                # Plain list of values (e.g. keywords)
                or_terms = [f'"{v}"' for v in value]
                terms.append(f"({' OR '.join(or_terms)})")

            sub_queries[key] = " AND ".join(terms) if terms else "*"

        # Replace conditions
        compiled_query = condition
        for key, expr in sub_queries.items():
            compiled_query = compiled_query.replace(key, f"({expr})")

        # Normalize boolean operators
        compiled_query = compiled_query.replace(" and ", " AND ").replace(" or ", " OR ").replace(" not ", " NOT ")
        return compiled_query.strip()

    @staticmethod
    def _format_val(val: Any, modifier: str) -> str:
        s = str(val)
        if "contains" in modifier:
            return f"*{s}*"
        if "endswith" in modifier:
            return f"*{s}"
        if "startswith" in modifier:
            return f"{s}*"
        if " " in s or "\\" in s or ":" in s:
            return f'"{s}"'
        return s
