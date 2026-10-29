"""
HTML incident-report renderer.

Uses Jinja2 to produce a self-contained HTML file that embeds:
* An interactive Cytoscape.js graph with layout.
* An incident-summary sidebar (score, severity, blast radius, time range).
* A scrollable timeline of alert events.
* MITRE ATT&CK technique badges.
* Playbook recommendations.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegis.graph.builder import AttackGraphBuilder

# Directory containing Jinja2 templates (sibling templates/ folder).
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class HTMLReportRenderer:
    """Render a self-contained HTML incident report."""

    def __init__(self, template_dir: Path | None = None) -> None:
        search_path = template_dir or _TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(search_path)),
            autoescape=select_autoescape(["html"]),
        )

    def render(
        self,
        incident: Any,
        graph_data: dict[str, Any],
        output_path: Path | str,
    ) -> Path:
        """Render the incident report and write it to output_path."""
        builder = AttackGraphBuilder()
        timeline = builder.build_timeline(incident)

        if hasattr(incident, "time_range"):
            start, end = incident.time_range
        elif hasattr(incident, "start_time") and hasattr(incident, "end_time"):
            start, end = incident.start_time, incident.end_time
        else:
            now = datetime.utcnow()
            start, end = now, now

        duration_sec = getattr(incident, "duration_seconds", None)
        if duration_sec is None and start and end:
            duration_sec = int((end - start).total_seconds())

        techs = getattr(incident, "mitre_techniques", None)
        if techs is None:
            techs = list(getattr(incident, "techniques", []))

        playbooks = getattr(incident, "playbook_recommendations", [])

        template = self._env.get_template("incident_report.html")
        html = template.render(
            incident=incident,
            graph_json=json.dumps(graph_data, default=str),
            timeline=timeline,
            techniques=sorted(set(techs)),
            time_start=start.isoformat() if hasattr(start, "isoformat") else str(start),
            time_end=end.isoformat() if hasattr(end, "isoformat") else str(end),
            duration_seconds=duration_sec,
            playbooks=playbooks,
        )

        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html, encoding="utf-8")
        return out_path
