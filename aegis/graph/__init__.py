"""
AEGIS Graph Visualization sub-package.

Provides:
    - ``AttackGraphBuilder`` — converts correlated incidents into
      Cytoscape.js-compatible graph structures.
    - ``HTMLReportRenderer`` — renders self-contained HTML incident reports
      with interactive graph visualisation and timeline views.
"""

from aegis.graph.builder import AttackGraphBuilder
from aegis.graph.renderer import HTMLReportRenderer

__all__ = ["AttackGraphBuilder", "HTMLReportRenderer"]
