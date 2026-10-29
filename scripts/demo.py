"""
scripts.demo — End-to-end demonstration of the AEGIS correlation engine.

Demonstrates:
1. The Raw Alert Flood (20 un-correlated atomic detection alerts across 3 hosts).
2. Automated Entity Resolution & Semantic Linking (Process Lineage, Logon Session, Lateral Movement).
3. Temporal Sliding-Window Clustering (80% noise reduction).
4. Multi-Factor Risk Scoring & Blast-Radius Assessment.
5. Interactive Cytoscape.js Attack Graph Generation.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Safe terminal encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from rich.console import Console
from rich.table import Table

from aegis.correlate.engine import CorrelationEngine
from aegis.correlate.schema import Alert
from aegis.graph.builder import AttackGraphBuilder
from aegis.graph.renderer import HTMLReportRenderer

console = Console(legacy_windows=False)


def run_demo() -> None:
    console.print("\n[bold cyan]=======================================================================[/bold cyan]")
    console.print("[bold white]            AEGIS - Automated Event Graph & Incident Synthesis          [/bold white]")
    console.print("[dim white]         Detection Engineering & Automated Incident Correlation Demo   [/dim white]")
    console.print("[bold cyan]=======================================================================[/bold cyan]\n")

    # Step 1: Load raw attack telemetry
    fixture_path = ROOT_DIR / "tests" / "fixtures" / "malicious" / "full_attack_chain.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = [Alert.from_dict(item) for item in data]

    console.print(f"[bold red]>> STAGE 1: THE RAW ALERT FLOOD ({len(alerts)} alerts)[/bold red]")
    console.print("[dim]Simulating incoming un-correlated SIEM alert stream across enterprise hosts...[/dim]\n")

    table = Table(title="Raw SIEM Alert Queue (Disjoint Telemetry)", show_header=True, header_style="bold magenta")
    table.add_column("Timestamp", style="dim", width=20)
    table.add_column("Host", style="cyan", width=22)
    table.add_column("User", style="yellow", width=18)
    table.add_column("Rule Title / Technique", style="white")
    table.add_column("Sev", width=8)

    for a in alerts[:8]:
        sev_color = "red" if a.severity.value in ("critical", "high") else "yellow"
        table.add_row(
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.hostname,
            a.username or "-",
            f"{a.rule_name} [{a.mitre_technique}]",
            f"[{sev_color}]{a.severity.value.upper()}[/{sev_color}]",
        )

    console.print(table)
    console.print(f"[dim italic]... and {len(alerts) - 8} more raw alerts scattered across the event queue.[/dim italic]\n")
    console.print("[bold yellow]Problem:[/bold yellow] Analysts face alert fatigue. Which alert is root cause? What is the blast radius?\n")
    time.sleep(0.5)

    # Step 2: Correlation Engine Execution
    console.print("[bold green]>> STAGE 2: AEGIS CORRELATION ENGINE PROCESSING[/bold green]")
    t0 = time.time()
    engine = CorrelationEngine()
    incidents = engine.process(alerts)
    elapsed = time.time() - t0

    console.print(f"  [green][+] Resolved entities:[/green] Process GUIDs (composite), Logon IDs (per-host), Normalized UPNs")
    console.print(f"  [green][+] Semantic linking:[/green] Process Lineage, Session Continuity, Lateral Movement")
    console.print(f"  [green][+] Temporal clustering:[/green] 30m Sliding Window, 10m Silence Gap Timeout")
    console.print(f"  [green][+] Processed {len(alerts)} alerts in {elapsed:.3f}s[/green]\n")

    # Step 3: Noise reduction & summary
    reduction = (1.0 - (len(incidents) / len(alerts))) * 100
    console.print(f"[bold green]>> STAGE 3: NOISE REDUCTION RESULTS[/bold green]")
    console.print(f"  Raw Alerts:               [bold red]{len(alerts)}[/bold red]")
    console.print(f"  Correlated Incidents:     [bold green]{len(incidents)}[/bold green]")
    console.print(f"  Alert Compression:        [bold green]{len(alerts) / len(incidents):.1f}:1[/bold green]")
    console.print(f"  Noise Reduction Ratio:    [bold green]{reduction:.1f}%[/bold green]\n")

    # Step 4: Incident summary table
    inc_table = Table(title="Correlated Attack Incidents", show_header=True, header_style="bold green")
    inc_table.add_column("Incident ID", style="dim", width=12)
    inc_table.add_column("Severity", width=10)
    inc_table.add_column("Score", width=8)
    inc_table.add_column("Alerts", width=8)
    inc_table.add_column("Techniques", width=22)
    inc_table.add_column("Blast Radius (Hosts)", style="cyan")
    inc_table.add_column("Recommended Playbook", style="yellow")

    for inc in incidents:
        color = "red" if inc.severity == "critical" else "orange3" if inc.severity == "high" else "yellow"
        pb = inc.playbook_recommendations[0].split("/")[-1] if inc.playbook_recommendations else "None"
        inc_table.add_row(
            inc.incident_id[:8],
            f"[{color}]{inc.severity.upper()}[/{color}]",
            f"{inc.score:.2f}",
            str(len(inc.alerts)),
            ", ".join(sorted(inc.techniques)[:3]) or "None",
            ", ".join(sorted(inc.hosts)),
            pb,
        )

    console.print(inc_table)
    console.print()

    # Step 5: Render interactive Cytoscape.js HTML report
    top_inc = incidents[0]
    builder = AttackGraphBuilder()
    graph_data = builder.build(top_inc)

    out_report = ROOT_DIR / "reports" / "demo_attack_graph.html"
    renderer = HTMLReportRenderer()
    renderer.render(top_inc, graph_data, out_report)

    console.print(f"[bold green]>> STAGE 4: INTERACTIVE ATTACK GRAPH RENDERED[/bold green]")
    console.print(f"  [bold cyan]Report URL:[/bold cyan] {out_report.as_uri()}")
    console.print(f"  [dim]Open the HTML file in any browser to inspect the interactive kill-chain DAG![/dim]\n")
    console.print("[bold cyan]=======================================================================[/bold cyan]\n")


if __name__ == "__main__":
    run_demo()
