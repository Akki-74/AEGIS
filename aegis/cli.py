"""AEGIS CLI — Command-line interface for the AEGIS platform.

Provides Click-based command groups for:
    - ``aegis rules``     — Compile, test, and validate Sigma detection rules.
    - ``aegis correlate`` — Run the correlation engine on exported alert data.
    - ``aegis graph``     — Build attack graphs from correlated incidents.
    - ``aegis eval``      — Evaluate detection coverage and noise metrics.
    - ``aegis session``   — Manage operational session logs and analyst notes.

Entry point: ``aegis.cli:main`` (registered in pyproject.toml).

Usage::

    aegis --help
    aegis rules compile --rules-dir rules/ --backend elasticsearch
    aegis correlate run --input alerts.json --config config.yaml
    aegis session log "Completed tuning on LSASS memory rule"
    aegis session history
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import click
import yaml
from rich.console import Console

from aegis import __version__
from aegis.config import AegisConfig
from aegis.session_logger import SessionLogger

# Rich console instance for pretty terminal output.
console = Console(stderr=True)
session_logger = SessionLogger()


# =============================================================================
# Root group
# =============================================================================
@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="aegis")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=False),
    default="config.yaml",
    envvar="AEGIS_CONFIG",
    help="Path to the YAML configuration file.  [env: AEGIS_CONFIG]",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable verbose (debug-level) logging.",
)
@click.pass_context
def main(ctx: click.Context, config_path: str, verbose: bool) -> None:
    """AEGIS — Detection Engineering & Automated Incident Correlation.

    Compile Sigma rules, correlate security alerts into attack chains, build
    attack graphs, and evaluate detection coverage against MITRE ATT&CK.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["verbose"] = verbose


# =============================================================================
# Helper — load config lazily from context
# =============================================================================
def _load_config(ctx: click.Context) -> AegisConfig:
    config_path: str = ctx.obj["config_path"]
    path = Path(config_path)
    if path.exists():
        return AegisConfig.from_yaml(path)
    return AegisConfig()


# =============================================================================
# Command group: rules
# =============================================================================
@main.group()
def rules() -> None:
    """Manage Sigma detection rules — compile, test, and validate."""


@rules.command("compile")
@click.option(
    "--rules-dir", "-r",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    required=True,
    help="Directory containing Sigma rule YAML files.",
)
@click.option(
    "--backend", "-b",
    type=click.Choice(["elasticsearch", "opensearch"], case_sensitive=False),
    default="elasticsearch",
    show_default=True,
    help="Target SIEM backend for query compilation.",
)
@click.option(
    "--pipeline", "-p",
    type=click.Choice(["sysmon_ecs", "ecs_windows"], case_sensitive=False),
    default="sysmon_ecs",
    show_default=True,
    help="pySigma processing pipeline to apply.",
)
@click.option(
    "--output", "-o",
    type=click.Path(resolve_path=True),
    default=None,
    help="Output file for compiled queries (NDJSON or JSON).",
)
@click.pass_context
def rules_compile(
    ctx: click.Context,
    rules_dir: str,
    backend: str,
    pipeline: str,
    output: str | None,
) -> None:
    """Compile Sigma rules to Elasticsearch / OpenSearch queries via pySigma."""
    from aegis.pipelines.compile import RuleCompiler

    t0 = time.time()
    console.print(f"[bold green]▶ Compiling rules[/bold green] from {rules_dir}")
    compiler = RuleCompiler(pipeline_name=pipeline)
    compiled = compiler.compile_all(rules_dir, backend=backend)

    if not compiled:
        console.print("[yellow]No .yml rule files found.[/yellow]")
        session_logger.log_event("rules_compile", status="WARNING", details={"rules_dir": rules_dir, "count": 0})
        raise SystemExit(1)

    dur = time.time() - t0
    console.print(f"[green]✔ Successfully compiled {len(compiled)} rule(s) in {dur:.3f}s[/green]")

    session_logger.log_event(
        action="rules_compile",
        status="SUCCESS",
        details={"rules_dir": rules_dir, "rule_count": len(compiled), "backend": backend, "output": output},
        duration_s=dur,
    )

    if output:
        out_p = Path(output)
        if out_p.suffix.lower() == ".ndjson":
            compiler.export_ndjson(compiled, out_p)
        else:
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(json.dumps(compiled, indent=2), encoding="utf-8")
        console.print(f"[green]✔ Wrote queries to {output}[/green]")
    else:
        click.echo(json.dumps(compiled, indent=2))


@rules.command("test")
@click.option(
    "--rules-dir", "-r",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default="rules",
    help="Directory containing Sigma rule YAML files.",
)
@click.pass_context
def rules_test(ctx: click.Context, rules_dir: str) -> None:
    """Run test suite and rule validation."""
    from run_tests import main as run_test_suite
    t0 = time.time()
    console.print(f"[bold green]▶ Running AEGIS test suite and rule verifications[/bold green]")
    code = run_test_suite()
    dur = time.time() - t0
    session_logger.log_event(
        action="rules_test",
        status="SUCCESS" if code == 0 else "FAILED",
        details={"exit_code": code},
        duration_s=dur,
    )
    if code != 0:
        raise SystemExit(code)


@rules.command("validate")
@click.option(
    "--rules-dir", "-r",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    required=True,
    help="Directory containing Sigma rule YAML files.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Fail on warnings.",
)
@click.pass_context
def rules_validate(ctx: click.Context, rules_dir: str, strict: bool) -> None:
    """Validate that all Sigma rules meet AEGIS metadata standards."""
    t0 = time.time()
    required_fields = [
        "title", "id", "status", "description", "author",
        "date", "modified", "tags", "logsource", "detection",
        "falsepositives", "level",
    ]

    rules_path = Path(rules_dir)
    rule_files = sorted(rules_path.rglob("*.yml"))

    if not rule_files:
        console.print("[yellow]No .yml rule files found.[/yellow]")
        raise SystemExit(1)

    console.print(f"[bold green]▶ Validating {len(rule_files)} rules[/bold green] in {rules_dir}")
    errors = 0
    seen_ids: dict[str, str] = {}

    for rf in rule_files:
        rel = str(rf.relative_to(rules_path)).replace("\\", "/")
        try:
            with rf.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            console.print(f"  [red]FAIL[/red] {rel}: YAML syntax error - {e}")
            errors += 1
            continue

        if not isinstance(data, dict):
            console.print(f"  [red]FAIL[/red] {rel}: Root is not a mapping")
            errors += 1
            continue

        missing = [req for req in required_fields if req not in data]
        if missing:
            console.print(f"  [red]FAIL[/red] {rel}: Missing fields: {', '.join(missing)}")
            errors += 1
            continue

        r_id = str(data.get("id", ""))
        try:
            uuid.UUID(r_id)
        except ValueError:
            console.print(f"  [red]FAIL[/red] {rel}: Invalid UUID '{r_id}'")
            errors += 1
            continue

        if r_id in seen_ids:
            console.print(f"  [red]FAIL[/red] {rel}: Duplicate ID '{r_id}' with {seen_ids[r_id]}")
            errors += 1
            continue
        seen_ids[r_id] = rel

        tags = data.get("tags", [])
        if not any(str(t).lower().startswith("attack.") for t in tags):
            console.print(f"  [red]FAIL[/red] {rel}: No attack.* MITRE tag found")
            errors += 1
            continue

        console.print(f"  [green]PASS[/green] {rel}")

    dur = time.time() - t0
    session_logger.log_event(
        action="rules_validate",
        status="SUCCESS" if errors == 0 else "FAILED",
        details={"total_rules": len(rule_files), "error_count": errors},
        duration_s=dur,
    )

    if errors > 0:
        console.print(f"\n[red]Validation failed with {errors} error(s)[/red]")
        raise SystemExit(1)
    console.print(f"\n[bold green]✔ All {len(rule_files)} rules passed validation successfully![/bold green]")


# =============================================================================
# Command group: correlate
# =============================================================================
@main.group()
def correlate() -> None:
    """Alert correlation engine — group alerts into attack chains."""


@correlate.command("run")
@click.option(
    "--input", "-i", "input_file",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="Path to the alerts JSON file.",
)
@click.option(
    "--output", "-o",
    type=click.Path(resolve_path=True),
    default=None,
    help="Output file for correlated incidents (JSON).",
)
@click.pass_context
def correlate_run(ctx: click.Context, input_file: str, output: str | None) -> None:
    """Run the sliding-window correlation engine on a set of alerts."""
    from aegis.correlate.engine import CorrelationEngine

    t0 = time.time()
    config = _load_config(ctx)
    console.print(f"[bold green]▶ Running correlation engine[/bold green]")
    console.print(f"  Input:  {input_file}")

    engine = CorrelationEngine(config)
    incidents = engine.process_from_file(input_file)
    dur = time.time() - t0

    console.print(f"[bold green]✔ Correlated into {len(incidents)} incident(s) ({dur:.3f}s)[/bold green]")

    for idx, inc in enumerate(incidents, 1):
        console.print(
            f"  Incident #{idx} [{inc.severity.upper()} - Score {inc.score:.2f}]: "
            f"{len(inc.alerts)} alerts, {len(inc.techniques)} techniques, "
            f"Hosts: {', '.join(sorted(inc.hosts)) or 'None'}"
        )

    out_dicts = [inc.to_dict() for inc in incidents]
    res_json = json.dumps(out_dicts, indent=2, default=str)

    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(res_json, encoding="utf-8")
        console.print(f"[green]✔ Exported incidents to {output}[/green]")
    else:
        click.echo(res_json)

    session_logger.log_event(
        action="correlate_run",
        status="SUCCESS",
        details={
            "input_file": input_file,
            "incident_count": len(incidents),
            "output": output,
            "top_score": round(incidents[0].score, 4) if incidents else 0.0,
            "top_severity": incidents[0].severity if incidents else None,
        },
        duration_s=dur,
    )


# =============================================================================
# Command group: graph
# =============================================================================
@main.group()
def graph() -> None:
    """Attack graph operations — build and export kill-chain graphs."""


@graph.command("build")
@click.option(
    "--input", "-i", "input_file",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="Path to correlated incidents JSON file or raw alerts.",
)
@click.option(
    "--output", "-o",
    type=click.Path(resolve_path=True),
    default="attack_graph.html",
    show_default=True,
    help="Output file path (.html or .json).",
)
@click.pass_context
def graph_build(
    ctx: click.Context,
    input_file: str,
    output: str,
) -> None:
    """Build an attack graph and HTML report from incidents."""
    from aegis.correlate.engine import CorrelationEngine
    from aegis.correlate.schema import Incident
    from aegis.graph.builder import AttackGraphBuilder
    from aegis.graph.renderer import HTMLReportRenderer

    t0 = time.time()
    console.print(f"[bold green]▶ Building attack graph[/bold green] from {input_file}")
    with Path(input_file).open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list) and data and "alerts" in data[0]:
        incidents = [Incident.from_dict(d) for d in data]
    else:
        engine = CorrelationEngine(_load_config(ctx))
        incidents = engine.process_from_file(input_file)

    if not incidents:
        console.print("[yellow]No incidents to graph.[/yellow]")
        return

    top_inc = incidents[0]
    builder = AttackGraphBuilder()
    graph_data = builder.build(top_inc)

    out_path = Path(output)
    if out_path.suffix.lower() == ".html":
        renderer = HTMLReportRenderer()
        renderer.render(top_inc, graph_data, out_path)
        console.print(f"[green]✔ Interactive HTML attack graph rendered to {output}[/green]")
    else:
        out_path.write_text(json.dumps(graph_data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]✔ Cytoscape graph JSON exported to {output}[/green]")

    dur = time.time() - t0
    session_logger.log_event(
        action="graph_build",
        status="SUCCESS",
        details={"input_file": input_file, "output": output, "format": out_path.suffix},
        duration_s=dur,
    )


# =============================================================================
# Command group: eval
# =============================================================================
@main.group()
def eval() -> None:
    """Evaluate detection coverage and noise reduction metrics."""


@eval.command("coverage")
@click.option(
    "--rules-dir", "-r",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default="rules",
    help="Directory containing Sigma rule YAML files.",
)
@click.option(
    "--output", "-o",
    type=click.Path(resolve_path=True),
    default=None,
    help="Output file for the coverage matrix / Navigator layer.",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["json", "csv", "markdown"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format.",
)
@click.pass_context
def eval_coverage(
    ctx: click.Context,
    rules_dir: str,
    output: str | None,
    output_format: str,
) -> None:
    """Generate an ATT&CK coverage matrix and Navigator layer from Sigma rules."""
    from aegis.eval.coverage import CoverageAnalyzer

    t0 = time.time()
    console.print(f"[bold green]▶ Generating ATT&CK coverage matrix[/bold green] from {rules_dir}")
    analyzer = CoverageAnalyzer(rules_dir)
    df = analyzer.analyze()

    if output_format == "markdown":
        res = analyzer.coverage_report(df)
    elif output_format == "csv":
        res = df.to_csv(index=False)
    else:
        res = df.to_json(orient="records", indent=2)

    if output:
        out_p = Path(output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if out_p.suffix.lower() == ".json" and "navigator" in out_p.stem.lower():
            analyzer.generate_navigator_layer(df, out_p)
            console.print(f"[green]✔ Generated ATT&CK Navigator v4.5 layer to {output}[/green]")
        else:
            out_p.write_text(res, encoding="utf-8")
            console.print(f"[green]✔ Saved coverage matrix to {output}[/green]")
    else:
        click.echo(res)

    dur = time.time() - t0
    session_logger.log_event(
        action="eval_coverage",
        status="SUCCESS",
        details={"rules_dir": rules_dir, "technique_count": df['technique_id'].nunique(), "output": output},
        duration_s=dur,
    )


@eval.command("noise")
@click.option(
    "--before", "-b", "before_file",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="Path to raw alerts JSON file.",
)
@click.option(
    "--after", "-a", "after_file",
    type=click.Path(exists=True, resolve_path=True),
    required=True,
    help="Path to correlated incidents JSON file.",
)
@click.option(
    "--output", "-o",
    type=click.Path(resolve_path=True),
    default=None,
    help="Output file for noise metrics JSON.",
)
@click.pass_context
def eval_noise(
    ctx: click.Context,
    before_file: str,
    after_file: str,
    output: str | None,
) -> None:
    """Calculate noise reduction metrics comparing raw vs. correlated alerts."""
    from aegis.eval.noise import NoiseAnalyzer

    console.print(f"[bold green]▶ Calculating noise reduction metrics[/bold green]")
    with Path(before_file).open("r", encoding="utf-8") as f:
        raw_data = json.load(f)
    raw_alerts = raw_data.get("alerts", raw_data) if isinstance(raw_data, dict) else raw_data

    with Path(after_file).open("r", encoding="utf-8") as f:
        corr_data = json.load(f)
    corr_incs = corr_data.get("incidents", corr_data) if isinstance(corr_data, dict) else corr_data

    raw_count = len(raw_alerts)
    inc_count = len(corr_incs)
    reduction = NoiseAnalyzer.calculate_reduction(raw_count, inc_count)

    metrics = {
        "raw_alert_count": raw_count,
        "correlated_incident_count": inc_count,
        "compression_ratio": f"{round(raw_count / inc_count, 2)}:1" if inc_count > 0 else "N/A",
        "noise_reduction_percentage": round(reduction * 100, 2),
    }

    console.print(f"  Raw Alerts:               {raw_count}")
    console.print(f"  Correlated Incidents:     {inc_count}")
    console.print(f"  Compression Ratio:        {metrics['compression_ratio']}")
    console.print(f"  Noise Reduction:          [bold green]{metrics['noise_reduction_percentage']}%[/bold green]")

    res_json = json.dumps(metrics, indent=2)
    if output:
        Path(output).write_text(res_json, encoding="utf-8")
        console.print(f"[green]✔ Metrics written to {output}[/green]")
    else:
        click.echo(res_json)

    session_logger.log_event(
        action="eval_noise",
        status="SUCCESS",
        details=metrics,
    )


# =============================================================================
# Command group: session
# =============================================================================
@main.group()
def session() -> None:
    """Inspect and maintain operational session logs and analyst notes."""


@session.command("log")
@click.argument("message", type=str)
@click.option("--author", "-a", type=str, default=None, help="Author name.")
def session_log_cmd(message: str, author: str | None) -> None:
    """Append a manual operational note to the session log."""
    rec = session_logger.add_note(message, author=author)
    console.print(f"[green]✔ Appended session note:[/green] {message}")
    console.print(f"  Timestamp: {rec['timestamp']}")
    console.print(f"  Operator:  {rec['user']}@{rec['hostname']}")


@session.command("history")
@click.option(
    "--limit", "-n",
    type=int,
    default=10,
    show_default=True,
    help="Number of records to show.",
)
def session_history_cmd(limit: int) -> None:
    """Display recent operational session logs."""
    records = session_logger.read_recent(limit=limit)
    if not records:
        console.print("[yellow]No session records found.[/yellow]")
        return

    console.print(f"[bold green]▶ Recent Session Log History (Last {len(records)})[/bold green]\n")
    for r in records:
        ts = r.get("timestamp", "")[:19]
        status = r.get("status", "INFO")
        action = r.get("action", "")
        user = r.get("user", "")
        details = r.get("details", {})
        dur = r.get("duration_seconds")
        dur_str = f" ({dur:.3f}s)" if dur is not None else ""

        color = "green" if status == "SUCCESS" else "cyan" if status == "NOTE" else "yellow"
        console.print(f"  [{color}]{ts}[/{color}] [{status}] [bold]{action.upper()}[/bold] by {user}{dur_str}")
        if "message" in details:
            console.print(f"    [italic]Note:[/italic] {details['message']}")
        elif details:
            summary = ", ".join(f"{k}={v}" for k, v in details.items() if v is not None)
            console.print(f"    [dim]{summary}[/dim]")


if __name__ == "__main__":
    main()
