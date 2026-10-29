"""
tests.test_playbook_safety — Test safe playbook execution harness, guardrails, dry-run defaults, and rollback generation.
"""

from __future__ import annotations

import pytest

from aegis.playbooks.runner import (
    PlaybookRunner,
    PlaybookSafetyError,
)


def test_dry_run_by_default() -> None:
    """Runner must execute in dry_run mode by default without modifying infrastructure."""
    runner = PlaybookRunner()
    plan = runner.run(
        "credential_theft.yml",
        affected_hosts=["WS01"],
        affected_users=["victim_user"],
    )

    assert plan.dry_run is True
    assert plan.approved_by is None
    for step in plan.step_results:
        assert step.status == "dry_run"
        assert "[DRY-RUN]" in step.message
        assert len(step.rollback_procedure) > 0


def test_live_execution_requires_approval() -> None:
    """Runner must reject live execution if no approval signature is supplied."""
    runner = PlaybookRunner()
    with pytest.raises(PlaybookSafetyError, match="requires an authorized 'approved_by'"):
        runner.run(
            "credential_theft.yml",
            affected_hosts=["WS01"],
            dry_run=False,
            approved_by=None,
        )


def test_protected_host_guardrail() -> None:
    """Domain Controllers and critical infrastructure must be blocked from isolation without override."""
    runner = PlaybookRunner()
    plan = runner.run(
        "credential_theft.yml",
        affected_hosts=["DC01", "WS02"],
        affected_users=["victim_user"],
        dry_run=True,
    )

    # DC01 must be blocked
    dc_steps = [s for s in plan.step_results if s.target.lower() == "dc01"]
    assert len(dc_steps) >= 1
    for s in dc_steps:
        assert s.status == "blocked"
        assert "BLOCKED by Target Guardrail" in s.message

    # WS02 must be allowed in dry-run
    ws_steps = [s for s in plan.step_results if s.target.lower() == "ws02"]
    assert len(ws_steps) >= 1
    for s in ws_steps:
        assert s.status == "dry_run"


def test_critical_target_override() -> None:
    """With explicit critical override and approval, actions on critical targets are permitted."""
    runner = PlaybookRunner()
    plan = runner.run(
        "credential_theft.yml",
        affected_hosts=["DC01"],
        dry_run=False,
        approved_by="senior_soc_lead",
        allow_critical_target_override=True,
    )

    assert plan.dry_run is False
    dc_steps = [s for s in plan.step_results if s.target.lower() == "dc01"]
    for s in dc_steps:
        assert s.status == "executed"
        assert "[LIVE]" in s.message


def test_rollback_procedure_generation() -> None:
    """Every executed or simulated action must generate a corresponding recovery procedure."""
    runner = PlaybookRunner()
    plan = runner.run(
        "lateral_movement.yml",
        affected_hosts=["WS05"],
        affected_users=["test_user"],
    )

    assert len(plan.recovery_plan) >= 1
    for recovery_action in plan.recovery_plan:
        assert isinstance(recovery_action, str)
        assert len(recovery_action) > 10
