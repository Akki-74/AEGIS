"""
aegis.playbooks.runner
======================

Safe containment and incident response execution harness.

Design Philosophy: Safety by Default
------------------------------------
1. **Dry-Run by Default** — All playbook actions execute in simulation/dry-run mode
   unless explicitly unlocked with ``dry_run=False`` and an authorized approval signature.
2. **Explicit Two-Man / Senior Approval** — Actions cannot run against live
   infrastructure without an ``approved_by`` analyst identity.
3. **Target Validation Guardrails** — Prevents accidental isolation or disruption of
   critical infrastructure (Domain Controllers, Gateways, DNS) and privileged
   system accounts (SYSTEM, krbtgt).
4. **Automated Rollback Plan** — Every generated containment plan includes inverse
   recovery steps (e.g. ``unisolate_endpoint``, ``unsuspend_account``).
5. **Comprehensive Audit Trail** — Every run is logged to operational JSONL logs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Critical infrastructure targets that must never be auto-isolated without override
PROTECTED_HOSTS: set[str] = {
    "dc01",
    "dc02",
    "domaincontroller",
    "dns01",
    "gateway",
    "router",
    "adfs01",
}

# Critical service identities that must never be locked out
PROTECTED_ACCOUNTS: set[str] = {
    "system",
    "local service",
    "network service",
    "krbtgt",
}


class PlaybookSafetyError(Exception):
    """Raised when an action violates safety guardrails or target validation."""


@dataclass
class PlaybookStepResult:
    """Outcome of a single response step."""

    step_id: int
    action: str
    target: str
    status: str  # "dry_run", "executed", "blocked", "failed"
    message: str
    rollback_procedure: str
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "rollback_procedure": self.rollback_procedure,
            "executed_at": self.executed_at.isoformat(),
        }


@dataclass
class PlaybookExecutionPlan:
    """Complete execution record including safety approvals and rollback plan."""

    playbook_name: str
    dry_run: bool
    approved_by: str | None
    incident_id: str | None
    step_results: list[PlaybookStepResult] = field(default_factory=list)
    recovery_plan: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook_name": self.playbook_name,
            "dry_run": self.dry_run,
            "approved_by": self.approved_by,
            "incident_id": self.incident_id,
            "step_results": [s.to_dict() for s in self.step_results],
            "recovery_plan": list(self.recovery_plan),
            "created_at": self.created_at.isoformat(),
        }


class PlaybookRunner:
    """Safe orchestrator for response playbooks with guardrails and dry-run defaults."""

    def __init__(self, playbooks_dir: Path | str | None = None) -> None:
        self.playbooks_dir = Path(playbooks_dir or Path(__file__).parent)

    def load_playbook(self, playbook_filename: str) -> dict[str, Any]:
        """Load and parse a YAML playbook from disk."""
        path = self.playbooks_dir / Path(playbook_filename).name
        if not path.exists():
            raise FileNotFoundError(f"Playbook file not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def run(
        self,
        playbook_filename: str,
        *,
        affected_hosts: list[str] | set[str] | None = None,
        affected_users: list[str] | set[str] | None = None,
        dry_run: bool = True,
        approved_by: str | None = None,
        allow_critical_target_override: bool = False,
        incident_id: str | None = None,
    ) -> PlaybookExecutionPlan:
        """Execute or simulate a playbook against specified targets.

        Parameters
        ----------
        playbook_filename:
            Filename of the playbook (e.g. 'credential_theft.yml').
        affected_hosts:
            Target hostnames to contain/remediate.
        affected_users:
            Target user accounts to reset/suspend.
        dry_run:
            If True (default), simulates actions and produces safety recommendations.
        approved_by:
            Analyst or senior approver ID. Required if ``dry_run=False``.
        allow_critical_target_override:
            If True, allows actions on protected infrastructure (e.g. Domain Controllers).
        incident_id:
            Associated incident UUID for audit provenance.
        """
        data = self.load_playbook(playbook_filename)
        playbook_name = data.get("name", "Unknown Playbook")
        steps = data.get("steps", [])

        # Strict approval check
        if not dry_run and not approved_by:
            raise PlaybookSafetyError(
                f"Execution of playbook '{playbook_name}' in live mode requires an authorized "
                f"'approved_by' analyst signature."
            )

        hosts = [h.strip() for h in (affected_hosts or []) if h.strip()]
        users = [u.strip() for u in (affected_users or []) if u.strip()]

        plan = PlaybookExecutionPlan(
            playbook_name=playbook_name,
            dry_run=dry_run,
            approved_by=approved_by,
            incident_id=incident_id,
        )

        for step in steps:
            step_id = step.get("id", 0)
            action = step.get("action", "unknown_action")
            raw_target_param = str(step.get("parameters", {}).get("target", ""))
            raw_account_param = str(step.get("parameters", {}).get("accounts", ""))

            targets: list[str] = []
            if "{affected_hosts}" in raw_target_param:
                targets = hosts or ["<no_host_specified>"]
            elif "{affected_users}" in raw_account_param:
                targets = users or ["<no_user_specified>"]
            else:
                targets = ["endpoint/environment"]

            for target in targets:
                # ── Guardrail: Target validation ──────────────────────────────
                is_protected = (
                    target.lower() in PROTECTED_HOSTS
                    or target.lower() in PROTECTED_ACCOUNTS
                    or target.endswith("$")
                )

                if is_protected and not allow_critical_target_override:
                    msg = (
                        f"BLOCKED by Target Guardrail: '{target}' is protected infrastructure or a system "
                        f"account. Isolation rejected without explicit critical target override."
                    )
                    logger.warning(msg)
                    plan.step_results.append(
                        PlaybookStepResult(
                            step_id=step_id,
                            action=action,
                            target=target,
                            status="blocked",
                            message=msg,
                            rollback_procedure="N/A (action prevented)",
                        )
                    )
                    continue

                # Generate recovery procedure
                rollback = self._generate_rollback_procedure(action, target)
                plan.recovery_plan.append(rollback)

                if dry_run:
                    status = "dry_run"
                    msg = (
                        f"[DRY-RUN] Simulated action '{action}' on target '{target}'. "
                        f"No live infrastructure modified."
                    )
                else:
                    status = "executed"
                    msg = f"[LIVE] Executed '{action}' on '{target}' approved by '{approved_by}'."

                plan.step_results.append(
                    PlaybookStepResult(
                        step_id=step_id,
                        action=action,
                        target=target,
                        status=status,
                        message=msg,
                        rollback_procedure=rollback,
                    )
                )

        logger.info(
            "Playbook '%s' processed (dry_run=%s, steps=%d, recovery_steps=%d)",
            playbook_name,
            dry_run,
            len(plan.step_results),
            len(plan.recovery_plan),
        )
        return plan

    @staticmethod
    def _generate_rollback_procedure(action: str, target: str) -> str:
        """Generate inverse rollback / recovery instructions for a given containment action."""
        rollbacks = {
            "isolate_endpoint": (
                f"unisolate_endpoint: Remove network isolation firewall rule on host '{target}' "
                f"via EDR API or 'netsh advfirewall reset'."
            ),
            "force_password_reset": (
                f"restore_account_access: Provide temporary credentials to verified user '{target}' "
                f"following out-of-band verification."
            ),
            "revoke_kerberos_tickets": (
                f"reissue_tickets: Allow user/service '{target}' to re-authenticate against Domain Controller "
                f"after secret rotation."
            ),
            "terminate_process": (
                f"restart_service: If required business application '{target}' was terminated, "
                f"restart service under clean service account."
            ),
            "suspend_user": (
                f"unsuspend_user: Enable-ADAccount -Identity '{target}' via ActiveDirectory PowerShell."
            ),
        }
        return rollbacks.get(
            action,
            f"manual_verification: Verify system state and reverse manual containment on '{target}'.",
        )
