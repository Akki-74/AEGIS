"""
tests.test_playbooks — Validation and schema integrity tests for incident response playbooks.
"""

from __future__ import annotations

from pathlib import Path
import yaml

from aegis.correlate.engine import _TACTIC_PLAYBOOK_MAP, _TECHNIQUE_PLAYBOOK_MAP

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "aegis" / "playbooks"


def test_playbook_files_exist_and_parse() -> None:
    """Verify that all response playbook definitions exist and are valid YAML."""
    expected_playbooks = [
        "ad_compromise.yml",
        "credential_theft.yml",
        "lateral_movement.yml",
        "malware_execution.yml",
    ]
    for pb_name in expected_playbooks:
        pb_path = PLAYBOOKS_DIR / pb_name
        assert pb_path.exists(), f"Playbook file missing: {pb_path}"
        with pb_path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert isinstance(data, dict), f"Playbook {pb_name} must parse to a dictionary"
        assert "name" in data, f"Playbook {pb_name} missing 'name'"
        assert "description" in data, f"Playbook {pb_name} missing 'description'"
        assert "trigger_techniques" in data, f"Playbook {pb_name} missing 'trigger_techniques'"
        assert "steps" in data, f"Playbook {pb_name} missing 'steps'"
        assert len(data["steps"]) >= 1, f"Playbook {pb_name} must contain at least one response step"

        for step in data["steps"]:
            assert "id" in step, f"Step in {pb_name} missing 'id'"
            assert "action" in step, f"Step in {pb_name} missing 'action'"
            assert "description" in step, f"Step in {pb_name} missing 'description'"


def test_engine_playbook_mappings_resolve() -> None:
    """Verify that all playbook files referenced by the correlation engine exist on disk."""
    repo_root = Path(__file__).resolve().parent.parent
    for tactic, rel_path in _TACTIC_PLAYBOOK_MAP.items():
        # Maps like 'playbooks/credential_theft.yml' -> 'aegis/playbooks/credential_theft.yml'
        pb_path = repo_root / "aegis" / rel_path
        assert pb_path.exists(), f"Tactic '{tactic}' references non-existent playbook: {pb_path}"

    for tech, rel_path in _TECHNIQUE_PLAYBOOK_MAP.items():
        pb_path = repo_root / "aegis" / rel_path
        assert pb_path.exists(), f"Technique '{tech}' references non-existent playbook: {pb_path}"
