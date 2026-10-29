"""
tests.test_rules — Validate Sigma detection rule standards and structure.

Enforces:
1. Every rule has required fields (title, id, status, description, author, date,
   modified, logsource, detection, falsepositives, level).
2. Every rule has at least one MITRE ATT&CK tag.
3. Every rule ID is a valid UUID.
4. All rule IDs are unique across the repository.
5. Every rule has a 'condition' inside detection.
"""

from __future__ import annotations

import unittest
import uuid
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
RULE_FILES = sorted(RULES_DIR.rglob("*.yml"))

REQUIRED_FIELDS = [
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
]


class TestSigmaRules(unittest.TestCase):
    """Validation test suite for all Sigma rules."""

    def test_rule_files_exist(self) -> None:
        """Ensure at least 10 Sigma rules are present in the repository."""
        self.assertGreaterEqual(
            len(RULE_FILES), 10, f"Expected >= 10 rules, found {len(RULE_FILES)}"
        )

    def test_all_rules_have_required_fields(self) -> None:
        """Verify each Sigma rule has all mandatory metadata fields."""
        for rule_path in RULE_FILES:
            with self.subTest(rule=rule_path.name):
                with rule_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                self.assertIsInstance(
                    data, dict, f"Rule {rule_path.name} is not a valid YAML mapping"
                )
                for field in REQUIRED_FIELDS:
                    self.assertIn(
                        field,
                        data,
                        f"Rule {rule_path.name} missing required field '{field}'",
                    )

    def test_all_rules_have_valid_uuids(self) -> None:
        """Verify rule ID is a valid UUID string."""
        for rule_path in RULE_FILES:
            with self.subTest(rule=rule_path.name):
                with rule_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                rule_id = str(data.get("id", ""))
                try:
                    val = uuid.UUID(rule_id)
                    self.assertEqual(str(val), rule_id.lower())
                except ValueError:
                    self.fail(f"Rule {rule_path.name} has invalid UUID: '{rule_id}'")

    def test_all_rules_have_attack_tags(self) -> None:
        """Verify each rule is tagged with at least one MITRE ATT&CK reference."""
        for rule_path in RULE_FILES:
            with self.subTest(rule=rule_path.name):
                with rule_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                tags = data.get("tags", [])
                self.assertIsInstance(tags, list)
                self.assertGreater(len(tags), 0)
                has_attack = any(str(t).lower().startswith("attack.") for t in tags)
                self.assertTrue(has_attack, f"Rule {rule_path.name} has no 'attack.*' MITRE tags")

    def test_rule_detection_condition(self) -> None:
        """Verify detection block has a condition string."""
        for rule_path in RULE_FILES:
            with self.subTest(rule=rule_path.name):
                with rule_path.open("r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                detection = data.get("detection", {})
                self.assertIn(
                    "condition",
                    detection,
                    f"Rule {rule_path.name} missing 'condition' in detection",
                )

    def test_unique_rule_ids(self) -> None:
        """Verify all rule IDs are globally unique across the entire rules/ directory."""
        seen_ids: dict[str, str] = {}
        for rule_path in RULE_FILES:
            with rule_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rule_id = str(data.get("id", ""))
            self.assertNotIn(
                rule_id,
                seen_ids,
                f"Duplicate rule ID '{rule_id}' found in {rule_path.name} and {seen_ids.get(rule_id)}",
            )
            seen_ids[rule_id] = rule_path.name


if __name__ == "__main__":
    unittest.main()
