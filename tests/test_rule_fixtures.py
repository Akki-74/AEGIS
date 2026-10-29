"""
tests.test_rule_fixtures — Enforce positive and negative fixture tests for every rule.

Enforces:
1. Every Sigma rule in rules/ has a matching <stem>_positive.json fixture.
2. Every Sigma rule in rules/ has a matching <stem>_negative.json fixture.
3. The positive fixture MUST trigger the rule's detection block.
4. The negative fixture MUST NOT trigger the rule's detection block.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from aegis.eval.rule_evaluator import evaluate_detection_block

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
RULE_FILES = sorted(RULES_DIR.rglob("*.yml"))
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "rules"


def test_every_rule_has_positive_and_negative_fixtures() -> None:
    """Every rule must have both a positive and negative fixture in tests/fixtures/rules/."""
    assert len(RULE_FILES) >= 13, f"Expected 13 rules, found {len(RULE_FILES)}"

    missing_fixtures: list[str] = []
    for rule_path in RULE_FILES:
        stem = rule_path.stem
        pos_file = FIXTURES_DIR / f"{stem}_positive.json"
        neg_file = FIXTURES_DIR / f"{stem}_negative.json"

        if not pos_file.exists():
            missing_fixtures.append(f"{stem}_positive.json")
        if not neg_file.exists():
            missing_fixtures.append(f"{stem}_negative.json")

    assert not missing_fixtures, f"Missing fixtures: {missing_fixtures}"


def test_positive_fixtures_trigger_rules() -> None:
    """Each positive fixture must evaluate to True against its respective rule."""
    for rule_path in RULE_FILES:
        stem = rule_path.stem
        pos_file = FIXTURES_DIR / f"{stem}_positive.json"
        assert pos_file.exists(), f"Missing positive fixture for {stem}"

        with rule_path.open("r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        with pos_file.open("r", encoding="utf-8") as f:
            event_data = json.load(f)

        matched = evaluate_detection_block(rule_data["detection"], event_data)
        assert matched is True, (
            f"Rule {stem} FAILED to match its positive fixture {pos_file.name}!\n"
            f"Event: {event_data}\n"
            f"Detection: {rule_data['detection']}"
        )


def test_negative_fixtures_do_not_trigger_rules() -> None:
    """Each negative fixture must evaluate to False against its respective rule."""
    for rule_path in RULE_FILES:
        stem = rule_path.stem
        neg_file = FIXTURES_DIR / f"{stem}_negative.json"
        assert neg_file.exists(), f"Missing negative fixture for {stem}"

        with rule_path.open("r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        with neg_file.open("r", encoding="utf-8") as f:
            event_data = json.load(f)

        matched = evaluate_detection_block(rule_data["detection"], event_data)
        assert matched is False, (
            f"Rule {stem} FALSE POSITIVE! Unexpectedly matched negative fixture {neg_file.name}!\n"
            f"Event: {event_data}\n"
            f"Detection: {rule_data['detection']}"
        )
