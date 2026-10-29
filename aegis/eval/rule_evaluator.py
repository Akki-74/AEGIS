"""
aegis.eval.rule_evaluator
=========================

Lightweight, high-performance in-memory Sigma rule evaluator.
Evaluates atomic Sigma rule detections against structured event dictionaries
for fast unit testing without requiring an external SIEM or Elasticsearch cluster.
"""

from __future__ import annotations

import re
from typing import Any


def _match_field(event_val: Any, expected_val: Any, modifier: str | None = None) -> bool:
    """Evaluate a single field against expected criteria taking modifiers into account."""
    if event_val is None:
        return False

    str_val = str(event_val).lower()

    if modifier == "endswith":
        if isinstance(expected_val, list):
            return any(str_val.endswith(str(x).lower()) for x in expected_val)
        return str_val.endswith(str(expected_val).lower())

    if modifier == "startswith":
        if isinstance(expected_val, list):
            return any(str_val.startswith(str(x).lower()) for x in expected_val)
        return str_val.startswith(str(expected_val).lower())

    if modifier == "contains":
        if isinstance(expected_val, list):
            return any(str(x).lower() in str_val for x in expected_val)
        return str(expected_val).lower() in str_val

    # Exact or set inclusion match
    if isinstance(expected_val, list):
        expected_strs = [str(x).lower() for x in expected_val]
        return str_val in expected_strs

    return str_val == str(expected_val).lower()


def evaluate_detection_block(detection_def: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a Sigma detection block against a single event dict."""
    condition_expr = detection_def.get("condition", "")
    if not condition_expr:
        return False

    named_results: dict[str, bool] = {}

    for name, block in detection_def.items():
        if name == "condition":
            continue

        if not isinstance(block, dict):
            continue

        block_matches = True
        for raw_field, expected in block.items():
            if "|" in raw_field:
                field_name, modifier = raw_field.split("|", 1)
            else:
                field_name, modifier = raw_field, None

            event_val = event.get(field_name)
            if not _match_field(event_val, expected, modifier):
                block_matches = False
                break

        named_results[name] = block_matches

    # Evaluate simple Sigma boolean condition expressions:
    # e.g., "selection and not filter" or "selection_1 and selection_2 and not filter"
    eval_env = {k: v for k, v in named_results.items()}

    # Clean condition string to python boolean expression
    cleaned_expr = condition_expr.strip()
    # Replace identifiers with eval_env lookups
    tokens = re.split(r"(\s+|\(|\)|\band\b|\bor\b|\bnot\b)", cleaned_expr)
    py_tokens = []
    for t in tokens:
        stripped = t.strip()
        if stripped in named_results:
            py_tokens.append(f"eval_env['{stripped}']")
        elif stripped in ("and", "or", "not", "(", ")"):
            py_tokens.append(stripped)
        elif not stripped:
            py_tokens.append(t)
        else:
            py_tokens.append(f"eval_env.get('{stripped}', False)")

    py_expr = "".join(py_tokens)
    try:
        return bool(eval(py_expr, {"__builtins__": None, "eval_env": eval_env}))
    except Exception:
        # Fallback heuristic: selection is true and all filters are false
        selections = [v for k, v in named_results.items() if not k.startswith("filter")]
        filters = [v for k, v in named_results.items() if k.startswith("filter")]
        return all(selections) and not any(filters)
