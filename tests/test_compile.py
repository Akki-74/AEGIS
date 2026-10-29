"""
tests.test_compile — Tests for Sigma rule compilation.
"""

from __future__ import annotations

from pathlib import Path
from aegis.pipelines.compile import RuleCompiler

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def test_native_compile_single_rule() -> None:
    """Verify that native compiler can compile a Sigma rule to Lucene/ES query."""
    rule_file = RULES_DIR / "credential_access" / "lsass_memory_access.yml"
    compiler = RuleCompiler(pipeline_name="sysmon_ecs")
    query = compiler.compile_rule(rule_file, backend="elasticsearch")

    assert isinstance(query, str)
    assert len(query) > 0
    assert "lsass.exe" in query


def test_compile_all_rules() -> None:
    """Verify that all rules can be compiled into a dictionary of queries."""
    compiler = RuleCompiler(pipeline_name="sysmon_ecs")
    compiled = compiler.compile_all(RULES_DIR, backend="elasticsearch")

    assert len(compiled) == 13
    for path, query in compiled.items():
        assert isinstance(query, str)
        assert len(query) > 0
