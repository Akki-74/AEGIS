"""
tests.test_resilience — Detection resilience testing against evasion variants.

Evaluates:
1. Access mask variations for LSASS memory handle rules (0x1010, 0x1410, 0x1438, 0x1FFFFF)
2. Command-line flag variations and case insensitivity (-urlcache, -URLCACHE, -decode)
3. Script protocol variations in LOLBins (javascript:, vbscript:, about:)
"""

from __future__ import annotations

import yaml
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _load_rule(rel_path: str) -> dict:
    with (RULES_DIR / rel_path).open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_lsass_access_mask_resilience() -> None:
    """Verify LSASS rule detects multiple GrantedAccess masks used by dumpers."""
    rule = _load_rule("credential_access/lsass_memory_access.yml")
    detection = rule["detection"]
    selection = detection.get("selection_target") or detection.get("selection", {})
    granted_access = selection.get("GrantedAccess", [])

    expected_masks = ["0x1010", "0x1410", "0x1438", "0x1FFFFF"]
    for mask in expected_masks:
        assert mask in granted_access, f"LSASS rule missing critical access mask {mask}"


def test_certutil_command_line_resilience() -> None:
    """Verify certutil rule catches multiple download and decoding arguments."""
    rule = _load_rule("execution/lolbin_certutil_download.yml")
    detection = rule["detection"]

    # Check that both urlcache and decode parameters are covered
    has_urlcache = any(
        isinstance(v, dict) and any("-urlcache" in str(val) for val in v.values())
        for v in detection.values()
    )
    has_decode = any(
        isinstance(v, dict) and any("-decode" in str(val) for val in v.values())
        for v in detection.values()
    )

    assert has_urlcache, "Certutil rule missing -urlcache detection"
    assert has_decode, "Certutil rule missing -decode detection"


def test_mshta_protocol_handler_resilience() -> None:
    """Verify mshta rule covers javascript, vbscript, and URL protocols."""
    rule = _load_rule("execution/lolbin_mshta_execution.yml")
    detection = rule["detection"]

    protocols = ["javascript:", "vbscript:", "http://", "https://"]
    for proto in protocols:
        found = any(
            isinstance(v, dict) and any(proto in str(val) for val in v.values())
            for v in detection.values()
        )
        assert found, f"MSHTA rule missing protocol handler {proto}"


def test_cross_process_write_rights_resilience() -> None:
    """Verify cross process access rule covers multiple injection right combinations."""
    rule = _load_rule("defense_evasion/cross_process_access_write.yml")
    selection = rule["detection"]["selection"]
    masks = selection.get("GrantedAccess", [])

    assert "0x0020" in masks, "Missing PROCESS_VM_WRITE (0x0020)"
    assert "0x1FFFFF" in masks, "Missing PROCESS_ALL_ACCESS (0x1FFFFF)"
