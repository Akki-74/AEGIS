"""
tests.test_public_dataset — End-to-end evaluation of public datasets (OTRF / EVTX-ATTACK-SAMPLES).

Validates that:
1. Public telemetry samples run through AEGIS detection rules without modification.
2. Detections produce valid, normalized Alert objects with correct ATT&CK mappings.
3. The in-memory correlation engine successfully links cross-host alerts into ranked attack chains.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from aegis.correlate.engine import CorrelationEngine
from aegis.correlate.schema import Alert
from aegis.eval.rule_evaluator import evaluate_detection_block

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
DATASET_PATH = Path(__file__).resolve().parent / "fixtures" / "public_datasets" / "otrf_attack_sample.json"


def test_public_dataset_detection_and_correlation_end_to_end() -> None:
    """Run public OTRF / EVTX-ATTACK-SAMPLES dataset through detection rules and correlation engine."""
    # 1. Load public dataset
    with DATASET_PATH.open("r", encoding="utf-8") as f:
        events = json.load(f)
    assert len(events) >= 5, "Public dataset must contain multiple event steps"

    # 2. Load all Sigma rules
    rules = []
    for rule_path in RULES_DIR.rglob("*.yml"):
        with rule_path.open("r", encoding="utf-8") as f:
            rules.append((rule_path.stem, yaml.safe_load(f)))

    # 3. Match events against rules
    generated_alerts: list[Alert] = []
    for event in events:
        for rule_stem, rule_def in rules:
            if evaluate_detection_block(rule_def["detection"], event):
                tags = rule_def.get("tags", [])
                technique = next((t.split("attack.")[1].upper() for t in tags if "attack.t" in t), "")
                tactic = next((t.split("attack.")[1] for t in tags if not t.startswith("attack.t")), "execution")
                
                alert_dict = {
                    "rule_id": rule_def.get("id", rule_stem),
                    "rule_name": rule_def.get("title", rule_stem),
                    "mitre_technique": technique,
                    "mitre_tactic": tactic,
                    "timestamp": event.get("TimeCreated"),
                    "hostname": event.get("Computer", "UNKNOWN"),
                    "username": event.get("User") or event.get("TargetUserName") or "SYSTEM",
                    "process_guid": event.get("ProcessGuid") or event.get("SourceProcessGuid"),
                    "parent_process_guid": event.get("ParentProcessGuid"),
                    "logon_id": event.get("LogonId"),
                    "source_ip": event.get("IpAddress"),
                    "dest_ip": event.get("DestIp"),
                    "severity": rule_def.get("level", "medium"),
                    "raw_event": event,
                }
                generated_alerts.append(Alert.from_dict(alert_dict))

    # 4. Verify detection accuracy
    assert len(generated_alerts) >= 5, f"Expected >= 5 rule detections, got {len(generated_alerts)}"
    detected_techniques = {a.mitre_technique for a in generated_alerts}
    assert "T1105" in detected_techniques or any("1105" in t for t in detected_techniques)
    assert "T1003.001" in detected_techniques or any("1003" in t for t in detected_techniques)
    assert "T1558.003" in detected_techniques or any("1558" in t for t in detected_techniques)

    # 5. Run Correlation Engine
    engine = CorrelationEngine()
    incidents = engine.process(generated_alerts)

    assert len(incidents) >= 1, "Should correlate detected alerts into at least 1 incident"
    top_incident = incidents[0]

    # Verify incident characteristics
    assert top_incident.score >= 0.45
    all_hosts = {h for inc in incidents for h in inc.hosts}
    assert len(all_hosts) >= 2, f"Expected cross-host blast radius, got {all_hosts}"
    assert len(top_incident.playbook_recommendations) >= 1
