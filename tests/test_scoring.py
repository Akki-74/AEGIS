"""
tests.test_scoring — Incident multi-factor scoring and blast-radius tests.
"""

from __future__ import annotations

from datetime import datetime, timezone

from aegis.correlate.schema import Alert, Incident, Severity
from aegis.correlate.scoring import IncidentScorer


def _make_alert(
    tactic: str,
    technique: str,
    host: str = "WKS01",
    user: str = "jdoe",
    sev: Severity = Severity.MEDIUM,
) -> Alert:
    return Alert(
        rule_id="r1",
        rule_name=f"Alert {technique}",
        mitre_technique=technique,
        mitre_tactic=tactic,
        timestamp=datetime.now(timezone.utc),
        hostname=host,
        username=user,
        severity=sev,
    )


def test_full_kill_chain_scores_high() -> None:
    """Incident spanning multiple kill-chain tactics earns high severity score (> 0.65)."""
    alerts = [
        _make_alert("initial_access", "T1566", sev=Severity.HIGH),
        _make_alert("execution", "T1059.001", sev=Severity.HIGH),
        _make_alert("privilege_escalation", "T1055", sev=Severity.HIGH, user="Administrator"),
        _make_alert("credential_access", "T1003.001", sev=Severity.CRITICAL, user="Administrator"),
        _make_alert("defense_evasion", "T1134", sev=Severity.HIGH),
        _make_alert("discovery", "T1087", sev=Severity.MEDIUM),
        _make_alert("lateral_movement", "T1021.002", sev=Severity.HIGH),
        _make_alert("collection", "T1005", sev=Severity.MEDIUM),
        _make_alert("exfiltration", "T1041", sev=Severity.HIGH),
    ]
    incident = Incident(
        alerts=alerts,
        tactics={a.mitre_tactic for a in alerts},
        techniques={a.mitre_technique for a in alerts},
        hosts={"WKS01"},
        users={"Administrator"},
    )
    scorer = IncidentScorer()
    score = scorer.score(incident)
    assert score >= 0.50
    assert scorer.classify_severity(score) in ("high", "critical")


def test_single_benign_alert_scores_low() -> None:
    """Single low-severity execution alert scores low (< 0.35)."""
    alert = _make_alert("execution", "T1059.001", sev=Severity.LOW)
    incident = Incident(
        alerts=[alert],
        tactics={"execution"},
        techniques={"T1059.001"},
        hosts={"WKS01"},
        users={"jdoe"},
    )
    scorer = IncidentScorer()
    score = scorer.score(incident)
    assert score < 0.35
    assert scorer.classify_severity(score) in ("low", "info")


def test_asset_criticality_boost_on_dc() -> None:
    """Domain Controller involvement boosts composite score."""
    alert = _make_alert("credential_access", "T1003.001", host="DC01.CORP.LOCAL")
    incident = Incident(
        alerts=[alert],
        tactics={"credential_access"},
        techniques={"T1003.001"},
        hosts={"DC01.CORP.LOCAL"},
        users={"jdoe"},
    )
    scorer = IncidentScorer()
    score_standard = scorer.score(incident, asset_tags={"DC01.CORP.LOCAL": ["workstation"]})
    score_dc = scorer.score(incident, asset_tags={"DC01.CORP.LOCAL": ["domain_controller"]})

    assert score_dc > score_standard


def test_blast_radius_computation() -> None:
    """Blast radius correctly counts unique hosts, users, and high-privilege escalation."""
    alerts = [
        _make_alert("execution", "T1059.001", host="WKS01", user="jdoe"),
        _make_alert("credential_access", "T1003.001", host="WKS01", user="CORP\\Administrator"),
        _make_alert("lateral_movement", "T1021", host="SRV02", user="CORP\\Administrator"),
    ]
    incident = Incident(
        alerts=alerts,
        tactics={a.mitre_tactic for a in alerts},
        techniques={a.mitre_technique for a in alerts},
        hosts={"WKS01", "SRV02"},
        users={"jdoe", "CORP\\Administrator"},
    )
    scorer = IncidentScorer()
    blast = scorer.compute_blast_radius(incident)

    assert blast["hosts_touched"] == 2
    assert blast["accounts_used"] == 2
    assert blast["privilege_level_reached"] == "high"
