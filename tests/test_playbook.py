"""Tests for the response playbook.

The most important tests here are the SAFETY tests: automation that blocks
the wrong thing can do more damage than the attacker. They prove that an
allowlisted IP is never blocked and a possible compromise always reaches a
human, whatever threat intel says.
"""

import json
from datetime import datetime
from pathlib import Path

from logdetect.models import Alert
from logdetect.playbook import decide, enrich, load_intel, run_playbook

SAMPLE_INTEL = Path(__file__).parent.parent / "samples" / "threat_intel.json"
INTEL = {
    "allowlist": {"10.0.0.5": "internal scanner"},
    "ips": {
        "203.0.113.50": {"reputation": "malicious", "country": "NL", "tags": ["ssh-bruteforce"]},
        "192.0.2.44": {"reputation": "suspicious", "country": "US", "tags": ["botnet"]},
    },
}


def make_alert(ip="203.0.113.50", severity="high", rule="ssh_brute_force"):
    when = datetime(2026, 10, 6, 9, 0, 0)
    return Alert(rule, severity, "T1110.001", "Brute Force", ip,
                 "test alert", when, when, 5)


# ---- enrich

def test_enrich_known_ip_gets_intel():
    enriched = enrich(make_alert(), INTEL)
    assert enriched.reputation == "malicious"
    assert enriched.country == "NL"
    assert enriched.tags == ("ssh-bruteforce",)


def test_enrich_unknown_ip_gets_defaults():
    enriched = enrich(make_alert(ip="198.51.100.1"), INTEL)
    assert (enriched.reputation, enriched.country, enriched.tags) == ("unknown", "??", ())


def test_enrich_keeps_original_alert():
    alert = make_alert()
    assert enrich(alert, INTEL).alert is alert


def test_enrich_allowlisted_ip():
    enriched = enrich(make_alert(ip="10.0.0.5"), INTEL)
    assert enriched.reputation == "allowlisted"
    assert enriched.note == "internal scanner"


# ---- decide

def verdict(ip, severity="high"):
    return decide(enrich(make_alert(ip=ip, severity=severity), INTEL)).verdict


def test_malicious_ip_is_blocked():
    assert verdict("203.0.113.50") == "block"


def test_unknown_ip_high_severity_goes_to_human():
    assert verdict("198.51.100.1") == "escalate"


def test_suspicious_ip_high_severity_goes_to_human():
    assert verdict("192.0.2.44") == "escalate"


def test_unknown_ip_medium_severity_is_only_monitored():
    assert verdict("198.51.100.1", severity="medium") == "monitor"


# ---- safety

def test_safety_critical_always_escalates_even_if_malicious():
    assert verdict("203.0.113.50", severity="critical") == "escalate"


def test_safety_allowlisted_ip_is_never_blocked():
    for severity in ("medium", "high", "critical"):
        assert verdict("10.0.0.5", severity=severity) == "monitor"


# ---- act

def test_dry_run_writes_nothing(tmp_path):
    result = run_playbook([make_alert()], INTEL, tmp_path / "out", dry_run=True)
    assert result.blocked == ["203.0.113.50"]
    assert not (tmp_path / "out").exists()


def test_real_run_writes_blocklist_incidents_and_audit(tmp_path):
    alerts = [make_alert(), make_alert(ip="198.51.100.1")]
    run_playbook(alerts, INTEL, tmp_path)
    assert (tmp_path / "blocklist.txt").read_text().split() == ["203.0.113.50"]
    incidents = json.loads((tmp_path / "incidents.json").read_text())
    assert incidents[0]["id"] == "INC-0001"
    assert incidents[0]["source_ip"] == "198.51.100.1"
    assert len((tmp_path / "audit.log").read_text().splitlines()) == 2


def test_ip_is_blocked_only_once_across_alerts_and_runs(tmp_path):
    alerts = [make_alert(), make_alert(rule="ssh_password_spraying")]
    first = run_playbook(alerts, INTEL, tmp_path)
    second = run_playbook(alerts, INTEL, tmp_path)
    assert first.blocked == ["203.0.113.50"]
    assert second.blocked == []
    assert (tmp_path / "blocklist.txt").read_text().split() == ["203.0.113.50"]


def test_sample_intel_file_loads():
    intel = load_intel(SAMPLE_INTEL)
    assert "203.0.113.120" in intel["allowlist"]
    assert intel["ips"]["203.0.113.50"]["reputation"] == "malicious"


# ---- recommended steps

def test_escalated_incident_has_recommended_steps(tmp_path):
    alert = Alert("ssh_success_after_failures", "critical", "T1078", "Valid Accounts",
                  "192.0.2.44", "Successful login as 'deploy' after 6 failed attempts",
                  datetime(2026, 10, 6), datetime(2026, 10, 6), 7)
    run_playbook([alert], INTEL, tmp_path)
    steps = json.loads((tmp_path / "incidents.json").read_text())[0]["recommended_steps"]
    assert steps[0] == "Disable or reset the password of the account that logged in ('deploy')"
    assert any("192.0.2.44" in step for step in steps)


def test_unknown_rule_gets_default_steps():
    from logdetect.playbook import recommended_steps
    steps = recommended_steps(make_alert(rule="something_new", ip="198.51.100.1"))
    assert steps == ["Investigate activity from 198.51.100.1", "Decide whether to block 198.51.100.1"]


def test_every_rule_has_recommended_steps():
    from logdetect.playbook import RECOMMENDED_STEPS
    rules = {"ssh_brute_force", "ssh_password_spraying", "ssh_success_after_failures",
             "web_sql_injection", "web_path_traversal", "web_scanner"}
    assert rules <= RECOMMENDED_STEPS.keys()
