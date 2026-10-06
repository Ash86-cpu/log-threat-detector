"""Tests for report formatting."""

import json
from pathlib import Path

from logdetect.detections import run_all
from logdetect.parser import parse_ssh_log
from logdetect.report import filter_by_severity, format_json, format_text

SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "auth.log"


def sample_alerts():
    return run_all(parse_ssh_log(SAMPLE_LOG, year=2026))


def test_json_report_is_valid_json_with_summary():
    report = json.loads(format_json(sample_alerts(), event_count=31))

    assert report["summary"] == {
        "events_parsed": 31,
        "alerts_raised": 4,
        "by_severity": {"critical": 1, "high": 3},
    }
    assert report["alerts"][0]["first_seen"] == "2026-10-06T11:41:00"


def test_severity_filter_keeps_only_critical():
    alerts = filter_by_severity(sample_alerts(), "critical")

    assert [a.severity for a in alerts] == ["critical"]


def test_text_report_mentions_every_alert():
    alerts = sample_alerts()
    text = format_text(alerts, event_count=31)

    assert "raised 4 alerts" in text
    for alert in alerts:
        assert alert.source_ip in text
        assert alert.mitre_id in text
