"""Tests for the detection rules.

Each rule gets at least one test that it FIRES on an attack and one that it
STAYS QUIET on normal behaviour. The second kind matters just as much: a rule
that alerts on everything is useless to an analyst.
"""

from datetime import datetime, timedelta
from pathlib import Path

from logdetect.detections import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
    run_all,
)
from logdetect.models import Event
from logdetect.parser import parse_ssh_log

SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "auth.log"
START = datetime(2026, 10, 6, 9, 0, 0)


def make_event(seconds, action="login_failed", ip="203.0.113.50", username="root"):
    """Build a fake Event `seconds` after START, so tests don't need log files."""
    return Event(
        timestamp=START + timedelta(seconds=seconds),
        source="ssh",
        action=action,
        source_ip=ip,
        username=username,
        raw="",
    )


# --- brute force -----------------------------------------------------------

def test_brute_force_fires_at_threshold():
    events = [make_event(i) for i in range(5)]
    alerts = detect_brute_force(events, threshold=5)

    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1110.001"
    assert alerts[0].source_ip == "203.0.113.50"
    assert alerts[0].event_count == 5


def test_brute_force_quiet_below_threshold():
    events = [make_event(i) for i in range(4)]

    assert detect_brute_force(events, threshold=5) == []


def test_brute_force_quiet_when_failures_are_spread_out():
    # 5 failures, but an hour apart: a forgetful user, not an attack.
    events = [make_event(i * 3600) for i in range(5)]

    assert detect_brute_force(events, threshold=5, window=timedelta(minutes=5)) == []


def test_brute_force_does_not_combine_different_ips():
    events = [make_event(i, ip=f"203.0.113.{i}") for i in range(10)]

    assert detect_brute_force(events, threshold=5) == []


# --- password spraying -----------------------------------------------------

def test_spraying_fires_on_many_usernames():
    users = ["admin", "test", "oracle", "git", "ubuntu"]
    events = [make_event(i * 10, username=user) for i, user in enumerate(users)]
    alerts = detect_password_spraying(events, min_usernames=5)

    assert len(alerts) == 1
    assert alerts[0].mitre_id == "T1110.003"


def test_spraying_quiet_when_one_account_is_hammered():
    # Many failures but only one username: that is brute force, not spraying.
    events = [make_event(i) for i in range(20)]

    assert detect_password_spraying(events, min_usernames=5) == []


def test_spraying_is_missed_by_brute_force_rule():
    # The reason spraying needs its own rule: one attempt per account
    # never reaches a per-account threshold.
    users = ["admin", "test", "oracle", "git", "ubuntu", "deploy"]
    events = [make_event(i * 10, username=user) for i, user in enumerate(users)]

    assert detect_brute_force(events, threshold=5) == []
    assert len(detect_password_spraying(events, min_usernames=5)) == 1


# --- success after failures ------------------------------------------------

def test_success_after_failures_fires():
    events = [make_event(i) for i in range(4)]
    events.append(make_event(10, action="login_success"))
    alerts = detect_success_after_failures(events, min_failures=3)

    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].mitre_id == "T1078"


def test_single_typo_then_success_is_not_an_alert():
    # The classic false positive: a real user mistypes once, then gets in.
    events = [make_event(0), make_event(15, action="login_success")]

    assert detect_success_after_failures(events, min_failures=3) == []


def test_success_from_a_different_ip_is_not_linked():
    events = [make_event(i, ip="203.0.113.50") for i in range(5)]
    events.append(make_event(10, action="login_success", ip="198.51.100.7"))

    assert detect_success_after_failures(events, min_failures=3) == []


def test_old_failures_do_not_count():
    events = [make_event(i) for i in range(5)]
    events.append(make_event(7200, action="login_success"))  # two hours later

    assert detect_success_after_failures(
        events, min_failures=3, window=timedelta(minutes=10)
    ) == []


# --- everything together ---------------------------------------------------

def test_no_events_means_no_alerts():
    assert run_all([]) == []


def test_sample_log_end_to_end():
    alerts = run_all(parse_ssh_log(SAMPLE_LOG, year=2026))

    assert [a.rule for a in alerts] == [
        "ssh_success_after_failures",   # critical sorts first
        "ssh_brute_force",
        "ssh_password_spraying",
        "ssh_brute_force",
    ]
    assert alerts[0].source_ip == "192.0.2.44"


def test_legitimate_users_in_sample_log_raise_nothing():
    alerts = run_all(parse_ssh_log(SAMPLE_LOG, year=2026))
    flagged_ips = {a.source_ip for a in alerts}

    assert "198.51.100.7" not in flagged_ips    # alice, key-based logins
    assert "198.51.100.23" not in flagged_ips   # bob, one typo
