"""Tests for the log parser: does each kind of line become the right Event?"""

from datetime import datetime
from pathlib import Path

from logdetect.parser import parse_ssh_line, parse_ssh_log

SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "auth.log"


def test_failed_password_is_parsed():
    line = "Oct  6 09:14:02 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 40112 ssh2"
    event = parse_ssh_line(line, year=2026)

    assert event.action == "login_failed"
    assert event.username == "root"
    assert event.source_ip == "203.0.113.50"
    assert event.timestamp == datetime(2026, 10, 6, 9, 14, 2)


def test_invalid_user_keeps_the_real_username():
    # "invalid user" is sshd's note that the account doesn't exist.
    # The username is "admin", not "invalid".
    line = "Oct  6 10:03:00 web01 sshd[2400]: Failed password for invalid user admin from 203.0.113.99 port 33000 ssh2"
    event = parse_ssh_line(line, year=2026)

    assert event.username == "admin"
    assert event.action == "login_failed"


def test_accepted_publickey_is_a_success():
    line = "Oct  6 08:02:00 web01 sshd[1801]: Accepted publickey for alice from 198.51.100.7 port 51022 ssh2"
    event = parse_ssh_line(line, year=2026)

    assert event.action == "login_success"
    assert event.username == "alice"


def test_two_digit_day_is_parsed():
    line = "Dec 25 23:59:59 web01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2"
    event = parse_ssh_line(line, year=2026)

    assert event.timestamp == datetime(2026, 12, 25, 23, 59, 59)


def test_unrelated_lines_are_ignored():
    assert parse_ssh_line("Oct  6 08:05:00 web01 CRON[1810]: session opened for user root") is None
    assert parse_ssh_line("") is None
    assert parse_ssh_line("complete garbage") is None


def test_raw_line_is_kept_as_evidence():
    line = "Oct  6 09:14:02 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 40112 ssh2\n"
    event = parse_ssh_line(line, year=2026)

    assert event.raw == line.rstrip("\n")


def test_sample_log_event_counts():
    events = list(parse_ssh_log(SAMPLE_LOG, year=2026))

    assert len(events) == 31
    assert sum(e.action == "login_failed" for e in events) == 27
    assert sum(e.action == "login_success" for e in events) == 4
