"""Tests for web access log parsing and the web detection rules."""

from datetime import datetime
from pathlib import Path

from logdetect.parser import parse_web_line, parse_web_log
from logdetect.web_detections import classify, run_all_web

SAMPLE_LOG = Path(__file__).parent.parent / "samples" / "access.log"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/130.0"


def make_line(path, ip="203.0.113.77", status=200, user_agent=BROWSER):
    return (
        f'{ip} - - [06/Oct/2026:12:00:00 +0000] "GET {path} HTTP/1.1" '
        f'{status} 512 "-" "{user_agent}"'
    )


def request_for(path, **kwargs):
    return parse_web_line(make_line(path, **kwargs))


# --- parsing ---------------------------------------------------------------

def test_access_line_is_parsed():
    request = request_for("/products?category=shoes", ip="198.51.100.14")

    assert request.source_ip == "198.51.100.14"
    assert request.method == "GET"
    assert request.path == "/products?category=shoes"
    assert request.status == 200
    assert request.user_agent == BROWSER
    assert request.timestamp == datetime(2026, 10, 6, 12, 0, 0)


def test_non_access_lines_are_ignored():
    assert parse_web_line("") is None
    assert parse_web_line("Oct  6 09:14:02 web01 sshd[1]: Failed password for root") is None


# --- signatures ------------------------------------------------------------

def test_sql_injection_is_detected():
    assert classify(request_for("/item?id=1 UNION SELECT NULL,NULL--".replace(" ", "+"))) == ["web_sql_injection"]


def test_url_encoded_sql_injection_is_detected():
    # %27 is a quote and %20 a space: the payload is ' OR '1'='1
    request = request_for("/item?id=1%27%20OR%20%271%27%3D%271")

    assert classify(request) == ["web_sql_injection"]


def test_path_traversal_is_detected():
    assert classify(request_for("/download?file=../../../../etc/passwd")) == ["web_path_traversal"]
    assert classify(request_for("/download?file=..%2F..%2Fetc%2Fpasswd")) == ["web_path_traversal"]


def test_scanner_user_agent_is_detected():
    request = request_for("/admin/", user_agent="Mozilla/5.00 (Nikto/2.5.0)")

    assert classify(request) == ["web_scanner"]


def test_ordinary_requests_are_not_flagged():
    for path in ["/", "/products?category=shoes", "/static/site.css", "/account"]:
        assert classify(request_for(path)) == []


def test_innocent_words_are_not_sql_injection():
    # "select" and "union" are ordinary English words. A rule that fires on
    # them alone would bury analysts in false positives.
    assert classify(request_for("/search?q=select+a+plan")) == []
    assert classify(request_for("/search?q=credit+union+rates")) == []


# --- alerts ----------------------------------------------------------------

def test_many_requests_from_one_ip_become_one_alert():
    requests = [request_for(f"/page{i}", user_agent="sqlmap/1.8") for i in range(50)]
    alerts = run_all_web(requests)

    assert len(alerts) == 1
    assert alerts[0].rule == "web_scanner"
    assert alerts[0].event_count == 50


def test_no_requests_means_no_alerts():
    assert run_all_web([]) == []


def test_sample_log_end_to_end():
    requests = list(parse_web_log(SAMPLE_LOG))
    alerts = run_all_web(requests)

    assert len(requests) == 27
    assert [(a.rule, a.source_ip) for a in alerts] == [
        ("web_sql_injection", "203.0.113.77"),
        ("web_path_traversal", "203.0.113.88"),
        ("web_scanner", "203.0.113.77"),
        ("web_scanner", "203.0.113.120"),
    ]


def test_legitimate_visitors_in_sample_log_raise_nothing():
    flagged = {a.source_ip for a in run_all_web(parse_web_log(SAMPLE_LOG))}

    assert "198.51.100.14" not in flagged
    assert "198.51.100.30" not in flagged
