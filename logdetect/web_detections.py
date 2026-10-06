"""Detection rules for web server access logs.

Unlike the SSH rules, which count events over time, these are SIGNATURE
rules: each request is checked against patterns that only show up in attacks.
"""

import re
from collections import defaultdict
from typing import Iterable, List
from urllib.parse import unquote_plus

from .models import Alert, WebRequest

# Fragments of SQL that have no business appearing in a URL.
SQL_INJECTION = re.compile(
    r"union\s+(all\s+)?select"
    r"|'\s*or\s+'?\d+'?\s*=\s*'?\d+"     # ' OR 1=1   /   ' OR '1'='1
    r"|\bsleep\s*\(\s*\d+\s*\)"          # time-based blind injection
    r"|information_schema"
    r"|;\s*drop\s+table",
    re.IGNORECASE,
)

# Attempts to climb out of the web root or read well-known sensitive files.
PATH_TRAVERSAL = re.compile(
    r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini",
    re.IGNORECASE,
)

# Tools that announce themselves in the User-Agent header.
SCANNER_USER_AGENT = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|nuclei",
    re.IGNORECASE,
)

# name -> (severity, ATT&CK id, ATT&CK name, human label)
RULES = {
    "web_sql_injection": (
        "high", "T1190", "Exploit Public-Facing Application", "SQL injection",
    ),
    "web_path_traversal": (
        "high", "T1190", "Exploit Public-Facing Application", "Path traversal",
    ),
    "web_scanner": (
        "medium", "T1595.002", "Active Scanning: Vulnerability Scanning",
        "Scanning tool",
    ),
}


def classify(request: WebRequest) -> List[str]:
    """Return the names of every rule this single request matches."""
    # Attackers URL-encode payloads (%27 for ', %20 for space) to slip past
    # naive filters, so decode before matching.
    path = unquote_plus(request.path)

    matches = []
    if SQL_INJECTION.search(path):
        matches.append("web_sql_injection")
    if PATH_TRAVERSAL.search(path):
        matches.append("web_path_traversal")
    if SCANNER_USER_AGENT.search(request.user_agent):
        matches.append("web_scanner")
    return matches


def run_all_web(requests: Iterable[WebRequest]) -> List[Alert]:
    """Check every request, then raise ONE alert per attacker IP per rule.

    Grouping matters: a scanner sends hundreds of requests, and an analyst
    wants one alert saying so, not hundreds of near-identical ones.
    """
    hits = defaultdict(list)
    for request in sorted(requests, key=lambda r: r.timestamp):
        for rule in classify(request):
            hits[(rule, request.source_ip)].append(request)

    alerts = []
    for (rule, ip), matched in hits.items():
        severity, mitre_id, mitre_name, label = RULES[rule]
        succeeded = sum(1 for r in matched if r.status == 200)

        if rule == "web_scanner":
            detail = f"user agent '{matched[0].user_agent}'"
        else:
            detail = f"e.g. {unquote_plus(matched[0].path)}"
        description = f"{label}: {len(matched)} requests, {detail}"
        if succeeded and rule != "web_scanner":
            description += f" ({succeeded} returned HTTP 200 - check for impact)"

        alerts.append(Alert(
            rule=rule,
            severity=severity,
            mitre_id=mitre_id,
            mitre_name=mitre_name,
            source_ip=ip,
            description=description,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            event_count=len(matched),
        ))

    severity_order = {"critical": 0, "high": 1, "medium": 2}
    return sorted(alerts, key=lambda a: (severity_order[a.severity], a.first_seen))
