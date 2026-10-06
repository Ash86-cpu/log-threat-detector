"""Turn a list of Alerts into output: text for humans, JSON for machines."""

import json
from collections import Counter
from dataclasses import asdict
from typing import List

from .models import Alert

SEVERITY_ORDER = ["critical", "high", "medium"]


def filter_by_severity(alerts: List[Alert], minimum: str) -> List[Alert]:
    """Keep only alerts at or above the given severity."""
    allowed = SEVERITY_ORDER[: SEVERITY_ORDER.index(minimum) + 1]
    return [alert for alert in alerts if alert.severity in allowed]


def format_text(alerts: List[Alert], event_count: int) -> str:
    """A report for an analyst reading in a terminal."""
    lines = [f"Parsed {event_count} login events, raised {len(alerts)} alerts", ""]
    for alert in alerts:
        lines += [
            f"[{alert.severity.upper()}] {alert.rule}  ({alert.mitre_id} {alert.mitre_name})",
            f"  source ip : {alert.source_ip}",
            f"  what      : {alert.description}",
            f"  when      : {alert.first_seen:%b %d %H:%M:%S} to {alert.last_seen:%H:%M:%S}",
            "",
        ]
    return "\n".join(lines)


def format_json(alerts: List[Alert], event_count: int) -> str:
    """A report another program can consume, e.g. a SIEM or a ticketing system."""
    counts = Counter(alert.severity for alert in alerts)
    report = {
        "summary": {
            "events_parsed": event_count,
            "alerts_raised": len(alerts),
            "by_severity": {s: counts[s] for s in SEVERITY_ORDER if counts[s]},
        },
        "alerts": [
            {
                **asdict(alert),
                # datetime objects aren't valid JSON, so convert to ISO 8601 text
                "first_seen": alert.first_seen.isoformat(),
                "last_seen": alert.last_seen.isoformat(),
            }
            for alert in alerts
        ],
    }
    return json.dumps(report, indent=2)
