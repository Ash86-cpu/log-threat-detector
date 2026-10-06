"""Data structures shared by the parser and the detection rules."""

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    """One security-relevant thing that happened, extracted from one log line.

    Every log format gets normalised into this shape, so detection rules
    never need to know what the original log line looked like.
    """

    timestamp: datetime
    source: str      # which log it came from, e.g. "ssh"
    action: str      # what happened: "login_failed" or "login_success"
    source_ip: str   # who did it
    username: str    # the account they targeted
    raw: str         # the original line, kept as evidence for the analyst


@dataclass(frozen=True)
class Alert:
    """A detection rule's verdict that something suspicious happened."""

    rule: str             # short machine-readable rule name
    severity: str         # "medium", "high" or "critical"
    mitre_id: str         # MITRE ATT&CK technique ID, e.g. "T1110.001"
    mitre_name: str       # human-readable technique name
    source_ip: str
    description: str      # one sentence an analyst can act on
    first_seen: datetime
    last_seen: datetime
    event_count: int
