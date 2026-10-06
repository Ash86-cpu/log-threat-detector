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
