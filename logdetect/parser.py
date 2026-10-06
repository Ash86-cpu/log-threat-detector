"""Turn raw log lines into structured Event objects."""

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from .models import Event

# Matches OpenSSH authentication lines such as:
#   Oct  6 09:14:02 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 40112 ssh2
#   Oct  6 09:14:09 web01 sshd[2215]: Failed password for invalid user admin from 203.0.113.50 port 40120 ssh2
#   Oct  6 09:20:11 web01 sshd[2301]: Accepted publickey for alice from 198.51.100.7 port 51022 ssh2
SSH_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "  # Oct  6 09:14:02
    r"\S+ "                                                 # hostname
    r"sshd\[\d+\]: "                                        # process name and PID
    r"(?P<result>Failed|Accepted) \S+ for "                 # outcome and auth method
    r"(?:invalid user )?"                                   # present if the account doesn't exist
    r"(?P<username>\S+) from (?P<ip>\S+) port \d+"
)

ACTIONS = {"Failed": "login_failed", "Accepted": "login_success"}


def parse_ssh_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Parse one line of an SSH auth log. Returns None if it isn't a login attempt.

    Syslog timestamps don't include a year, so we have to supply one.
    It defaults to the current year.
    """
    match = SSH_AUTH_PATTERN.match(line)
    if match is None:
        return None

    year = year or datetime.now().year
    timestamp = datetime.strptime(
        f"{year} {match['timestamp']}", "%Y %b %d %H:%M:%S"
    )
    return Event(
        timestamp=timestamp,
        source="ssh",
        action=ACTIONS[match["result"]],
        source_ip=match["ip"],
        username=match["username"],
        raw=line.rstrip("\n"),
    )


def parse_ssh_log(path: Path, year: Optional[int] = None) -> Iterator[Event]:
    """Yield an Event for every login attempt in an SSH auth log file.

    Reads line by line instead of loading the whole file, because real
    auth logs can be gigabytes in size.
    """
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_ssh_line(line, year)
            if event is not None:
                yield event
