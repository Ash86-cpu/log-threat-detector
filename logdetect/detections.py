"""Detection rules: each one takes a list of Events and returns Alerts.

Every rule is a threshold over a time window. "5 failures" on its own means
little: 5 failures in a year is normal, 5 in a minute is an attack. The
thresholds are parameters so they can be tuned to an environment.
"""

from collections import defaultdict
from datetime import timedelta
from typing import Iterable, List

from .models import Alert, Event


def _busiest_window(events: List[Event], window: timedelta) -> List[Event]:
    """Return the largest run of events that all fit inside one time window.

    `events` must be sorted by time. Uses a sliding window: `start` chases
    `end` through the list, so each event is visited at most twice.
    """
    best: List[Event] = []
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > len(best):
            best = events[start:end + 1]
    return best


def detect_brute_force(
    events: Iterable[Event],
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> List[Alert]:
    """One IP repeatedly failing to log in to the SAME account.

    MITRE ATT&CK T1110.001 (Brute Force: Password Guessing).
    """
    failures = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.action == "login_failed":
            failures[(event.source_ip, event.username)].append(event)

    alerts = []
    for (ip, username), attempts in failures.items():
        burst = _busiest_window(attempts, window)
        if len(burst) >= threshold:
            seconds = int((burst[-1].timestamp - burst[0].timestamp).total_seconds())
            alerts.append(Alert(
                rule="ssh_brute_force",
                severity="high",
                mitre_id="T1110.001",
                mitre_name="Brute Force: Password Guessing",
                source_ip=ip,
                description=(
                    f"{len(burst)} failed logins for account '{username}' "
                    f"in {seconds}s"
                ),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                event_count=len(burst),
            ))
    return alerts


def detect_password_spraying(
    events: Iterable[Event],
    min_usernames: int = 5,
    window: timedelta = timedelta(minutes=10),
) -> List[Alert]:
    """One IP failing to log in to MANY DIFFERENT accounts.

    Attackers spray one or two common passwords across many accounts to
    stay under per-account lockout limits, so a per-account brute force
    rule never fires. MITRE ATT&CK T1110.003 (Brute Force: Password Spraying).
    """
    failures = defaultdict(list)
    for event in sorted(events, key=lambda e: e.timestamp):
        if event.action == "login_failed":
            failures[event.source_ip].append(event)

    alerts = []
    for ip, attempts in failures.items():
        best: List[Event] = []
        best_users: set = set()
        start = 0
        for end in range(len(attempts)):
            while attempts[end].timestamp - attempts[start].timestamp > window:
                start += 1
            users = {e.username for e in attempts[start:end + 1]}
            if len(users) > len(best_users):
                best, best_users = attempts[start:end + 1], users

        if len(best_users) >= min_usernames:
            alerts.append(Alert(
                rule="ssh_password_spraying",
                severity="high",
                mitre_id="T1110.003",
                mitre_name="Brute Force: Password Spraying",
                source_ip=ip,
                description=(
                    f"Failed logins against {len(best_users)} different accounts: "
                    f"{', '.join(sorted(best_users))}"
                ),
                first_seen=best[0].timestamp,
                last_seen=best[-1].timestamp,
                event_count=len(best),
            ))
    return alerts


def detect_success_after_failures(
    events: Iterable[Event],
    min_failures: int = 3,
    window: timedelta = timedelta(minutes=10),
) -> List[Alert]:
    """A successful login that follows a burst of failures from the same IP.

    This is the one that matters most: it suggests the guessing WORKED and
    the account is now compromised. MITRE ATT&CK T1078 (Valid Accounts).
    """
    ordered = sorted(events, key=lambda e: e.timestamp)
    recent_failures = defaultdict(list)
    alerts = []

    for event in ordered:
        key = (event.source_ip, event.username)
        if event.action == "login_failed":
            recent_failures[key].append(event)
        elif event.action == "login_success":
            preceding = [
                f for f in recent_failures[key]
                if event.timestamp - f.timestamp <= window
            ]
            if len(preceding) >= min_failures:
                alerts.append(Alert(
                    rule="ssh_success_after_failures",
                    severity="critical",
                    mitre_id="T1078",
                    mitre_name="Valid Accounts",
                    source_ip=event.source_ip,
                    description=(
                        f"Successful login as '{event.username}' after "
                        f"{len(preceding)} failed attempts - possible compromise"
                    ),
                    first_seen=preceding[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(preceding) + 1,
                ))
            recent_failures[key].clear()
    return alerts


ALL_RULES = [
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
]


def run_all(events: Iterable[Event]) -> List[Alert]:
    """Run every rule and return alerts, most severe first."""
    events = list(events)
    severity_order = {"critical": 0, "high": 1, "medium": 2}
    alerts = [alert for rule in ALL_RULES for alert in rule(events)]
    return sorted(alerts, key=lambda a: (severity_order[a.severity], a.first_seen))
