"""Entry point: lets you run the tool with `python -m logdetect <logfile>`."""

import sys
from collections import Counter
from pathlib import Path

from .parser import parse_ssh_log


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m logdetect <path-to-auth.log>")
        return 1

    events = list(parse_ssh_log(Path(sys.argv[1])))
    print(f"Parsed {len(events)} login events\n")

    for action, count in Counter(e.action for e in events).items():
        print(f"  {action:<14} {count}")

    print("\nFailed logins by source IP:")
    failures = Counter(e.source_ip for e in events if e.action == "login_failed")
    for ip, count in failures.most_common():
        print(f"  {ip:<16} {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
