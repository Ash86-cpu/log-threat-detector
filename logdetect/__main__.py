"""Entry point: lets you run the tool with `python -m logdetect <logfile>`."""

import sys
from pathlib import Path

from .detections import run_all
from .parser import parse_ssh_log


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m logdetect <path-to-auth.log>")
        return 1

    events = list(parse_ssh_log(Path(sys.argv[1])))
    alerts = run_all(events)
    print(f"Parsed {len(events)} login events, raised {len(alerts)} alerts\n")

    for alert in alerts:
        print(f"[{alert.severity.upper()}] {alert.rule}  ({alert.mitre_id} {alert.mitre_name})")
        print(f"  source ip : {alert.source_ip}")
        print(f"  what      : {alert.description}")
        print(f"  when      : {alert.first_seen:%b %d %H:%M:%S} to {alert.last_seen:%H:%M:%S}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
