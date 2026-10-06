"""Command-line interface. Run `python -m logdetect --help` to see the options."""

import argparse
import sys
from pathlib import Path

from .detections import run_all
from .parser import parse_ssh_log
from .report import SEVERITY_ORDER, filter_by_severity, format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logdetect",
        description="Detect brute force, password spraying and likely "
                    "account compromise in SSH authentication logs.",
    )
    parser.add_argument("logfile", type=Path, help="path to an SSH auth log")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--output", type=Path, metavar="FILE",
        help="write the report to FILE instead of the terminal",
    )
    parser.add_argument(
        "--min-severity", choices=SEVERITY_ORDER, default="medium",
        help="hide alerts below this severity (default: medium)",
    )
    parser.add_argument(
        "--year", type=int,
        help="year the log was written (syslog lines omit it; default: this year)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.logfile.is_file():
        print(f"error: log file not found: {args.logfile}", file=sys.stderr)
        return 1

    events = list(parse_ssh_log(args.logfile, args.year))
    alerts = filter_by_severity(run_all(events), args.min_severity)

    formatter = format_json if args.format == "json" else format_text
    report = formatter(alerts, len(events))

    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"Wrote {len(alerts)} alerts to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
