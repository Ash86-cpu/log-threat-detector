"""Command-line interface. Run `python -m logdetect --help` to see the options."""

import argparse
import sys
from pathlib import Path

from .detections import run_all
from .parser import parse_ssh_log, parse_web_log
from .web_detections import run_all_web
from .report import SEVERITY_ORDER, filter_by_severity, format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logdetect",
        description="Detect attacks in SSH authentication logs (brute force, "
                    "password spraying, account compromise) and web access "
                    "logs (SQL injection, path traversal, scanners).",
    )
    parser.add_argument("logfile", type=Path, help="path to the log file")
    parser.add_argument(
        "--type", choices=["ssh", "web"], default="ssh", dest="log_type",
        help="kind of log: ssh auth log or web access log (default: ssh)",
    )
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
        help="year an ssh log was written (syslog lines omit it; default: this year)",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.logfile.is_file():
        print(f"error: log file not found: {args.logfile}", file=sys.stderr)
        return 1

    if args.log_type == "web":
        events = list(parse_web_log(args.logfile))
        alerts = run_all_web(events)
    else:
        events = list(parse_ssh_log(args.logfile, args.year))
        alerts = run_all(events)
    alerts = filter_by_severity(alerts, args.min_severity)

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
