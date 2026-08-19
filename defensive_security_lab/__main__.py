"""Command-line entry point for the evidence lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .incident_timeline import analyze_file
from .ioc_matcher import match_file
from .local_header_audit import audit_fixture, fetch_and_audit
from .path_guard import classify_filenames


ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Localhost-only defensive security evidence lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    path_parser = subparsers.add_parser("path", help="classify safe and unsafe filename strings")
    path_parser.add_argument("names", nargs="+")

    ioc_parser = subparsers.add_parser("ioc", help="match synthetic indicators in a text file")
    ioc_parser.add_argument("indicators")
    ioc_parser.add_argument("records")

    incident_parser = subparsers.add_parser("incident", help="analyze synthetic authentication events")
    incident_parser.add_argument("events")

    headers_parser = subparsers.add_parser("headers", help="audit a header fixture or localhost URL")
    source = headers_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--fixture")

    subparsers.add_parser("all", help="run all bundled fixture analyses")
    return parser


def bundled_results() -> dict[str, object]:
    fixtures = ROOT / "fixtures"
    return {
        "path": classify_filenames(["report.vtt", "notes.txt", "../payload.mp4", "nested/file.log"]),
        "ioc": match_file(fixtures / "iocs.json", fixtures / "auth_events.jsonl"),
        "incident": analyze_file(fixtures / "auth_events.jsonl"),
        "headers": audit_fixture(fixtures / "http_headers.json"),
    }


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "path":
        result = classify_filenames(args.names)
    elif args.command == "ioc":
        result = match_file(args.indicators, args.records)
    elif args.command == "incident":
        result = analyze_file(args.events)
    elif args.command == "headers":
        result = fetch_and_audit(args.url) if args.url else audit_fixture(args.fixture)
    else:
        result = bundled_results()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

