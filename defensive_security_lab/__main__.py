"""Command-line entry point for the evidence lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .challenge_evidence import completed_categories, validate_matrix
from .incident_timeline import analyze_file, load_events
from .ioc_matcher import match_file
from .local_header_audit import audit_fixture, fetch_and_audit
from .path_guard import classify_filenames, explain
from .sigma import evaluate, load_rules
from .web_assessment import assess_response, assess_target

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
RULES = ROOT / "rules" / "sigma"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Localhost-only defensive security evidence lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    path_parser = subparsers.add_parser("path", help="classify safe and unsafe filename strings")
    path_parser.add_argument("names", nargs="+")

    explain_parser = subparsers.add_parser("explain", help="show why each filename was rejected")
    explain_parser.add_argument("names", nargs="+")

    ioc_parser = subparsers.add_parser("ioc", help="match synthetic indicators in a text file")
    ioc_parser.add_argument("indicators")
    ioc_parser.add_argument("records")

    incident_parser = subparsers.add_parser("incident", help="analyze synthetic auth events")
    incident_parser.add_argument("events")

    headers_parser = subparsers.add_parser(
        "headers", help="audit a header fixture or localhost URL"
    )
    source = headers_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url")
    source.add_argument("--fixture")

    sigma_parser = subparsers.add_parser("sigma", help="evaluate bundled Sigma rules over events")
    sigma_parser.add_argument("events", nargs="?", default=str(FIXTURES / "auth_events.jsonl"))
    sigma_parser.add_argument("--rules", default=str(RULES))

    assess_parser = subparsers.add_parser(
        "assess", help="security-header assessment of a loopback URL or a captured response"
    )
    assess_source = assess_parser.add_mutually_exclusive_group(required=True)
    assess_source.add_argument("--url", help="an authorized loopback target")
    assess_source.add_argument("--capture", help="a captured response JSON file")

    subparsers.add_parser(
        "challenges", help="validate the local training-challenge evidence matrix"
    )

    subparsers.add_parser("all", help="run all bundled fixture analyses")
    return parser


def run_challenges() -> dict[str, object]:
    """Validate the challenge matrix and summarise it without leaking detail."""

    path = FIXTURES / "challenge_matrix.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    validate_matrix(records)
    return {
        "record_count": len(records),
        "completed_categories": sorted(completed_categories(records)),
        "records": [
            {
                "name": record["name"],
                "official_category": record["official_category"],
                "difficulty_stars": record["difficulty_stars"],
                "instance_solved_state": record["instance_solved_state"],
                "genuinely_completed": record["genuinely_completed"],
            }
            for record in records
        ],
    }


def run_assessment(url: str | None, capture: str | None) -> dict[str, object]:
    """Assess either a live loopback target or a previously captured response."""

    if capture:
        data = json.loads(Path(capture).read_text(encoding="utf-8"))
        return assess_response(data["url"], int(data["status"]), dict(data["headers"])).as_dict()
    return assess_target(url).as_dict()


def run_sigma(events_path: str, rules_path: str) -> list[dict[str, object]]:
    """Evaluate every bundled rule against one event fixture."""

    events = load_events(events_path)
    results: list[dict[str, object]] = []
    for rule in load_rules(rules_path):
        matches = evaluate(rule, events)
        results.append(
            {
                "rule": rule["title"],
                "id": rule["id"],
                "level": rule["level"],
                "match_count": len(matches),
                "matches": matches,
            }
        )
    return results


def _load_capture() -> dict[str, object] | None:
    """Load the authorized-target capture if it is present."""

    path = FIXTURES / "juice_shop_baseline.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


_CAPTURE = _load_capture()


def bundled_results() -> dict[str, object]:
    return {
        "path": classify_filenames(
            ["report.vtt", "notes.txt", "../payload.mp4", "nested/file.log", "CON.txt"]
        ),
        "ioc": match_file(FIXTURES / "iocs.json", FIXTURES / "auth_events.jsonl"),
        "incident": analyze_file(FIXTURES / "auth_events.jsonl"),
        "spray": analyze_file(FIXTURES / "auth_events_spray.jsonl"),
        "headers": audit_fixture(FIXTURES / "http_headers.json"),
        "assess": assess_response(
            "captured://juice_shop_baseline",
            _CAPTURE["status"],
            _CAPTURE["headers"],
        ).as_dict()
        if _CAPTURE
        else None,
        "sigma": [
            {"rule": entry["rule"], "match_count": entry["match_count"]}
            for entry in run_sigma(str(FIXTURES / "auth_events.jsonl"), str(RULES))
        ],
    }


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "path":
        result = classify_filenames(args.names)
    elif args.command == "explain":
        result = [explain(name) for name in args.names]
    elif args.command == "ioc":
        result = match_file(args.indicators, args.records)
    elif args.command == "incident":
        result = analyze_file(args.events)
    elif args.command == "headers":
        result = fetch_and_audit(args.url) if args.url else audit_fixture(args.fixture)
    elif args.command == "sigma":
        result = run_sigma(args.events, args.rules)
    elif args.command == "assess":
        result = run_assessment(args.url, args.capture)
    elif args.command == "challenges":
        result = run_challenges()
    else:
        result = bundled_results()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
