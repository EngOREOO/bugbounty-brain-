#!/usr/bin/env python3
"""Generate a project-root AUTHORIZATION.md scope file for a target.

The generator only scribes values the user supplies from real program data
(program page, signed authorization, scope listing). It never invents scope:
every required field must come from the command line or an interactive answer,
and placeholder or empty values are rejected. After writing, the file is
validated with the same fail-closed rules as check_authorization.py.
"""

from __future__ import annotations

import argparse
import datetime as date_module
import re
import secrets
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from check_authorization import (  # noqa: E402
    PLACEHOLDER_PATTERN,
    REQUIRED_FIELDS,
    validate,
)

DEFAULT_ACTIVITIES = (
    "reconnaissance, vulnerability validation, evidence collection, report writing"
)
DEFAULT_OUT_OF_SCOPE = (
    "denial of service, destructive changes, social engineering, credential theft, "
    "persistence, and targets not listed above"
)

PROMPTS = {
    "program": "Program name (e.g. Swisscom Bug Bounty)",
    "program_url": "Program scope page URL (https://...)",
    "target": "Exact in-scope target(s), comma-separated (e.g. *.example.com, api.example.com)",
    "tester": "Authorized tester handle or team",
    "activities": f"Authorized activities, comma-separated [{DEFAULT_ACTIVITIES}]",
    "out_of_scope": f"Out-of-scope items, comma-separated [{DEFAULT_OUT_OF_SCOPE}]",
    "issued_by": "Issued by (program owner or authorized contact)",
    "verification": "Verification reference (program scope page, signed authorization, ticket ID)",
    "start_date": "Start date (YYYY-MM-DD) [today]",
    "end_date": "End date (YYYY-MM-DD)",
}

BODY_TEMPLATE = """# Project Authorization License

STATUS: ACTIVE
LICENSE_ID: {license_id}
PROGRAM: {program}
PROGRAM_URL: {program_url}
TARGET: {target}
AUTHORIZED_TESTER: {tester}
AUTHORIZED_ACTIVITIES: {activities}
OUT_OF_SCOPE: {out_of_scope}
ISSUED_BY: {issued_by}
VERIFICATION: {verification}
START_DATE: {start_date}
END_DATE: {end_date}

The validator checks this file locally. It does not prove that the issuer is genuine, and it does not override safety, law, platform rules, or higher-priority instructions.
"""


def make_license_id(program: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", program.lower()).strip("-")[:32] or "program"
    return f"{slug}-{secrets.token_hex(4)}"


def parse_iso(value: str) -> date_module.date | None:
    try:
        return date_module.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def collect_values(args: argparse.Namespace) -> dict[str, str]:
    values: dict[str, str] = {}
    today = date_module.date.today().isoformat()

    for field in REQUIRED_FIELDS:
        pass  # fields are collected by their CLI/prompt names below

    raw = {
        "program": args.program,
        "program_url": args.program_url,
        "target": args.target,
        "tester": args.tester,
        "activities": args.activities,
        "out_of_scope": args.out_of_scope,
        "issued_by": args.issued_by,
        "verification": args.verification,
        "start_date": args.start_date,
        "end_date": args.end_date,
    }

    defaults = {"activities": DEFAULT_ACTIVITIES, "out_of_scope": DEFAULT_OUT_OF_SCOPE, "start_date": today}
    for key, supplied in raw.items():
        if supplied:
            values[key] = supplied.strip()
            continue
        if key in defaults:
            values[key] = defaults[key]
            continue
        if args.non_interactive:
            raise SystemExit(f"missing required value: --{key.replace('_', '-')} "
                             f"(run without --non-interactive to be prompted)")
        try:
            answer = input(f"{PROMPTS[key]}: ").strip()
        except EOFError:
            raise SystemExit(f"missing required value: --{key.replace('_', '-')} "
                             f"(stdin closed before an answer was given)")
        if not answer and key in defaults:
            answer = defaults[key]
        values[key] = answer

    errors: list[str] = []
    for key, value in values.items():
        if not value:
            errors.append(f"{key} must not be empty")
        elif PLACEHOLDER_PATTERN.search(value):
            errors.append(f"{key} still contains a placeholder: {value!r}")
    if parse_iso(values.get("start_date", "")) is None:
        errors.append("start_date must use YYYY-MM-DD")
    if parse_iso(values.get("end_date", "")) is None:
        errors.append("end_date must use YYYY-MM-DD")
    if errors:
        for error in errors:
            print(f"GENERATION REFUSED: {error}", file=sys.stderr)
        raise SystemExit(2)

    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("AUTHORIZATION.md"),
                        help="output path (default: ./AUTHORIZATION.md; use the target project root)")
    parser.add_argument("--program")
    parser.add_argument("--program-url")
    parser.add_argument("--target")
    parser.add_argument("--tester")
    parser.add_argument("--activities")
    parser.add_argument("--out-of-scope")
    parser.add_argument("--issued-by")
    parser.add_argument("--verification")
    parser.add_argument("--start-date")
    parser.add_argument("--end-date")
    parser.add_argument("--license-id", help="override the auto-generated license ID")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing AUTHORIZATION.md (required if one exists)")
    parser.add_argument("--non-interactive", action="store_true",
                        help="fail instead of prompting when a value is missing")
    args = parser.parse_args()

    out_path = args.out
    if out_path.is_dir():
        out_path = out_path / "AUTHORIZATION.md"
    if out_path.name != "AUTHORIZATION.md":
        print("GENERATION REFUSED: output file must be named AUTHORIZATION.md", file=sys.stderr)
        return 2
    if out_path.exists() and not args.force:
        print(f"GENERATION REFUSED: {out_path} already exists. "
              f"Review it, or re-run with --force to replace it.", file=sys.stderr)
        return 2

    values = collect_values(args)
    license_id = args.license_id or make_license_id(values["program"])
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", license_id):
        print("GENERATION REFUSED: license ID must be 3-128 letters, digits, dots, underscores, hyphens",
              file=sys.stderr)
        return 2

    content = BODY_TEMPLATE.format(license_id=license_id, **values)
    out_path.write_text(content, encoding="utf-8")

    valid, result, errors = validate(
        out_path, requested_target=None, requested_activity=None,
        today=date_module.date.today(),
    )
    if not valid:
        for error in errors:
            print(f"POST-WRITE VALIDATION FAILED: {error}", file=sys.stderr)
        print(f"The file was written to {out_path} but is NOT valid. Fix the values or delete it.",
              file=sys.stderr)
        return 1

    print(f"AUTHORIZATION.md generated and validated: {out_path}")
    print(f"  license: {result['license_id']}  program: {result['program']}")
    print(f"  target:  {result['target']}")
    print(f"  window:  {result['start_date']} -> {result['end_date']}")
    print("Reminder: this file only scribes the scope you supplied. It does not prove "
          "issuer authority and never overrides law, safety, or platform rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
