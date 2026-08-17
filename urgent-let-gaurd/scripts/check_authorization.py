#!/usr/bin/env python3
"""Fail-closed validation for a project-root AUTHORIZATION.md scope file."""

from __future__ import annotations

import argparse
import datetime as date_module
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_FIELDS = (
    "STATUS",
    "LICENSE_ID",
    "PROGRAM",
    "PROGRAM_URL",
    "TARGET",
    "AUTHORIZED_TESTER",
    "AUTHORIZED_ACTIVITIES",
    "OUT_OF_SCOPE",
    "ISSUED_BY",
    "VERIFICATION",
    "START_DATE",
    "END_DATE",
)
FIELD_PATTERN = re.compile(r"^([A-Z][A-Z0-9_]+):\s*(.*?)\s*$")
PLACEHOLDER_PATTERN = re.compile(
    r"\[.*?\]|\b(?:TODO|TBD|REPLACE(?:[-_ ]?ME)?|TEMPLATE_ONLY|YYYY-MM-DD)\b",
    re.IGNORECASE,
)
BROAD_TARGETS = {"*", "all", "all targets", "any target", "everything", "the internet"}
BROAD_ACTIVITIES = {"*", "all", "anything", "full access", "任意"}


def parse_fields(path: Path) -> tuple[dict[str, str], list[str]]:
    fields: dict[str, str] = {}
    errors: list[str] = []

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return fields, [f"cannot read {path}: {exc}"]

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(">"):
            continue
        match = FIELD_PATTERN.match(stripped)
        if not match:
            continue
        key, value = match.groups()
        if key in fields:
            errors.append(f"duplicate field {key} on line {line_number}")
        else:
            fields[key] = value.strip()
    return fields, errors


def parse_iso_date(value: str, field_name: str, errors: list[str]) -> date_module.date | None:
    try:
        parsed = date_module.datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        errors.append(f"{field_name} must use YYYY-MM-DD")
        return None
    return parsed


def normalize_target(value: str) -> str:
    normalized = value.strip().lower().rstrip("/")
    if "://" in normalized:
        parsed = urlparse(normalized)
        normalized = f"{parsed.netloc}{parsed.path}".rstrip("/")
    return normalized


def target_matches(requested: str, authorized_target: str) -> bool:
    requested_value = normalize_target(requested)
    for raw_token in re.split(r"[,;]", authorized_target):
        token = normalize_target(raw_token)
        if not token:
            continue
        if token.startswith("*."):
            suffix = token[2:]
            if requested_value.endswith(f".{suffix}") and requested_value != suffix:
                return True
        elif requested_value == token:
            return True
    return False


def activity_matches(requested: str, authorized_activities: str) -> bool:
    requested_value = requested.strip().lower()
    tokens = [item.strip().lower() for item in re.split(r"[,;]", authorized_activities) if item.strip()]
    return any(requested_value == token or requested_value in token for token in tokens)


def validate(
    path: Path,
    requested_target: str | None,
    requested_activity: str | None,
    today: date_module.date,
) -> tuple[bool, dict[str, object], list[str]]:
    errors: list[str] = []
    if path.name != "AUTHORIZATION.md":
        errors.append("authorization file must be named AUTHORIZATION.md")
    if not path.is_file():
        errors.append(f"authorization file not found: {path}")
        return False, {}, errors

    fields, parse_errors = parse_fields(path)
    errors.extend(parse_errors)
    missing = [field for field in REQUIRED_FIELDS if not fields.get(field)]
    errors.extend(f"missing field {field}" for field in missing)

    for field, value in fields.items():
        if PLACEHOLDER_PATTERN.search(value):
            errors.append(f"field {field} contains a placeholder")

    if fields.get("STATUS", "").upper() != "ACTIVE":
        errors.append("STATUS must be ACTIVE")

    license_id = fields.get("LICENSE_ID", "")
    if license_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", license_id):
        errors.append("LICENSE_ID must be 3-128 letters, digits, dots, underscores, or hyphens")

    program_url = fields.get("PROGRAM_URL", "")
    parsed_url = urlparse(program_url)
    if program_url and (parsed_url.scheme != "https" or not parsed_url.netloc):
        errors.append("PROGRAM_URL must be an HTTPS URL")

    target_tokens = [normalize_target(token) for token in re.split(r"[,;]", fields.get("TARGET", ""))]
    if any(token in BROAD_TARGETS for token in target_tokens):
        errors.append("TARGET must name an explicit program target, not a universal wildcard")
    if not any(re.search(r"[a-z0-9]", token) for token in target_tokens):
        errors.append("TARGET must contain concrete target data")

    activities = [item.strip().lower() for item in re.split(r"[,;]", fields.get("AUTHORIZED_ACTIVITIES", "")) if item.strip()]
    if any(item in BROAD_ACTIVITIES for item in activities):
        errors.append("AUTHORIZED_ACTIVITIES must be explicit, not universal access")

    start_date = parse_iso_date(fields["START_DATE"], "START_DATE", errors) if fields.get("START_DATE") else None
    end_date = parse_iso_date(fields["END_DATE"], "END_DATE", errors) if fields.get("END_DATE") else None
    if start_date and end_date:
        if start_date > end_date:
            errors.append("START_DATE must not be after END_DATE")
        if today < start_date or today > end_date:
            errors.append(f"authorization is not active on {today.isoformat()}")

    if requested_target and not target_matches(requested_target, fields.get("TARGET", "")):
        errors.append(f"requested target is outside AUTHORIZATION.md TARGET scope: {requested_target}")
    if requested_activity and not activity_matches(requested_activity, fields.get("AUTHORIZED_ACTIVITIES", "")):
        errors.append(f"requested activity is outside AUTHORIZED_ACTIVITIES scope: {requested_activity}")

    if errors:
        return False, {}, errors

    result: dict[str, object] = {
        "authorized": True,
        "license_id": license_id,
        "program": fields["PROGRAM"],
        "target": fields["TARGET"],
        "authorized_activities": fields["AUTHORIZED_ACTIVITIES"],
        "out_of_scope": fields["OUT_OF_SCOPE"],
        "start_date": fields["START_DATE"],
        "end_date": fields["END_DATE"],
    }
    return True, result, []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=Path("AUTHORIZATION.md"))
    parser.add_argument("--target", help="exact target to check against TARGET scope")
    parser.add_argument("--activity", help="activity to check against AUTHORIZED_ACTIVITIES scope")
    parser.add_argument("--at", dest="effective_date", help="date to validate, for testing, in YYYY-MM-DD format")
    args = parser.parse_args()

    errors: list[str] = []
    effective_date = date_module.date.today()
    if args.effective_date:
        parsed_effective_date = parse_iso_date(args.effective_date, "--at", errors)
        if parsed_effective_date:
            effective_date = parsed_effective_date
    if errors:
        for error in errors:
            print(f"INVALID AUTHORIZATION: {error}", file=sys.stderr)
        return 1

    valid, result, errors = validate(args.path, args.target, args.activity, effective_date)
    if not valid:
        for error in errors:
            print(f"INVALID AUTHORIZATION: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
