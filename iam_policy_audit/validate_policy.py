"""
A small static checker for AWS-style IAM policy documents (JSON).
It flags three common red flags in every Allow statement:
1. a wildcard Action
2. a wildcard Resource
3. a missing Condition block

Usage:
    python3 validate_policy.py <policy.json> [<policy.json> ...]
"""

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence, cast

Statement = dict[str, Any]


def as_list(value: Any) -> list[Any]:
    """Policy fields can hold a single string or a list of strings."""
    return [value] if isinstance(value, str) else cast(list[Any], value)


@dataclass(frozen=True)
class Rule:
    """One red flag: the message to print and the test that detects it."""

    message: str
    is_violated_by: Callable[[Statement], bool]


RULES: tuple[Rule, ...] = (
    Rule(
        'Wildcard Action ("*") -> allows ALL operations',
        lambda stmt: "*" in as_list(stmt.get("Action", [])),
    ),
    Rule(
        'Wildcard Resource ("*") -> access to ALL resources',
        lambda stmt: "*" in as_list(stmt.get("Resource", [])),
    ),
    Rule(
        "No Condition block -> applies without any time or location restriction",
        lambda stmt: "Condition" not in stmt,
    ),
)


def statements_of(policy: dict[str, Any]) -> list[Statement]:
    """Return the statements of a policy as a list."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        return [cast(Statement, statements)]
    return cast(list[Statement], statements)


def audit_file(path: str) -> int:
    """Print the audit of one policy file and return its red flag count."""
    policy: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))

    print(f"\n=== Audit result: {path} ===")
    total = 0

    for number, stmt in enumerate(statements_of(policy), start=1):
        name: str = stmt.get("Sid", f"Statement #{number}")
        print(f"\nStatement: {name}")

        if stmt.get("Effect") != "Allow":
            print("  (Effect is not Allow, skipped from the red flag checks)")
            continue

        findings: list[str] = [
            rule.message for rule in RULES if rule.is_violated_by(stmt)
        ]
        for message in findings:
            print(f"  [RED FLAG] {message}")
        if not findings:
            print("  No red flags found in this statement.")
        total += len(findings)

    print(f"\nTotal red flags found in {path}: {total}")
    return total


def main(paths: Sequence[str]) -> int:
    if not paths:
        print(
            "Usage: python3 validate_policy.py <policy.json> [<policy.json> ...]")
        return 1

    exit_code = 0
    for path in paths:
        try:
            if audit_file(path) > 0:
                exit_code = 1
        except FileNotFoundError:
            print(f"File not found: {path}")
            exit_code = 1
        except json.JSONDecodeError as error:
            print(f"File is not valid JSON: {error}")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
