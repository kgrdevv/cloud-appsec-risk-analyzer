import argparse
import json
from pathlib import Path
from typing import Any

from analyzer.schemas import NormalizedFinding


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "medium"
    return value.lower()


def normalize_file_path(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return value.lstrip("/")


def normalize_line_range(value: Any) -> tuple[int, int | None]:
    if not isinstance(value, list) or not value:
        return 0, None

    start = value[0] if isinstance(value[0], int) else 0
    end = value[-1] if isinstance(value[-1], int) else None
    return start, end


def normalize_result(result: dict[str, Any]) -> NormalizedFinding:
    line, end_line = normalize_line_range(result.get("file_line_range"))

    return NormalizedFinding(
        scanner="checkov",
        rule_id=str(result.get("check_id", "unknown")),
        title=str(result.get("check_name", "Checkov IaC finding")),
        severity=normalize_severity(result.get("severity")),
        category="iac",
        file=normalize_file_path(result.get("repo_file_path") or result.get("file_path")),
        line=line,
        end_line=end_line,
        cwe=[],
        owasp=[],
        confidence="medium",
        impact="medium",
        likelihood="medium",
    )


def extract_failed_checks(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results = payload.get("results", {})

    if isinstance(results, dict):
        failed_checks = results.get("failed_checks", [])
        if isinstance(failed_checks, list):
            return [check for check in failed_checks if isinstance(check, dict)]

    if isinstance(results, list):
        failed_checks: list[dict[str, Any]] = []
        for result_set in results:
            if not isinstance(result_set, dict):
                continue
            nested_results = result_set.get("results", {})
            if not isinstance(nested_results, dict):
                continue
            nested_failed = nested_results.get("failed_checks", [])
            if isinstance(nested_failed, list):
                failed_checks.extend(check for check in nested_failed if isinstance(check, dict))
        return failed_checks

    return []


def normalize_checkov(input_path: Path) -> list[dict[str, object]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    failed_checks = extract_failed_checks(payload)
    return [normalize_result(result).to_dict() for result in failed_checks]


def write_json(output_path: Path, findings: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize Checkov JSON into the common findings schema.")
    parser.add_argument(
        "--input",
        default="scanner-results/checkov.json",
        help="Path to Checkov JSON output.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/checkov-normalized-findings.json",
        help="Path where normalized findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = normalize_checkov(Path(args.input))
    write_json(Path(args.output), findings)
    print(f"Normalized {len(findings)} Checkov finding(s) to {args.output}")


if __name__ == "__main__":
    main()
