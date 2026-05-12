import argparse
import json
from pathlib import Path
from typing import Any

from analyzer.schemas import NormalizedFinding


SEVERITY_MAP = {
    "INFO": "low",
    "WARNING": "medium",
    "ERROR": "high",
}


def normalize_label(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.lower()


def normalize_cwe(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []

    normalized = []
    for value in values:
        if not isinstance(value, str):
            continue
        cwe_id = value.split(":", maxsplit=1)[0].strip()
        if cwe_id:
            normalized.append(cwe_id)
    return normalized


def normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return SEVERITY_MAP.get(value.upper(), value.lower())


def normalize_result(result: dict[str, Any]) -> NormalizedFinding:
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    start = result.get("start", {})
    end = result.get("end", {})

    return NormalizedFinding(
        scanner="semgrep",
        rule_id=str(result.get("check_id", "unknown")),
        title=str(extra.get("message", "Semgrep finding")),
        severity=normalize_severity(extra.get("severity")),
        category="sast",
        file=str(result.get("path", "unknown")),
        line=int(start.get("line", 0)),
        end_line=end.get("line") if isinstance(end.get("line"), int) else None,
        cwe=normalize_cwe(metadata.get("cwe")),
        owasp=normalize_string_list(metadata.get("owasp")),
        confidence=normalize_label(metadata.get("confidence")),
        impact=normalize_label(metadata.get("impact")),
        likelihood=normalize_label(metadata.get("likelihood")),
    )


def normalize_semgrep(input_path: Path) -> list[dict[str, object]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    results = payload.get("results", [])
    if not isinstance(results, list):
        raise ValueError("Semgrep JSON does not contain a valid results list")

    return [normalize_result(result).to_dict() for result in results if isinstance(result, dict)]


def write_json(output_path: Path, findings: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize Semgrep JSON into the common findings schema.")
    parser.add_argument(
        "--input",
        default="scanner-results/semgrep.json",
        help="Path to Semgrep JSON output.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/normalized-findings.json",
        help="Path where normalized findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = normalize_semgrep(Path(args.input))
    write_json(Path(args.output), findings)
    print(f"Normalized {len(findings)} Semgrep finding(s) to {args.output}")


if __name__ == "__main__":
    main()
