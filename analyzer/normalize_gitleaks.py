import argparse
import json
from pathlib import Path
from typing import Any

from analyzer.schemas import NormalizedFinding


def normalize_file_path(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return value.lstrip("/")


def normalize_line(value: Any) -> int:
    return value if isinstance(value, int) else 0


def normalize_result(result: dict[str, Any]) -> NormalizedFinding:
    rule_id = str(result.get("RuleID") or result.get("rule") or "unknown")
    description = str(result.get("Description") or result.get("description") or "Secret detected")
    file_path = normalize_file_path(result.get("File") or result.get("file"))
    start_line = normalize_line(result.get("StartLine") or result.get("line"))
    end_line = result.get("EndLine")

    return NormalizedFinding(
        scanner="gitleaks",
        rule_id=rule_id,
        title=description,
        severity="high",
        category="secret",
        file=file_path,
        line=start_line,
        end_line=end_line if isinstance(end_line, int) else None,
        cwe=[],
        owasp=[],
        confidence="high",
        impact="high",
        likelihood="medium",
    )


def extract_results(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [result for result in payload if isinstance(result, dict)]

    if isinstance(payload, dict):
        findings = payload.get("findings") or payload.get("results") or payload.get("Findings")
        if isinstance(findings, list):
            return [result for result in findings if isinstance(result, dict)]

    return []


def normalize_gitleaks(input_path: Path) -> list[dict[str, object]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    results = extract_results(payload)
    return [normalize_result(result).to_dict() for result in results]


def write_json(output_path: Path, findings: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize Gitleaks JSON into the common findings schema.")
    parser.add_argument(
        "--input",
        default="scanner-results/gitleaks.json",
        help="Path to Gitleaks JSON output.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/gitleaks-normalized-findings.json",
        help="Path where normalized findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = normalize_gitleaks(Path(args.input))
    write_json(Path(args.output), findings)
    print(f"Normalized {len(findings)} Gitleaks finding(s) to {args.output}")


if __name__ == "__main__":
    main()

