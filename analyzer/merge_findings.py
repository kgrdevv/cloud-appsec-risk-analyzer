import argparse
import json
from pathlib import Path
from typing import Any


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError(f"{input_path} does not contain a valid findings list")

    return [finding for finding in findings if isinstance(finding, dict)]


def write_json(output_path: Path, findings: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge normalized findings from multiple scanners.")
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="One or more normalized findings JSON files.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/normalized-findings.json",
        help="Path where merged findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    merged_findings: list[dict[str, Any]] = []

    for input_path in args.input:
        merged_findings.extend(load_findings(Path(input_path)))

    write_json(Path(args.output), merged_findings)
    print(f"Merged {len(merged_findings)} finding(s) to {args.output}")


if __name__ == "__main__":
    main()

