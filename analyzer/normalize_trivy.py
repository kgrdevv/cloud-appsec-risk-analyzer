import argparse
import json
from pathlib import Path
from typing import Any

from analyzer.schemas import NormalizedFinding


SEVERITY_MAP = {
    "UNKNOWN": "low",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def normalize_file_path(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    path = value.lstrip("/")
    if path.startswith("src/"):
        return path.removeprefix("src/")
    return path


def normalize_severity(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    return SEVERITY_MAP.get(value.upper(), value.lower())


def normalize_vulnerability(result: dict[str, Any], vulnerability: dict[str, Any]) -> NormalizedFinding:
    package_name = str(vulnerability.get("PkgName", "unknown-package"))
    vulnerability_id = str(vulnerability.get("VulnerabilityID", "unknown"))
    installed_version = str(vulnerability.get("InstalledVersion", "unknown"))
    fixed_version = vulnerability.get("FixedVersion")
    title = vulnerability.get("Title")

    if isinstance(title, str) and title:
        finding_title = title
    else:
        finding_title = f"{package_name} {vulnerability_id}"

    if isinstance(fixed_version, str) and fixed_version:
        finding_title = f"{finding_title} (fixed in {fixed_version})"

    return NormalizedFinding(
        scanner="trivy",
        rule_id=vulnerability_id,
        title=finding_title,
        severity=normalize_severity(vulnerability.get("Severity")),
        category="sca",
        file=normalize_file_path(result.get("Target")),
        line=0,
        end_line=None,
        cwe=[],
        owasp=[],
        confidence="medium",
        impact=normalize_severity(vulnerability.get("Severity")),
        likelihood="medium",
    )


def normalize_trivy(input_path: Path) -> list[dict[str, object]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ValueError("Trivy JSON does not contain a valid Results list")

    findings = []
    for result in results:
        if not isinstance(result, dict):
            continue

        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if isinstance(vulnerability, dict):
                findings.append(normalize_vulnerability(result, vulnerability).to_dict())

    return findings


def write_json(output_path: Path, findings: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Normalize Trivy JSON into the common findings schema.")
    parser.add_argument(
        "--input",
        default="scanner-results/trivy.json",
        help="Path to Trivy JSON output.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/trivy-normalized-findings.json",
        help="Path where normalized findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = normalize_trivy(Path(args.input))
    write_json(Path(args.output), findings)
    print(f"Normalized {len(findings)} Trivy finding(s) to {args.output}")


if __name__ == "__main__":
    main()

