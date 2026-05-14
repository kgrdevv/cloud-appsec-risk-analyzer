import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


PRIORITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "unknown": 4,
}


def markdown_escape(value: Any) -> str:
    text = str(value) if value is not None else ""
    return text.replace("|", "\\|").replace("\n", " ")


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Scored findings JSON does not contain a valid findings list")

    return [finding for finding in findings if isinstance(finding, dict)]


def priority_sort_key(finding: dict[str, Any]) -> tuple[int, int]:
    priority = str(finding.get("priority", "unknown")).lower()
    score = finding.get("risk_score", 0)
    score_value = score if isinstance(score, int) else 0
    return (PRIORITY_ORDER.get(priority, PRIORITY_ORDER["unknown"]), -score_value)


def format_list(values: Any) -> str:
    if not isinstance(values, list) or not values:
        return "None"
    return ", ".join(markdown_escape(value) for value in values)


def build_summary(findings: list[dict[str, Any]]) -> list[str]:
    priority_counts = Counter(str(finding.get("priority", "unknown")).lower() for finding in findings)
    scanner_counts = Counter(str(finding.get("scanner", "unknown")).lower() for finding in findings)

    lines = [
        "## Executive Summary",
        "",
        f"- Total findings: `{len(findings)}`",
        f"- Critical: `{priority_counts.get('critical', 0)}`",
        f"- High: `{priority_counts.get('high', 0)}`",
        f"- Medium: `{priority_counts.get('medium', 0)}`",
        f"- Low: `{priority_counts.get('low', 0)}`",
        "",
        "Scanner coverage:",
        "",
    ]

    if scanner_counts:
        for scanner, count in sorted(scanner_counts.items()):
            lines.append(f"- `{scanner}`: `{count}` finding(s)")
    else:
        lines.append("- No scanner findings were provided.")

    lines.append("")
    return lines


def build_findings_table(findings: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Findings Overview",
        "",
        "| Priority | Score | Scanner | Rule | Location |",
        "| --- | ---: | --- | --- | --- |",
    ]

    if not findings:
        lines.append("| None | 0 | None | None | None |")
        lines.append("")
        return lines

    for finding in findings:
        location = f"{finding.get('file', 'unknown')}:{finding.get('line', 0)}"
        lines.append(
            "| {priority} | {score} | {scanner} | {rule} | {location} |".format(
                priority=markdown_escape(finding.get("priority", "unknown")),
                score=markdown_escape(finding.get("risk_score", 0)),
                scanner=markdown_escape(finding.get("scanner", "unknown")),
                rule=markdown_escape(finding.get("rule_id", "unknown")),
                location=markdown_escape(location),
            )
        )

    lines.append("")
    return lines


def build_finding_details(findings: list[dict[str, Any]]) -> list[str]:
    lines = ["## Finding Details", ""]

    if not findings:
        lines.extend(["No findings to report.", ""])
        return lines

    for index, finding in enumerate(findings, start=1):
        location = f"{finding.get('file', 'unknown')}:{finding.get('line', 0)}"
        lines.extend(
            [
                f"### {index}. {markdown_escape(finding.get('title', 'Security finding'))}",
                "",
                f"- Priority: `{markdown_escape(finding.get('priority', 'unknown'))}`",
                f"- Risk score: `{markdown_escape(finding.get('risk_score', 0))}`",
                f"- Scanner severity: `{markdown_escape(finding.get('severity', 'unknown'))}`",
                f"- Scanner: `{markdown_escape(finding.get('scanner', 'unknown'))}`",
                f"- Rule ID: `{markdown_escape(finding.get('rule_id', 'unknown'))}`",
                f"- Location: `{markdown_escape(location)}`",
                f"- Category: `{markdown_escape(finding.get('category', 'unknown'))}`",
                f"- CWE: {format_list(finding.get('cwe'))}",
                f"- OWASP: {format_list(finding.get('owasp'))}",
                f"- Confidence: `{markdown_escape(finding.get('confidence', 'unknown'))}`",
                f"- Impact: `{markdown_escape(finding.get('impact', 'unknown'))}`",
                f"- Likelihood: `{markdown_escape(finding.get('likelihood', 'unknown'))}`",
                f"- Risk factors: {format_list(finding.get('risk_factors'))}",
                "",
            ]
        )

    return lines


def build_recommendations(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["## Recommended Actions", "", "No remediation actions are required.", ""]

    return [
        "## Recommended Actions",
        "",
        "1. Review high-priority findings first and confirm whether the affected route is reachable.",
        "2. Replace dynamic SQL construction with parameterized queries.",
        "3. Replace demo authentication with a real authentication and authorization model before production use.",
        "4. Feed additional scanner outputs into the analyzer to improve prioritization confidence.",
        "",
    ]


def build_report(findings: list[dict[str, Any]]) -> str:
    sorted_findings = sorted(findings, key=priority_sort_key)
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# Security Risk Report",
        "",
        f"Generated at: `{generated_at}`",
        "",
        "This report is generated from normalized and scored security findings.",
        "",
    ]

    lines.extend(build_summary(sorted_findings))
    lines.extend(build_findings_table(sorted_findings))
    lines.extend(build_finding_details(sorted_findings))
    lines.extend(build_recommendations(sorted_findings))

    return "\n".join(lines)


def write_report(output_path: Path, report: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a Markdown security risk report.")
    parser.add_argument(
        "--input",
        default="scanner-results/scored-findings.json",
        help="Path to scored findings JSON.",
    )
    parser.add_argument(
        "--output",
        default="reports/security-report.md",
        help="Path where the Markdown report should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = load_findings(Path(args.input))
    report = build_report(findings)
    write_report(Path(args.output), report)
    print(f"Generated report with {len(findings)} finding(s) at {args.output}")


if __name__ == "__main__":
    main()

