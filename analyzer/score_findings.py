import argparse
import json
from pathlib import Path
from typing import Any

from analyzer.schemas import ScoredFinding


SEVERITY_POINTS = {
    "low": 20,
    "medium": 40,
    "high": 45,
    "critical": 70,
}

IMPACT_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 15,
}

LIKELIHOOD_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 20,
}

CONFIDENCE_POINTS = {
    "low": -5,
    "medium": 0,
    "high": 5,
}


def label_points(value: Any, mapping: dict[str, int]) -> int:
    if not isinstance(value, str):
        return 0
    return mapping.get(value.lower(), 0)


def exposure_bonus(finding: dict[str, Any]) -> tuple[int, list[str]]:
    factors = []
    bonus = 0

    file_path = str(finding.get("file", ""))
    title = str(finding.get("title", "")).lower()
    category = str(finding.get("category", "")).lower()

    if file_path.startswith("app/"):
        bonus += 5
        factors.append("application_code")

    if file_path.startswith("infra/terraform/"):
        bonus += 5
        factors.append("iac_exposure_model")

    if "sql" in title:
        bonus += 5
        factors.append("injection_pattern")

    if finding.get("cwe") and "CWE-89" in finding["cwe"]:
        bonus += 5
        factors.append("sql_injection_cwe")

    if category == "iac":
        if "0.0.0.0/0" in title or "public" in title:
            bonus += 10
            factors.append("public_exposure")
        if "wildcard" in title or "permissions" in title or "privilege" in title:
            bonus += 10
            factors.append("broad_permissions")

    return bonus, factors


def priority_from_score(score: int) -> str:
    if score >= 95:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_finding(finding: dict[str, Any]) -> ScoredFinding:
    score = 0
    score += label_points(finding.get("severity"), SEVERITY_POINTS)
    score += label_points(finding.get("impact"), IMPACT_POINTS)
    score += label_points(finding.get("likelihood"), LIKELIHOOD_POINTS)
    score += label_points(finding.get("confidence"), CONFIDENCE_POINTS)

    bonus, risk_factors = exposure_bonus(finding)
    score += bonus
    score = max(0, min(score, 100))

    return ScoredFinding(
        scanner=str(finding.get("scanner", "unknown")),
        rule_id=str(finding.get("rule_id", "unknown")),
        title=str(finding.get("title", "Security finding")),
        severity=str(finding.get("severity", "unknown")),
        priority=priority_from_score(score),
        risk_score=score,
        category=str(finding.get("category", "unknown")),
        file=str(finding.get("file", "unknown")),
        line=int(finding.get("line", 0)),
        end_line=finding.get("end_line") if isinstance(finding.get("end_line"), int) else None,
        cwe=finding.get("cwe", []) if isinstance(finding.get("cwe"), list) else [],
        owasp=finding.get("owasp", []) if isinstance(finding.get("owasp"), list) else [],
        confidence=finding.get("confidence") if isinstance(finding.get("confidence"), str) else None,
        impact=finding.get("impact") if isinstance(finding.get("impact"), str) else None,
        likelihood=finding.get("likelihood") if isinstance(finding.get("likelihood"), str) else None,
        risk_factors=risk_factors,
    )


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Normalized findings JSON does not contain a valid findings list")

    return [finding for finding in findings if isinstance(finding, dict)]


def write_json(output_path: Path, scored_findings: list[dict[str, object]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"findings": scored_findings}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Calculate risk scores for normalized findings.")
    parser.add_argument(
        "--input",
        default="scanner-results/normalized-findings.json",
        help="Path to normalized findings JSON.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/scored-findings.json",
        help="Path where scored findings should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = load_findings(Path(args.input))
    scored_findings = [score_finding(finding).to_dict() for finding in findings]
    write_json(Path(args.output), scored_findings)
    print(f"Scored {len(scored_findings)} finding(s) to {args.output}")


if __name__ == "__main__":
    main()
