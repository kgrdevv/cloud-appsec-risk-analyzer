import argparse
import json
from pathlib import Path
from typing import Any


def load_findings(input_path: Path) -> list[dict[str, Any]]:
    with input_path.open(encoding="utf-8") as input_file:
        payload = json.load(input_file)

    findings = payload.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("Scored findings JSON does not contain a valid findings list")

    return [finding for finding in findings if isinstance(finding, dict)]


def has_factor(finding: dict[str, Any], factor: str) -> bool:
    factors = finding.get("risk_factors", [])
    return isinstance(factors, list) and factor in factors


def max_score(findings: list[dict[str, Any]]) -> int:
    scores = [finding.get("risk_score", 0) for finding in findings]
    numeric_scores = [score for score in scores if isinstance(score, int)]
    return max(numeric_scores, default=0)


def make_scenario(
    scenario_id: str,
    title: str,
    severity: str,
    summary: str,
    findings: list[dict[str, Any]],
    correlation_factors: list[str],
) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "max_finding_score": max_score(findings),
        "correlation_factors": correlation_factors,
        "related_findings": [
            {
                "scanner": finding.get("scanner", "unknown"),
                "rule_id": finding.get("rule_id", "unknown"),
                "file": finding.get("file", "unknown"),
                "line": finding.get("line", 0),
                "risk_score": finding.get("risk_score", 0),
                "priority": finding.get("priority", "unknown"),
            }
            for finding in findings
        ],
    }


def correlate_public_app_exposure(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    sast_findings = [finding for finding in findings if finding.get("category") == "sast"]
    public_iac_findings = [finding for finding in findings if has_factor(finding, "public_exposure")]

    if not sast_findings or not public_iac_findings:
        return None

    related_findings = sorted(
        [*sast_findings[:2], *public_iac_findings[:3]],
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )

    return make_scenario(
        scenario_id="public_app_exposure",
        title="Application weakness with public exposure context",
        severity="high",
        summary=(
            "Application-level findings are present while Terraform findings indicate public exposure. "
            "This increases prioritization because a vulnerable workload may be reachable from an untrusted network."
        ),
        findings=related_findings,
        correlation_factors=["sast_finding", "public_exposure", "cloud_context"],
    )


def correlate_privileged_access_risk(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    secret_findings = [finding for finding in findings if finding.get("category") == "secret"]
    broad_permission_findings = [finding for finding in findings if has_factor(finding, "broad_permissions")]

    if not secret_findings or not broad_permission_findings:
        return None

    related_findings = sorted(
        [*secret_findings[:2], *broad_permission_findings[:3]],
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )

    return make_scenario(
        scenario_id="privileged_access_risk",
        title="Secret material near broad cloud permissions",
        severity="medium",
        summary=(
            "Secret-like material and broad IAM permission findings exist in the same repository. "
            "The current secret is a controlled fixture, but the pattern demonstrates why credential exposure and over-permissioned cloud access should be reviewed together."
        ),
        findings=related_findings,
        correlation_factors=["secret_material", "broad_permissions", "credential_misuse_path"],
    )


def correlate_cloud_data_exposure(findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    data_exposure_findings = [
        finding
        for finding in findings
        if finding.get("category") == "iac"
        and ("s3" in str(finding.get("title", "")).lower() or "bucket" in str(finding.get("title", "")).lower())
        and (has_factor(finding, "public_exposure") or finding.get("priority") == "high")
    ]

    if not data_exposure_findings:
        return None

    related_findings = sorted(
        data_exposure_findings[:5],
        key=lambda finding: finding.get("risk_score", 0),
        reverse=True,
    )

    return make_scenario(
        scenario_id="cloud_data_exposure",
        title="Cloud storage exposure controls are weak",
        severity="medium",
        summary=(
            "Multiple storage-related IaC findings indicate weak public access, encryption, logging, or lifecycle controls. "
            "These findings should be reviewed as a storage exposure scenario instead of isolated checklist items."
        ),
        findings=related_findings,
        correlation_factors=["storage_controls", "public_exposure", "iac_cluster"],
    )


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scenarios = [
        correlate_public_app_exposure(findings),
        correlate_privileged_access_risk(findings),
        correlate_cloud_data_exposure(findings),
    ]
    return [scenario for scenario in scenarios if scenario is not None]


def write_json(output_path: Path, scenarios: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as output_file:
        json.dump({"correlated_risks": scenarios}, output_file, indent=2)
        output_file.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Correlate scored findings into risk scenarios.")
    parser.add_argument(
        "--input",
        default="scanner-results/scored-findings.json",
        help="Path to scored findings JSON.",
    )
    parser.add_argument(
        "--output",
        default="scanner-results/correlated-risks.json",
        help="Path where correlated risks should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    findings = load_findings(Path(args.input))
    scenarios = correlate_findings(findings)
    write_json(Path(args.output), scenarios)
    print(f"Correlated {len(scenarios)} risk scenario(s) to {args.output}")


if __name__ == "__main__":
    main()

