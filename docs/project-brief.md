# Project Brief

## Project Name

Cloud AppSec Risk Analyzer

## One-Sentence Description

Cloud AppSec Risk Analyzer demonstrates how AppSec findings, cloud exposure context, and DevSecOps pipeline automation can be combined into a prioritized risk report.

## Problem Statement

Security tools often generate large numbers of findings without explaining which issues are most important in a real environment. A vulnerable dependency, exposed secret, insecure code path, or permissive IaC rule may be important on its own, but the actual risk becomes clearer when findings are correlated with exposure and workload context.

This project models that workflow in a small but complete portfolio system.

## Target Scenario

A sample API application and Terraform exposure model are scanned in a CI/CD pipeline. The pipeline checks application code, dependencies, secrets, and infrastructure-as-code. Scanner outputs are normalized into a common format, scored, correlated into risk scenarios, and published as a Markdown report.

## Implemented MVP

- Small FastAPI sample application.
- Dockerfile for local/containerized API packaging.
- Intentionally insecure examples for controlled testing.
- Terraform files with intentionally risky cloud-style configuration.
- GitHub Actions workflow that runs Semgrep, Checkov, Gitleaks, and Trivy.
- Scanner-specific normalizers plus a merged finding schema.
- Risk scoring for normalized findings.
- Rule-based correlation into risk scenarios.
- Markdown security report uploaded as a workflow artifact.
- Supporting documentation for scanning, scoring, correlation, and reporting.

## Out of Scope for MVP

- Real cloud deployment.
- Production-grade dashboard authentication.
- Full vulnerability management workflow.
- Complex asset inventory.
- Multi-cloud support.
- Enterprise ticketing integration.

## Tools Used

- Python and FastAPI for the sample API and analyzer.
- Docker for container packaging.
- Terraform for infrastructure-as-code examples.
- GitHub Actions for CI/CD automation.
- Semgrep for SAST.
- Gitleaks for secret scanning.
- Trivy for filesystem dependency scanning.
- Checkov for IaC scanning.

## Interview Value

This project is designed to show more than tool usage. It demonstrates the ability to think like an AppSec and DevSecOps engineer:

- Identify security signals across the SDLC.
- Automate security checks in CI/CD.
- Understand the difference between raw findings and prioritized risk.
- Connect application security with cloud exposure.
- Communicate security results in a way that engineering teams can act on.

## Future Enhancements

- HTML dashboard with filtering and severity views.
- SARIF export for GitHub code scanning.
- OpenSSF Scorecard integration.
- OWASP ASVS and SAMM mapping.
- OPA or Conftest policy gates.
- Example pull request workflow with failing and passing security gates.
