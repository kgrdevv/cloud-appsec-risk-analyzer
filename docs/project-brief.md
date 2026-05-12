# Project Brief

## Project Name

Cloud AppSec Risk Analyzer

## One-Sentence Description

Cloud AppSec Risk Analyzer demonstrates how AppSec findings, cloud exposure context, and DevSecOps pipeline automation can be combined into a prioritized risk report.

## Problem Statement

Security tools often generate large numbers of findings without explaining which issues are most important in a real environment. A vulnerable dependency, exposed secret, risky container image, or permissive IaC rule may be important on its own, but the actual risk becomes clearer when findings are correlated with exposure and workload context.

This project models that workflow in a small but complete portfolio system.

## Target Scenario

A sample API application is built and scanned in a CI/CD pipeline. The pipeline checks the application code, dependencies, secrets, container image, and Terraform configuration. Scanner outputs are normalized into a common format. A risk analyzer then correlates findings and generates a report that explains which risks should be prioritized first.

## MVP Goals

- Build a small sample API application.
- Add intentionally insecure examples for controlled testing.
- Containerize the application.
- Add Terraform files with intentionally risky cloud-style configuration.
- Run security scanners in a repeatable pipeline.
- Normalize scanner results into one JSON schema.
- Calculate basic risk scores.
- Generate a readable security report.
- Document how the project maps to real AppSec and DevSecOps practices.

## Out of Scope for MVP

- Real cloud deployment.
- Production-grade dashboard authentication.
- Full vulnerability management workflow.
- Complex asset inventory.
- Multi-cloud support.
- Enterprise ticketing integration.

## Tools Planned

- Python and FastAPI for the sample API and analyzer.
- Docker for container packaging.
- Terraform for infrastructure-as-code examples.
- GitHub Actions for CI/CD automation.
- Semgrep for SAST.
- Gitleaks for secret scanning.
- Trivy for container and dependency scanning.
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

