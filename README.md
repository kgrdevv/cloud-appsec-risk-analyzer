# Cloud AppSec Risk Analyzer

Cloud AppSec Risk Analyzer is a portfolio DevSecOps project that demonstrates how application security, cloud exposure analysis, and CI/CD security automation can be combined to prioritize real-world risks across code, dependencies, containers, secrets, and infrastructure-as-code.

## Purpose

Modern security teams receive findings from many tools: SAST scanners, secret scanners, container scanners, dependency scanners, and IaC scanners. Each tool reports useful data, but the findings are often disconnected from business and cloud exposure context.

This project shows how those signals can be normalized, correlated, and converted into a risk-focused report that helps answer a practical question:

> Which security findings matter most, and why?

## MVP Scope

The first version of this project will include:

- A sample API application with intentionally vulnerable patterns.
- A Docker image for the sample application.
- Terraform configuration with intentionally risky cloud-style settings.
- A CI/CD security pipeline.
- Security scans using Semgrep, Gitleaks, Trivy, and Checkov.
- A parser that normalizes scanner output into a single JSON format.
- A simple risk scoring engine.
- A generated Markdown or HTML risk report.
- Documentation mapping the project to AppSec and DevSecOps practices.

## Planned Architecture

```mermaid
flowchart LR
    A["Sample API App"] --> B["CI/CD Pipeline"]
    C["Terraform / IaC"] --> B
    D["Docker Image"] --> B
    B --> E["Security Scanners"]
    E --> F["Normalized Findings JSON"]
    F --> G["Risk Scoring Engine"]
    G --> H["Risk Report / Dashboard"]
```

## Security Domains Covered

- SAST: insecure code patterns and application-level weaknesses.
- SCA: vulnerable third-party dependencies.
- Secret scanning: exposed credentials and sensitive values.
- Container scanning: vulnerable packages inside images.
- IaC scanning: risky infrastructure-as-code configuration.
- Risk correlation: combining technical findings with exposure context.

## Repository Status

This repository is in the early MVP stage. The project brief and sample API application have been started.

## Current Components

```text
app/                Sample FastAPI application used as the scan target
analyzer/           Future scanner output parser and risk scoring engine
docs/               Project brief and supporting documentation
infra/terraform/    Future intentionally risky IaC examples
pipeline/           Future local pipeline helper scripts
Dockerfile          Container definition for the sample API
requirements.txt    Python dependencies
```

Useful documentation:

- [Project brief](docs/project-brief.md)
- [Design decisions](docs/design-decisions.md)
- [API testing notes](docs/api-testing.md)

## Run the Sample API

After Python is installed:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

If dependency installation fails partway through, remove the local `.venv` directory, create it again, and rerun the install command.

Open:

```text
http://127.0.0.1:8000/docs
```

The API is intentionally small and includes controlled weaknesses so later pipeline stages can detect and prioritize security findings.
