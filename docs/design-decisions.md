# Design Decisions

This document tracks key project decisions and trade-offs. The goal is to keep the project honest: small enough to finish, but realistic enough to explain in an AppSec or DevSecOps interview.

## 1. Build a Small API Before Building the Pipeline

Decision: start with a small FastAPI application before adding scanners and CI/CD automation.

Reasoning: security pipelines need a real target. A pipeline that only runs tools without a meaningful application does not show much engineering thinking. The sample API gives the project code, dependencies, routes, input validation, a database interaction, and controlled weaknesses to inspect.

Trade-off: the API is intentionally simple. It is not meant to be a production order system.

## 2. Use Controlled Weaknesses Instead of Random Vulnerable Code

Decision: include a small number of intentional security weaknesses.

Reasoning: the project needs findings that can be detected, normalized, scored, and explained. Controlled weaknesses make the pipeline repeatable and allow the documentation to explain why each issue exists.

Current examples:

- Weak demo API key fallback.
- Unsafe SQL string construction in an admin search endpoint.
- Minimal admin authentication logic.

Trade-off: these weaknesses must be clearly documented so they are not mistaken for accidental poor coding.

## 3. Keep the MVP Local First

Decision: avoid deploying to a real cloud account in the MVP.

Reasoning: the goal is to demonstrate AppSec and DevSecOps thinking without requiring cloud costs, credentials, or account setup. Terraform examples can still model cloud exposure patterns without provisioning real infrastructure.

Trade-off: the MVP will not prove runtime cloud deployment. That can be added later if needed.

## 4. Prioritize Risk Correlation Over Tool Count

Decision: use a small scanner set first instead of adding every possible security tool.

Reasoning: the project should not be a checklist of scanners. The more interesting part is how findings are normalized and prioritized. A small number of well-understood tools is enough for the first version.

Initial tools:

- Semgrep for SAST.
- Gitleaks for secret scanning.
- Trivy for dependency and container scanning.
- Checkov for infrastructure-as-code scanning.

Trade-off: some security domains will be represented lightly in the MVP.

## 5. Use Python for Both the API and Analyzer

Decision: use Python for the sample API and the future risk analyzer.

Reasoning: Python is practical for API development, JSON parsing, report generation, and security automation. Using one language keeps the MVP easier to maintain and explain.

Trade-off: Go could be a good option for a production-grade CLI, but it would add extra complexity at this stage.

## 6. Treat Documentation as Part of the Product

Decision: write documentation alongside the code.

Reasoning: this is a portfolio project. The repository should show not only what was built, but also why certain choices were made. Clear documentation helps reviewers understand the AppSec reasoning behind the implementation.

Trade-off: documentation takes time, but it makes the project easier to review and discuss.

