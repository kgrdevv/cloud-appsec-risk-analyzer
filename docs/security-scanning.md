# Security Scanning

This document tracks the security scanning approach used by the project.

The first scanners added to the MVP are Semgrep, Checkov, Gitleaks, and Trivy. The goal is to start with a small number of understandable signals before adding more tools.

## Semgrep

Semgrep is used for static application security testing. In this project, it checks the sample FastAPI application for intentionally vulnerable code patterns.

Current local rule:

```text
semgrep-rules/python/sql-injection.yml
```

The first rule detects SQL queries built with dynamic string formatting before execution.

## Checkov

Checkov is used for infrastructure-as-code scanning. In this project, it checks the Terraform exposure model in:

```text
infra/terraform/
```

The Terraform sample intentionally includes risky cloud-style patterns, such as public ingress and broad IAM permissions. These are scan targets only and should not be deployed as written.

## Gitleaks

Gitleaks is used for secret scanning. In this project, it checks the repository for controlled secret-like test data.

Current configuration:

```text
gitleaks.toml
```

Current fixture:

```text
test-fixtures/secrets/leaky-config.txt
```

## Trivy

Trivy is used for dependency vulnerability scanning. In this project, it runs in filesystem mode and inspects dependency manifests such as:

```text
requirements.txt
```

## GitHub Actions

The repository includes a GitHub Actions workflow:

```text
.github/workflows/security-scan.yml
```

The workflow runs on:

- Pushes to `main`.
- Pull requests targeting `main`.
- Manual runs from the GitHub Actions tab.

Semgrep and Checkov run in container images in CI, so local Windows installation is not required for GitHub Actions scanning.

Current behavior:

- Uses the local rules from `semgrep-rules/`.
- Scans the `app/` directory.
- Runs Checkov against `infra/terraform/`.
- Runs Gitleaks against the repository contents.
- Runs Trivy against the repository filesystem.
- Writes JSON output to `scanner-results/semgrep.json`.
- Writes JSON output to `scanner-results/checkov.json`.
- Writes JSON output to `scanner-results/gitleaks.json`.
- Writes JSON output to `scanner-results/trivy.json`.
- Normalizes findings.
- Calculates risk scores.
- Generates a Markdown risk report.
- Uploads generated JSON files and the Markdown report as a workflow artifact named `security-scan-artifacts`.

The workflow is currently treated as a monitoring scan. The sample API intentionally contains a finding, so the first CI version focuses on producing machine-readable output instead of blocking every commit.

## Expected Findings

The Semgrep rule is expected to flag the admin search endpoint in:

```text
app/main.py
```

The relevant risk is not just "SQL injection exists." The more useful interpretation is:

- The vulnerable code is reachable through an admin-style endpoint.
- The endpoint accepts user-controlled input through the `q` query parameter.
- The query is built with string interpolation.
- The endpoint uses only a weak demo API key in the MVP.

This is the type of context the future analyzer should use when assigning priority.

Checkov is expected to flag one or more intentionally risky Terraform patterns in:

```text
infra/terraform/
```

Those findings provide cloud exposure context for later correlation.

Gitleaks is expected to flag the controlled demo secret fixture in:

```text
test-fixtures/secrets/leaky-config.txt
```

Trivy findings depend on the vulnerability database and current dependency versions. If no vulnerable dependency is present, Trivy may produce zero findings while still generating a valid JSON artifact.

## Run Locally

If Semgrep is installed locally:

```powershell
.\pipeline\run-semgrep.ps1
```

If PowerShell blocks local scripts, run the same helper with a process-level bypass:

```powershell
powershell -ExecutionPolicy Bypass -File .\pipeline\run-semgrep.ps1
```

The command writes JSON output to:

```text
scanner-results/semgrep.json
```

Scanner output is ignored by Git because it is generated runtime data.

## Install Options

For local development on Windows, Semgrep currently supports Windows as a beta platform. Before installing, configure Python to use UTF-8 by default:

```powershell
[System.Environment]::SetEnvironmentVariable('PYTHONUTF8', '1', 'User')
```

Then install Semgrep using one of the recommended tool installers:

```powershell
pipx install semgrep
```

or:

```powershell
uv tool install semgrep
```

Confirm the installation:

```powershell
semgrep --version
```

If local installation is awkward on Windows or on a very new Python version, it is reasonable to run Semgrep in CI or Docker instead.

Reference:

- Semgrep CE quickstart: `https://semgrep.dev/docs/getting-started/quickstart-ce`
