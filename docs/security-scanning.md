# Security Scanning

This document tracks the security scanning approach used by the project.

The first scanner added to the MVP is Semgrep. The goal is to start with one understandable signal before adding more tools.

## Semgrep

Semgrep is used for static application security testing. In this project, it checks the sample FastAPI application for intentionally vulnerable code patterns.

Current local rule:

```text
semgrep-rules/python/sql-injection.yml
```

The first rule detects SQL queries built with dynamic string formatting before execution.

## Expected Finding

The rule is expected to flag the admin search endpoint in:

```text
app/main.py
```

The relevant risk is not just "SQL injection exists." The more useful interpretation is:

- The vulnerable code is reachable through an admin-style endpoint.
- The endpoint accepts user-controlled input through the `q` query parameter.
- The query is built with string interpolation.
- The endpoint uses only a weak demo API key in the MVP.

This is the type of context the future analyzer should use when assigning priority.

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
