# Reporting

The report generator turns scored findings into a Markdown security risk report.

This is the first human-readable output of the analyzer. It is intended for review by engineers, security teams, or interviewers looking at the portfolio project.

## Input

The generator reads:

```text
scanner-results/scored-findings.json
```

This file is produced by the risk scoring step.

## Output

The generator writes:

```text
reports/security-report.md
```

The `reports/` directory is ignored by Git because reports are generated artifacts.

In GitHub Actions, the report is uploaded as part of the `security-scan-artifacts` workflow artifact.

## Report Sections

The first report version includes:

- executive summary;
- finding counts by priority;
- scanner coverage;
- findings overview table;
- detailed finding breakdown;
- recommended actions.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m analyzer.generate_report
```

Expected output:

```text
Generated report with 1 finding(s) at reports/security-report.md
```

## Current Limitation

The report currently reflects only findings that have already been normalized and scored. It does not run scanners by itself. A future pipeline step should chain scanning, normalization, scoring, and reporting.
