# Risk Scoring

The first risk scoring version converts normalized findings into scored findings.

This is intentionally simple. The goal is not to pretend that a small formula can replace real risk analysis. The goal is to create a transparent baseline that can be improved as more scanner context is added.

## Input

The scorer reads normalized findings from:

```text
scanner-results/normalized-findings.json
```

## Output

The scorer writes:

```text
scanner-results/scored-findings.json
```

Generated scanner and analyzer outputs are not committed to Git.

## Scoring Model

The current score is calculated from:

- scanner severity;
- estimated impact;
- estimated likelihood;
- scanner confidence;
- lightweight exposure/context bonuses.

The score is capped between `0` and `100`.

## Priority Mapping

| Score range | Priority |
| --- | --- |
| `0-39` | `low` |
| `40-69` | `medium` |
| `70-94` | `high` |
| `95-100` | `critical` |

## Current Context Bonuses

The first scoring version adds small bonuses for:

- findings in application code;
- injection-related finding titles;
- SQL injection CWE mapping.

These are deliberately conservative. Future versions should use richer context, such as whether a vulnerable route is public, admin-only, internet-exposed, connected to sensitive data, or tied to risky cloud/IaC configuration.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m analyzer.score_findings
```

Expected output for the current Semgrep finding:

```text
Scored 1 finding(s) to scanner-results/scored-findings.json
```

The current Semgrep SQL injection finding scores as `90/high`. It is intentionally not marked `critical` yet because the MVP has not added cross-tool exposure correlation.

## Current Limitation

The scoring model does not yet correlate findings across scanners. It scores each finding independently. Cross-tool correlation is planned after additional scanner outputs are added.
