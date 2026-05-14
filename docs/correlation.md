# Correlation

Correlation turns scored findings into risk scenarios.

The goal is to move beyond a flat list of scanner findings and explain why certain combinations deserve attention.

## Input

The correlation step reads:

```text
scanner-results/scored-findings.json
```

## Output

The correlation step writes:

```text
scanner-results/correlated-risks.json
```

## Current Scenarios

The first correlation version detects:

- `public_app_exposure`: application security findings exist alongside public exposure IaC findings;
- `privileged_access_risk`: secret-like material exists alongside broad IAM permission findings;
- `cloud_data_exposure`: storage-related IaC findings cluster around weak public access or data protection controls.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m analyzer.correlate_findings
```

Expected output depends on the current scanner findings. With the current MVP fixtures, the analyzer should identify multiple correlated risk scenarios.

## Current Limitation

Correlation is rule-based. It does not yet build a full asset graph or prove that a specific vulnerable endpoint is deployed behind a specific Terraform resource. That asset graph is a future enhancement.

