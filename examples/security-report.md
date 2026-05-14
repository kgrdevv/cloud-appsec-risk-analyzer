# Security Risk Report

This is a curated example of the Markdown report produced by Cloud AppSec Risk Analyzer.

The full CI artifact also includes raw scanner output, normalized findings, scored findings, and correlated risk scenarios.

## Executive Summary

- Total findings: `24`
- Critical: `0`
- High: `10`
- Medium: `14`
- Low: `0`

Scanner execution:

- `checkov`: completed, `22` finding(s)
- `gitleaks`: completed, `1` finding(s)
- `semgrep`: completed, `1` finding(s)
- `trivy`: completed, `0` finding(s)

## Findings Overview

| Priority | Score | Scanner | Rule | Location |
| --- | ---: | --- | --- | --- |
| high | 90 | semgrep | semgrep-rules.python.python.sqlite.dynamic-sql-query | app/main.py:118 |
| high | 75 | checkov | CKV_AWS_54 | infra/terraform/main.tf:26 |
| high | 75 | checkov | CKV_AWS_56 | infra/terraform/main.tf:26 |
| high | 75 | checkov | CKV_AWS_53 | infra/terraform/main.tf:26 |
| high | 75 | checkov | CKV_AWS_62 | infra/terraform/main.tf:35 |
| high | 75 | checkov | CKV_AWS_289 | infra/terraform/main.tf:35 |
| high | 75 | checkov | CKV_AWS_286 | infra/terraform/main.tf:35 |
| medium | 65 | checkov | CKV_AWS_382 | infra/terraform/main.tf:1 |
| medium | 65 | checkov | CKV_AWS_288 | infra/terraform/main.tf:35 |
| medium | 65 | gitleaks | demo-secret-access-token | test-fixtures/secrets/leaky-config.txt:4 |

## Correlated Risk Scenarios

### 1. Application weakness with public exposure context

- Severity: `high`
- Scenario ID: `public_app_exposure`
- Max related finding score: `90`
- Correlation factors: `sast_finding`, `public_exposure`, `cloud_context`

Summary: Application-level findings are present while Terraform findings indicate public exposure. This increases prioritization because a vulnerable workload may be reachable from an untrusted network.

Related findings:

- `semgrep` `semgrep-rules.python.python.sqlite.dynamic-sql-query` at `app/main.py:118` with score `90`
- `checkov` `CKV_AWS_54` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV_AWS_56` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV_AWS_53` at `infra/terraform/main.tf:26` with score `75`

### 2. Secret material near broad cloud permissions

- Severity: `medium`
- Scenario ID: `privileged_access_risk`
- Max related finding score: `75`
- Correlation factors: `secret_material`, `broad_permissions`, `credential_misuse_path`

Summary: Secret-like material and broad IAM permission findings exist in the same repository. The current secret is a controlled fixture, but the pattern demonstrates why credential exposure and over-permissioned cloud access should be reviewed together.

Related findings:

- `checkov` `CKV_AWS_62` at `infra/terraform/main.tf:35` with score `75`
- `checkov` `CKV_AWS_289` at `infra/terraform/main.tf:35` with score `75`
- `checkov` `CKV_AWS_286` at `infra/terraform/main.tf:35` with score `75`
- `gitleaks` `demo-secret-access-token` at `test-fixtures/secrets/leaky-config.txt:4` with score `65`

### 3. Cloud storage exposure controls are weak

- Severity: `medium`
- Scenario ID: `cloud_data_exposure`
- Max related finding score: `75`
- Correlation factors: `storage_controls`, `public_exposure`, `iac_cluster`

Summary: Multiple storage-related IaC findings indicate weak public access, encryption, logging, or lifecycle controls. These findings should be reviewed as a storage exposure scenario instead of isolated checklist items.

Related findings:

- `checkov` `CKV_AWS_54` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV_AWS_56` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV_AWS_53` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV_AWS_55` at `infra/terraform/main.tf:26` with score `75`
- `checkov` `CKV2_AWS_6` at `infra/terraform/main.tf:22` with score `75`

## Example Finding Detail

### SQL query is built with string interpolation before execution.

- Priority: `high`
- Risk score: `90`
- Scanner severity: `high`
- Scanner: `semgrep`
- Rule ID: `semgrep-rules.python.python.sqlite.dynamic-sql-query`
- Location: `app/main.py:118`
- Category: `sast`
- CWE: `CWE-89`
- OWASP: `A03:2021 - Injection`
- Confidence: `high`
- Impact: `high`
- Likelihood: `medium`
- Risk factors: `application_code`, `injection_pattern`, `sql_injection_cwe`

## Recommended Actions

1. Review high-priority findings first and confirm whether the affected asset is reachable.
2. Replace dynamic SQL construction with parameterized queries.
3. Replace demo authentication with a real authentication and authorization model before production use.
4. Restrict public network exposure in Terraform unless a public route is explicitly required.
5. Replace wildcard IAM permissions with least-privilege actions and resources.
6. Confirm whether detected secret material is a controlled fixture or a real credential.
7. Remove real credentials from version control and rotate any exposed secret values.
8. Feed additional scanner outputs into the analyzer to improve prioritization confidence.
