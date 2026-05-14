# Dependency Scanning

Trivy is used for dependency vulnerability scanning.

The MVP runs Trivy in filesystem mode against the repository. This allows the scanner to inspect dependency manifests such as:

```text
requirements.txt
```

## CI Behavior

GitHub Actions runs Trivy with vulnerability scanning enabled:

```text
trivy fs /src --scanners vuln --format json
```

The raw JSON output is written to:

```text
scanner-results/trivy.json
```

The analyzer normalizes this output to:

```text
scanner-results/trivy-normalized-findings.json
```

## Analyzer Category

Trivy vulnerability findings are normalized into the `sca` category.

This keeps dependency vulnerability findings separate from:

- `sast` findings from Semgrep;
- `iac` findings from Checkov;
- `secret` findings from Gitleaks.

## Current Limitation

The MVP starts with filesystem dependency scanning. Container image scanning can be added later after the Docker build is part of the CI workflow.

