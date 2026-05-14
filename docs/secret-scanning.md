# Secret Scanning

Gitleaks is used to detect committed secret-like material.

The MVP includes a controlled fixture in:

```text
test-fixtures/secrets/leaky-config.txt
```

The value in that file is not a real credential. It exists so the pipeline can produce a repeatable secret scanning finding.

## Configuration

The Gitleaks configuration lives in:

```text
gitleaks.toml
```

The current rule detects the demo secret format:

```text
DEMO_SECRET_ACCESS_TOKEN=demo_secret_...
```

## CI Behavior

GitHub Actions runs Gitleaks in monitoring mode. It writes JSON output to:

```text
scanner-results/gitleaks.json
```

The analyzer then normalizes this output to:

```text
scanner-results/gitleaks-normalized-findings.json
```

The finding is merged with Semgrep and Checkov output before risk scoring.

## Risk Scoring

Secret findings receive a `credential_material` risk factor. Findings under `test-fixtures/` also receive a `controlled_test_fixture` factor so the report explains why the value exists in the repository.

