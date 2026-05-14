# Example Outputs

This directory contains curated examples of generated analyzer output.

The GitHub Actions workflow produces the full runtime artifacts on every scan run. Those artifacts are uploaded from CI as `security-scan-artifacts` and include raw scanner JSON, normalized findings, scored findings, correlated risk scenarios, and the generated Markdown report.

The example report in this directory is committed so reviewers can quickly see the final output without downloading a workflow artifact first.

## Files

- [security-report.md](security-report.md): sample Markdown risk report generated from the current MVP scanner set.

## Notes

The sample report is based on intentionally vulnerable and risky test fixtures. The findings are expected and are used to demonstrate normalization, scoring, correlation, and reporting behavior.
