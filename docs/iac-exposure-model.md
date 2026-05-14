# IaC Exposure Model

The Terraform configuration in `infra/terraform/` is intentionally small and intentionally risky.

It is not meant to be applied to a real cloud account. Its purpose is to model cloud exposure signals that the analyzer can later correlate with application security findings.

## Current Demo Resources

The MVP Terraform sample includes:

- a public API-style security group;
- broad outbound network access;
- an S3 bucket with public access protections disabled;
- an IAM policy with wildcard permissions.

## Why This Exists

SAST can identify application weaknesses, but it does not answer whether the affected workload is exposed. IaC scanning adds cloud context.

Example risk story:

```text
Semgrep finds SQL injection in the API code.
Checkov finds public ingress in the Terraform model.
The analyzer can raise priority because the vulnerable workload is modeled as public-facing.
```

## Safety Note

The Terraform files are scan targets only. They should not be deployed as written.

