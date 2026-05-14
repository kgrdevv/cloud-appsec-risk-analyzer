resource "aws_security_group" "public_api" {
  name        = "demo-public-api"
  description = "Intentionally public API security group used for IaC scanning."

  ingress {
    description = "Public access to the sample API port for controlled exposure testing."
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Broad outbound access used as a controlled IaC finding."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "cloud-appsec-risk-analyzer-demo-reports"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_policy" "overprivileged_app_policy" {
  name        = "demo-overprivileged-app-policy"
  description = "Intentionally broad policy used for IaC scanning."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

