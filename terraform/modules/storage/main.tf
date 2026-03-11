data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── Reports S3 Bucket ────────────────────────────────────────────────────────

resource "aws_s3_bucket" "reports" {
  bucket = "${var.name_prefix}-reports-${data.aws_caller_identity.current.account_id}"

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = var.enable_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-old-reports"
    status = "Enabled"

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# Deny non-TLS access
resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.reports]
}

# ─── CloudWatch Log Group ─────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "stratusai" {
  name              = "/ecs/${var.name_prefix}"
  retention_in_days = var.log_retention_days
}

# ─── SSM Parameter for Anthropic API key ─────────────────────────────────────

resource "aws_ssm_parameter" "anthropic_api_key" {
  count = var.anthropic_api_key != "" ? 1 : 0

  name        = "/${var.name_prefix}/anthropic_api_key"
  type        = "SecureString"
  value       = var.anthropic_api_key
  description = "Anthropic API key for StratusAI AI analysis"

  lifecycle {
    ignore_changes = [value]  # Allow manual rotation without Terraform drift
  }
}
