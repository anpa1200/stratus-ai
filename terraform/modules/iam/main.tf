data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── ECS Task Execution Role ──────────────────────────────────────────────────
# Used by ECS to pull the image and read SSM secrets

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "execution_basic" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow ECS to read the Anthropic API key from SSM
resource "aws_iam_role_policy" "execution_ssm" {
  name = "ssm-read-api-key"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ssm.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# ─── ECS Task Role ────────────────────────────────────────────────────────────
# Used by the assessment container itself — all read-only cloud API calls

resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_policy" "scanner" {
  name        = "${var.name_prefix}-scanner-policy"
  description = "Read-only permissions for StratusAI cloud security scanner"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ── Identity & Access Management ────────────────────────────────────
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:SimulatePrincipalPolicy"
        ]
        Resource = "*"
      },

      # ── S3 ────────────────────────────────────────────────────────────────
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketCORS",
          "s3:GetBucketEncryption",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "s3:GetBucketNotification",
          "s3:GetBucketObjectLockConfiguration",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketReplication",
          "s3:GetBucketVersioning",
          "s3:GetBucketWebsite",
          "s3:GetEncryptionConfiguration",
          "s3:GetLifecycleConfiguration",
          "s3:GetPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "s3control:GetPublicAccessBlock"
        ]
        Resource = "*"
      },

      # ── EC2 / VPC / Security Groups ───────────────────────────────────────
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:GetEbsEncryptionByDefault",
          "ec2:GetEbsDefaultKmsKeyId",
          "ec2:GetSnapshotBlockPublicAccessState"
        ]
        Resource = "*"
      },

      # ── RDS ───────────────────────────────────────────────────────────────
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = [
          "rds:Describe*",
          "rds:List*"
        ]
        Resource = "*"
      },

      # ── CloudTrail ────────────────────────────────────────────────────────
      {
        Sid    = "CloudTrailReadOnly"
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetEventSelectors",
          "cloudtrail:GetInsightSelectors",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:ListTags",
          "cloudtrail:ListTrails"
        ]
        Resource = "*"
      },

      # ── GuardDuty ─────────────────────────────────────────────────────────
      {
        Sid    = "GuardDutyReadOnly"
        Effect = "Allow"
        Action = [
          "guardduty:GetDetector",
          "guardduty:GetFindings",
          "guardduty:GetMasterAccount",
          "guardduty:ListDetectors",
          "guardduty:ListFindings"
        ]
        Resource = "*"
      },

      # ── Security Hub ──────────────────────────────────────────────────────
      {
        Sid    = "SecurityHubReadOnly"
        Effect = "Allow"
        Action = [
          "securityhub:DescribeHub",
          "securityhub:DescribeProducts",
          "securityhub:GetFindings",
          "securityhub:ListEnabledProductsForImport"
        ]
        Resource = "*"
      },

      # ── AWS Config ────────────────────────────────────────────────────────
      {
        Sid    = "ConfigReadOnly"
        Effect = "Allow"
        Action = [
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
      },

      # ── IAM Access Analyzer ───────────────────────────────────────────────
      {
        Sid    = "AccessAnalyzerReadOnly"
        Effect = "Allow"
        Action = [
          "access-analyzer:GetAnalyzer",
          "access-analyzer:GetFinding",
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindings"
        ]
        Resource = "*"
      },

      # ── STS (identity check) ──────────────────────────────────────────────
      {
        Sid      = "STSCallerIdentity"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      },

      # ── S3 write access for reports only ──────────────────────────────────
      {
        Sid    = "ReportsBucketWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "arn:aws:s3:::${var.reports_bucket_name}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "task_scanner" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.scanner.arn
}
