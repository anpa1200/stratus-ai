resource "aws_ecr_repository" "stratusai" {
  name                 = var.name_prefix
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

# Lifecycle policy: keep only the N most recent images
resource "aws_ecr_lifecycle_policy" "cleanup" {
  repository = aws_ecr_repository.stratusai.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last ${var.retention_count} images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.retention_count
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# Allow ECS to pull from this repository
data "aws_iam_policy_document" "ecr_policy" {
  statement {
    sid    = "AllowECSPull"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = var.task_execution_role_arns
    }
    actions = [
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
    ]
  }
}

resource "aws_ecr_repository_policy" "stratusai" {
  repository = aws_ecr_repository.stratusai.name
  policy     = data.aws_iam_policy_document.ecr_policy.json
}
