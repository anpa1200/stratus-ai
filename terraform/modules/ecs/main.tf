data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ─── ECS Cluster ──────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "stratusai" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "stratusai" {
  cluster_name       = aws_ecs_cluster.stratusai.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# ─── Security Group for ECS tasks ─────────────────────────────────────────────

resource "aws_security_group" "ecs_task" {
  name        = "${var.name_prefix}-ecs-task"
  description = "StratusAI ECS task — outbound to AWS APIs and Anthropic"
  vpc_id      = var.vpc_id

  # Allow all outbound (needed for AWS SDK calls, Anthropic API, nmap)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }
}

# ─── ECS Task Definition ──────────────────────────────────────────────────────

locals {
  # Build CLI args from variables
  cli_args = concat(
    ["--provider", "aws", "--mode", var.scan_mode],
    var.scan_regions != "" ? ["--region", var.scan_regions] : [],
    var.scan_modules != "" ? ["--modules", var.scan_modules] : [],
    var.scan_modules == "" ? [] : [],
    ["--severity", var.scan_severity],
    ["--model", var.claude_model],
    var.enable_external_scan && var.external_scan_target != "" ? ["--target", var.external_scan_target] : [],
    var.enable_ai ? [] : ["--no-ai"],
    ["--output-dir", "/tmp/output"],
  )

  container_environment = [
    { name = "AWS_DEFAULT_REGION", value = data.aws_region.current.name },
    { name = "OUTPUT_S3_BUCKET", value = var.reports_bucket_name },
    { name = "OUTPUT_S3_PREFIX", value = "reports/" },
  ]

  # API key injected from SSM (not hardcoded in task def)
  container_secrets = var.anthropic_api_key_ssm_arn != "" ? [
    {
      name      = "ANTHROPIC_API_KEY"
      valueFrom = var.anthropic_api_key_ssm_arn
    }
  ] : []
}

resource "aws_ecs_task_definition" "stratusai" {
  family                   = var.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  task_role_arn            = var.task_role_arn
  execution_role_arn       = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "stratusai"
      image     = "${var.ecr_repository_url}:${var.image_tag}"
      essential = true

      command     = local.cli_args
      environment = local.container_environment
      secrets     = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # No ports needed — outbound only
      portMappings = []

      # Upload reports to S3 via entrypoint wrapper
      entryPoint = ["/bin/sh", "-c"]
      command = [
        join(" ", concat(
          ["/opt/venv/bin/python -m assessment.cli"],
          local.cli_args,
          ["&&"],
          var.reports_bucket_name != "" ? [
            "aws s3 cp /tmp/output/ s3://${var.reports_bucket_name}/reports/ --recursive --exclude '*.tmp'"
          ] : ["echo 'No S3 bucket configured, skipping upload'"]
        ))
      ]

      healthCheck = null
      readonlyRootFilesystem = false
      privileged             = false
    }
  ])

  lifecycle {
    create_before_destroy = true
  }
}
