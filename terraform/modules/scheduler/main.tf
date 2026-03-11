data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ─── EventBridge Scheduler IAM Role ──────────────────────────────────────────

resource "aws_iam_role" "scheduler" {
  name = "${var.name_prefix}-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "run-ecs-task"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = "${replace(var.task_definition_arn, "/:\\d+$/", "")}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [var.task_role_arn, var.execution_role_arn]
      }
    ]
  })
}

# ─── EventBridge Rule ─────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-scheduled-scan"
  description         = "StratusAI scheduled security assessment"
  schedule_expression = var.schedule_expression
  state               = "ENABLED"
}

resource "aws_cloudwatch_event_target" "ecs_task" {
  rule     = aws_cloudwatch_event_rule.schedule.name
  arn      = var.cluster_arn
  role_arn = aws_iam_role.scheduler.arn

  ecs_target {
    task_definition_arn = var.task_definition_arn
    task_count          = 1
    launch_type         = "FARGATE"

    network_configuration {
      subnets          = var.subnet_ids
      security_groups  = [var.security_group_id]
      assign_public_ip = true
    }

    enable_execute_command = false
  }
}

# ─── SNS Notification (optional) ─────────────────────────────────────────────

resource "aws_sns_topic" "notifications" {
  count = var.notification_email != "" ? 1 : 0
  name  = "${var.name_prefix}-scan-notifications"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.notifications[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# CloudWatch alarm on ECS task failure
resource "aws_cloudwatch_metric_alarm" "task_failure" {
  count = var.notification_email != "" ? 1 : 0

  alarm_name          = "${var.name_prefix}-scan-failure"
  alarm_description   = "StratusAI scan task failed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  dimensions = {
    ClusterName = var.cluster_name
  }

  alarm_actions = [aws_sns_topic.notifications[0].arn]
}
