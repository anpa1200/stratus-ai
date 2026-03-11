output "task_role_arn" {
  value       = aws_iam_role.task.arn
  description = "ARN of the ECS task role (used by the scanner container)"
}

output "execution_role_arn" {
  value       = aws_iam_role.execution.arn
  description = "ARN of the ECS execution role (used by ECS to pull image + secrets)"
}

output "task_role_name" {
  value = aws_iam_role.task.name
}

output "scanner_policy_arn" {
  value       = aws_iam_policy.scanner.arn
  description = "ARN of the read-only scanner IAM policy"
}
