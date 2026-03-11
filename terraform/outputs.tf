output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "ECR repository URL — use this as your Docker registry"
}

output "reports_bucket_name" {
  value       = module.storage.reports_bucket_name
  description = "S3 bucket where scan reports are stored"
}

output "reports_bucket_console_url" {
  value       = "https://s3.console.aws.amazon.com/s3/buckets/${module.storage.reports_bucket_name}"
  description = "AWS Console URL to view reports"
}

output "ecs_cluster_name" {
  value       = module.ecs.cluster_name
  description = "ECS cluster name"
}

output "task_definition_arn" {
  value       = module.ecs.task_definition_arn
  description = "ECS task definition ARN"
}

output "task_definition_family" {
  value       = module.ecs.task_definition_family
  description = "ECS task definition family name"
}

output "security_group_id" {
  value       = module.ecs.security_group_id
  description = "Security group ID for ECS tasks"
}

output "log_group_name" {
  value       = module.storage.log_group_name
  description = "CloudWatch log group for scanner output"
}

output "scanner_policy_arn" {
  value       = module.iam.scanner_policy_arn
  description = "IAM policy ARN — attach to any role/user for standalone read-only access"
}

output "task_role_arn" {
  value       = module.iam.task_role_arn
  description = "ECS task IAM role ARN"
}

output "subnet_ids" {
  value       = local.resolved_subnet_ids
  description = "Subnet IDs used by ECS tasks"
}
