output "cluster_arn" {
  value       = aws_ecs_cluster.stratusai.arn
  description = "ECS cluster ARN"
}

output "cluster_name" {
  value = aws_ecs_cluster.stratusai.name
}

output "task_definition_arn" {
  value       = aws_ecs_task_definition.stratusai.arn
  description = "ECS task definition ARN (use with aws ecs run-task)"
}

output "task_definition_family" {
  value = aws_ecs_task_definition.stratusai.family
}

output "security_group_id" {
  value       = aws_security_group.ecs_task.id
  description = "Security group ID for ECS tasks"
}
