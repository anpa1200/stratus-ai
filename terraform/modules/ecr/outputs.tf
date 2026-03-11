output "repository_url" {
  value       = aws_ecr_repository.stratusai.repository_url
  description = "ECR repository URL (use as Docker registry)"
}

output "repository_name" {
  value = aws_ecr_repository.stratusai.name
}

output "registry_id" {
  value = aws_ecr_repository.stratusai.registry_id
}
