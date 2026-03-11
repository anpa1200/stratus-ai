"""
Minimal example: IAM role + ECR + ECS task definition only.
Run scans manually with: aws ecs run-task ...
No scheduler, no VPC created (uses default VPC).
"""

module "stratusai" {
  source = "../../"

  aws_region        = "us-east-1"
  name_prefix       = "stratusai"
  anthropic_api_key = var.anthropic_api_key

  # Use defaults: internal-only scan, us-east-1, all modules
  enable_scheduler = false
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

output "run_command" {
  value = <<-EOT

    # Trigger a manual scan:
    aws ecs run-task \
      --cluster ${module.stratusai.ecs_cluster_name} \
      --task-definition ${module.stratusai.task_definition_family} \
      --launch-type FARGATE \
      --network-configuration "awsvpcConfiguration={subnets=[${join(",", module.stratusai.subnet_ids)}],securityGroups=[${module.stratusai.security_group_id}],assignPublicIp=ENABLED}" \
      --region us-east-1

    # Watch logs:
    aws logs tail ${module.stratusai.log_group_name} --follow

    # Browse reports:
    aws s3 ls s3://${module.stratusai.reports_bucket_name}/reports/

  EOT
}
