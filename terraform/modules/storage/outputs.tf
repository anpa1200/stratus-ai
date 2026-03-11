output "reports_bucket_name" {
  value       = aws_s3_bucket.reports.id
  description = "S3 bucket name for scan reports"
}

output "reports_bucket_arn" {
  value = aws_s3_bucket.reports.arn
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.stratusai.name
  description = "CloudWatch log group for ECS task output"
}

output "log_group_arn" {
  value = aws_cloudwatch_log_group.stratusai.arn
}

output "anthropic_api_key_ssm_arn" {
  value       = length(aws_ssm_parameter.anthropic_api_key) > 0 ? aws_ssm_parameter.anthropic_api_key[0].arn : ""
  description = "SSM Parameter ARN for the Anthropic API key"
}

output "anthropic_api_key_ssm_name" {
  value = length(aws_ssm_parameter.anthropic_api_key) > 0 ? aws_ssm_parameter.anthropic_api_key[0].name : ""
}
