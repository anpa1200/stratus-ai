"""
Scheduled example: full deployment with weekly scans + email notifications.
"""

module "stratusai" {
  source = "../../"

  aws_region        = var.aws_region
  name_prefix       = "stratusai"
  environment       = "prod"
  anthropic_api_key = var.anthropic_api_key

  # Scan configuration
  scan_regions  = var.aws_region
  scan_severity = "LOW"
  claude_model  = "claude-sonnet-4-6"

  # Optional: add external endpoint scan alongside internal
  enable_external_scan = var.target_domain != ""
  external_scan_target = var.target_domain

  # Scheduled weekly scan every Monday at 08:00 UTC
  enable_scheduler    = true
  schedule_expression = "cron(0 8 ? * MON *)"
  notification_email  = var.notification_email

  # Retain 6 months of reports
  report_retention_days = 180
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
}

variable "notification_email" {
  type    = string
  default = ""
}

variable "target_domain" {
  type    = string
  default = ""
}

output "ecr_repository_url" {
  value = module.stratusai.ecr_repository_url
}

output "reports_bucket" {
  value = module.stratusai.reports_bucket_name
}
