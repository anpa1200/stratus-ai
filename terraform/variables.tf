variable "aws_region" {
  description = "AWS region to deploy StratusAI infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment label (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "stratusai"
}

# ─── ECR ─────────────────────────────────────────────────────────────────────

variable "ecr_image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "ecr_retention_count" {
  description = "Number of Docker image versions to retain in ECR"
  type        = number
  default     = 5
}

# ─── ECS ─────────────────────────────────────────────────────────────────────

variable "vpc_id" {
  description = "VPC ID where ECS tasks will run. Leave empty to create a new VPC."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "Subnet IDs for ECS Fargate tasks. Must be in the specified VPC."
  type        = list(string)
  default     = []
}

variable "task_cpu" {
  description = "ECS task CPU units (256 = 0.25 vCPU)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "ECS task memory in MiB"
  type        = number
  default     = 1024
}

variable "scan_regions" {
  description = "AWS regions to scan (comma-separated string passed to the CLI)"
  type        = string
  default     = "us-east-1"
}

variable "scan_modules" {
  description = "Scanner modules to run. Empty = all modules."
  type        = string
  default     = ""
}

variable "scan_severity" {
  description = "Minimum severity to include in report (CRITICAL|HIGH|MEDIUM|LOW|INFO)"
  type        = string
  default     = "INFO"
}

variable "claude_model" {
  description = "Claude model to use for AI analysis"
  type        = string
  default     = "claude-sonnet-4-6"
}

variable "enable_external_scan" {
  description = "Enable external endpoint scanning"
  type        = bool
  default     = false
}

variable "external_scan_target" {
  description = "Hostname to scan in external mode (if enable_external_scan is true)"
  type        = string
  default     = ""
}

# ─── Storage ──────────────────────────────────────────────────────────────────

variable "report_retention_days" {
  description = "Days to retain scan reports in S3"
  type        = number
  default     = 90
}

variable "enable_s3_versioning" {
  description = "Enable S3 versioning on the reports bucket"
  type        = bool
  default     = true
}

# ─── Secrets ──────────────────────────────────────────────────────────────────

variable "anthropic_api_key" {
  description = "Anthropic API key — stored in SSM Parameter Store (encrypted). Required unless enable_ai is false."
  type        = string
  sensitive   = true
  default     = ""
}

variable "enable_ai" {
  description = "Enable AI analysis. If false, --no-ai is passed and anthropic_api_key is not required."
  type        = bool
  default     = true
}

# ─── Scheduler ────────────────────────────────────────────────────────────────

variable "enable_scheduler" {
  description = "Enable EventBridge scheduled scans"
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "EventBridge schedule (rate or cron). e.g. 'rate(7 days)' or 'cron(0 8 * * ? *)'"
  type        = string
  default     = "rate(7 days)"
}

# ─── Notifications ────────────────────────────────────────────────────────────

variable "notification_email" {
  description = "Email address for scan completion notifications (optional, creates SNS topic)"
  type        = string
  default     = ""
}
