variable "gcp_project" {
  description = "GCP project ID to deploy StratusAI into"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for all resources"
  type        = string
  default     = "us-central1"
}

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "stratusai"
}

variable "environment" {
  description = "Deployment environment label (e.g. prod, staging)"
  type        = string
  default     = "prod"
}

# ─── Image ───────────────────────────────────────────────────────────────────

variable "image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

# ─── AI ──────────────────────────────────────────────────────────────────────

variable "enable_ai" {
  description = "Enable AI analysis. If false, --no-ai is passed and api_key is not required."
  type        = bool
  default     = true
}

variable "ai_model" {
  description = "AI model to use for analysis (claude-sonnet-4-6, gpt-4o, gemini-2.0-flash, etc.)"
  type        = string
  default     = "claude-sonnet-4-6"
}

variable "api_key" {
  description = "API key for the selected AI provider — stored in Secret Manager (encrypted)."
  type        = string
  sensitive   = true
  default     = ""
}

# ─── Scan ────────────────────────────────────────────────────────────────────

variable "scan_project" {
  description = "GCP project ID to scan (defaults to gcp_project if empty)"
  type        = string
  default     = ""
}

variable "scan_severity" {
  description = "Minimum severity to include in report (CRITICAL|HIGH|MEDIUM|LOW|INFO)"
  type        = string
  default     = "INFO"
}

variable "scan_modules" {
  description = "Scanner modules to run. Empty = all modules."
  type        = string
  default     = ""
}

variable "enable_external_scan" {
  description = "Enable external endpoint scanning"
  type        = bool
  default     = false
}

variable "external_scan_target" {
  description = "Hostname to scan in external mode"
  type        = string
  default     = ""
}

# ─── Storage ──────────────────────────────────────────────────────────────────

variable "report_retention_days" {
  description = "Days to retain scan reports in GCS"
  type        = number
  default     = 90
}

# ─── Scheduler ────────────────────────────────────────────────────────────────

variable "enable_scheduler" {
  description = "Enable Cloud Scheduler for automatic scans"
  type        = bool
  default     = false
}

variable "schedule_expression" {
  description = "Cloud Scheduler cron expression (e.g. '0 8 * * 1' = every Monday 08:00 UTC)"
  type        = string
  default     = "0 8 * * 1"
}

variable "notification_email" {
  description = "Email for scan completion notifications (optional)"
  type        = string
  default     = ""
}
