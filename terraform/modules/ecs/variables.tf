variable "name_prefix" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type    = list(string)
  default = []
}

variable "task_role_arn" {
  type = string
}

variable "execution_role_arn" {
  type = string
}

variable "ecr_repository_url" {
  type = string
}

variable "image_tag" {
  type    = string
  default = "latest"
}

variable "task_cpu" {
  type    = number
  default = 512
}

variable "task_memory" {
  type    = number
  default = 1024
}

variable "log_group_name" {
  type = string
}

variable "reports_bucket_name" {
  type    = string
  default = ""
}

variable "anthropic_api_key_ssm_arn" {
  type    = string
  default = ""
}

variable "scan_mode" {
  type    = string
  default = "internal"
}

variable "scan_regions" {
  type    = string
  default = ""
}

variable "scan_modules" {
  type    = string
  default = ""
}

variable "scan_severity" {
  type    = string
  default = "INFO"
}

variable "claude_model" {
  type    = string
  default = "claude-sonnet-4-6"
}

variable "enable_external_scan" {
  type    = bool
  default = false
}

variable "external_scan_target" {
  type    = string
  default = ""
}

variable "enable_ai" {
  type    = bool
  default = true
}
