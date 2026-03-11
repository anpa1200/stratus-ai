variable "name_prefix" {
  type = string
}

variable "enable_versioning" {
  type    = bool
  default = true
}

variable "retention_days" {
  type    = number
  default = 90
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "anthropic_api_key" {
  type      = string
  sensitive = true
  default   = ""
}
