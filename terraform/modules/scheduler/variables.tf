variable "name_prefix" {
  type = string
}

variable "cluster_arn" {
  type = string
}

variable "cluster_name" {
  type = string
}

variable "task_definition_arn" {
  type = string
}

variable "task_role_arn" {
  type = string
}

variable "execution_role_arn" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_id" {
  type = string
}

variable "schedule_expression" {
  type    = string
  default = "rate(7 days)"
}

variable "notification_email" {
  type    = string
  default = ""
}
