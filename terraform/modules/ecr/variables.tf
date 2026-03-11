variable "name_prefix" {
  type = string
}

variable "retention_count" {
  type    = number
  default = 5
}

variable "task_execution_role_arns" {
  type    = list(string)
  default = []
}
