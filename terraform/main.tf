data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── Optional: auto-discover default VPC / subnets ────────────────────────────
# Used when vpc_id / subnet_ids are not provided

data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.vpc_id == "" ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
  filter {
    name   = "map-public-ip-on-launch"
    values = ["true"]
  }
}

locals {
  resolved_vpc_id    = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.default[0].id
  resolved_subnet_ids = length(var.subnet_ids) > 0 ? var.subnet_ids : data.aws_subnets.default[0].ids
}

# ─── Storage (S3 + CloudWatch + SSM) ─────────────────────────────────────────

module "storage" {
  source = "./modules/storage"

  name_prefix        = var.name_prefix
  enable_versioning  = var.enable_s3_versioning
  retention_days     = var.report_retention_days
  log_retention_days = 30
  anthropic_api_key  = var.anthropic_api_key
}

# ─── IAM Roles ────────────────────────────────────────────────────────────────

module "iam" {
  source = "./modules/iam"

  name_prefix         = var.name_prefix
  reports_bucket_name = module.storage.reports_bucket_name
}

# ─── ECR Repository ───────────────────────────────────────────────────────────

module "ecr" {
  source = "./modules/ecr"

  name_prefix              = var.name_prefix
  retention_count          = var.ecr_retention_count
  task_execution_role_arns = [module.iam.execution_role_arn]
}

# ─── ECS Cluster + Task Definition ────────────────────────────────────────────

module "ecs" {
  source = "./modules/ecs"

  name_prefix               = var.name_prefix
  vpc_id                    = local.resolved_vpc_id
  subnet_ids                = local.resolved_subnet_ids
  task_role_arn             = module.iam.task_role_arn
  execution_role_arn        = module.iam.execution_role_arn
  ecr_repository_url        = module.ecr.repository_url
  image_tag                 = var.ecr_image_tag
  task_cpu                  = var.task_cpu
  task_memory               = var.task_memory
  log_group_name            = module.storage.log_group_name
  reports_bucket_name       = module.storage.reports_bucket_name
  anthropic_api_key_ssm_arn = module.storage.anthropic_api_key_ssm_arn
  scan_mode                 = var.enable_external_scan ? "both" : "internal"
  scan_regions              = var.scan_regions
  scan_modules              = var.scan_modules
  scan_severity             = var.scan_severity
  claude_model              = var.claude_model
  enable_external_scan      = var.enable_external_scan
  external_scan_target      = var.external_scan_target
  enable_ai                 = var.enable_ai
}

# ─── Scheduler (optional) ─────────────────────────────────────────────────────

module "scheduler" {
  count  = var.enable_scheduler ? 1 : 0
  source = "./modules/scheduler"

  name_prefix         = var.name_prefix
  cluster_arn         = module.ecs.cluster_arn
  cluster_name        = module.ecs.cluster_name
  task_definition_arn = module.ecs.task_definition_arn
  task_role_arn       = module.iam.task_role_arn
  execution_role_arn  = module.iam.execution_role_arn
  subnet_ids          = local.resolved_subnet_ids
  security_group_id   = module.ecs.security_group_id
  schedule_expression = var.schedule_expression
  notification_email  = var.notification_email
}
