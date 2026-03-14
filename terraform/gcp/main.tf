locals {
  target_project = var.scan_project != "" ? var.scan_project : var.gcp_project
  image_name     = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project}/${var.name_prefix}/${var.name_prefix}"
  full_image     = "${local.image_name}:${var.image_tag}"

  # Build CLI args for the Cloud Run Job container command
  cli_args = concat(
    ["--provider", "gcp", "--project", local.target_project],
    var.enable_ai ? ["--model", var.ai_model] : ["--no-ai"],
    var.scan_severity != "INFO" ? ["--severity", var.scan_severity] : [],
    var.scan_modules != "" ? ["--modules", var.scan_modules] : [],
    var.enable_external_scan && var.external_scan_target != "" ? ["--mode", "both", "--target", var.external_scan_target] : ["--mode", "internal"],
    ["--output-dir", "/tmp/output"]
  )
}

# ─── Enable required APIs ─────────────────────────────────────────────────────

resource "google_project_service" "apis" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com",
    "cloudscheduler.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# ─── Service Account ──────────────────────────────────────────────────────────

resource "google_service_account" "runner" {
  account_id   = "${var.name_prefix}-runner"
  display_name = "StratusAI Cloud Run runner"
  depends_on   = [google_project_service.apis]
}

# Read-only access to scan the project
resource "google_project_iam_member" "runner_viewer" {
  project = local.target_project
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.runner.email}"
}

# Write reports to GCS
resource "google_storage_bucket_iam_member" "runner_gcs" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.runner.email}"
}

# Read API key from Secret Manager
resource "google_secret_manager_secret_iam_member" "runner_secret" {
  count     = var.enable_ai && var.api_key != "" ? 1 : 0
  secret_id = google_secret_manager_secret.api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runner.email}"
}

# Allow Cloud Scheduler to invoke Cloud Run Jobs
resource "google_service_account" "scheduler" {
  count        = var.enable_scheduler ? 1 : 0
  account_id   = "${var.name_prefix}-scheduler"
  display_name = "StratusAI Cloud Scheduler invoker"
  depends_on   = [google_project_service.apis]
}

resource "google_project_iam_member" "scheduler_run_invoker" {
  count   = var.enable_scheduler ? 1 : 0
  project = var.gcp_project
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.scheduler[0].email}"
}

# ─── Artifact Registry ────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "images" {
  repository_id = var.name_prefix
  location      = var.gcp_region
  format        = "DOCKER"
  description   = "StratusAI Docker images"
  depends_on    = [google_project_service.apis]
}

# ─── GCS Reports Bucket ───────────────────────────────────────────────────────

resource "google_storage_bucket" "reports" {
  name          = "${var.gcp_project}-${var.name_prefix}-reports"
  location      = var.gcp_region
  force_destroy = false

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition { age = var.report_retention_days }
    action    { type = "Delete" }
  }

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.apis]
}

# ─── Secret Manager (API key) ─────────────────────────────────────────────────

resource "google_secret_manager_secret" "api_key" {
  count     = var.enable_ai && var.api_key != "" ? 1 : 0
  secret_id = "${var.name_prefix}-api-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "api_key" {
  count       = var.enable_ai && var.api_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.api_key[0].id
  secret_data = var.api_key
}

# ─── Cloud Run Job ────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_job" "scanner" {
  name     = "${var.name_prefix}-scan"
  location = var.gcp_region

  template {
    template {
      service_account = google_service_account.runner.email

      timeout = "3600s"  # 1 hour max

      containers {
        image   = local.full_image
        command = local.cli_args

        resources {
          limits = {
            cpu    = "2"
            memory = "2Gi"
          }
        }

        # Inject API key from Secret Manager
        dynamic "env" {
          for_each = var.enable_ai && var.api_key != "" ? [1] : []
          content {
            name = "ANTHROPIC_API_KEY"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.api_key[0].secret_id
                version = "latest"
              }
            }
          }
        }

        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = local.target_project
        }
      }
    }
  }

  depends_on = [
    google_artifact_registry_repository.images,
    google_project_service.apis,
  ]
}

# ─── Cloud Scheduler ──────────────────────────────────────────────────────────

resource "google_cloud_scheduler_job" "scan" {
  count    = var.enable_scheduler ? 1 : 0
  name     = "${var.name_prefix}-scheduled-scan"
  region   = var.gcp_region
  schedule = var.schedule_expression
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = "https://${var.gcp_region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.gcp_project}/jobs/${google_cloud_run_v2_job.scanner.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler[0].email
    }
  }

  depends_on = [google_project_service.apis]
}
