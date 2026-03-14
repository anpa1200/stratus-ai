output "artifact_registry_url" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project}/${var.name_prefix}"
  description = "Artifact Registry base URL — tag and push images here"
}

output "image_name" {
  value       = "${var.gcp_region}-docker.pkg.dev/${var.gcp_project}/${var.name_prefix}/${var.name_prefix}:${var.image_tag}"
  description = "Full image name including tag"
}

output "reports_bucket" {
  value       = google_storage_bucket.reports.name
  description = "GCS bucket where scan reports are stored"
}

output "reports_bucket_url" {
  value       = "https://console.cloud.google.com/storage/browser/${google_storage_bucket.reports.name}"
  description = "GCP Console URL to view reports"
}

output "cloud_run_job_name" {
  value       = google_cloud_run_v2_job.scanner.name
  description = "Cloud Run Job name"
}

output "service_account_email" {
  value       = google_service_account.runner.email
  description = "Service account running the scan job"
}

output "run_command" {
  value       = "gcloud run jobs execute ${google_cloud_run_v2_job.scanner.name} --region ${var.gcp_region} --project ${var.gcp_project}"
  description = "Command to trigger a scan manually"
}

output "logs_command" {
  value       = "gcloud logging read 'resource.type=cloud_run_job AND resource.labels.job_name=${google_cloud_run_v2_job.scanner.name}' --project ${var.gcp_project} --limit 100 --format json"
  description = "Command to view scan logs"
}
