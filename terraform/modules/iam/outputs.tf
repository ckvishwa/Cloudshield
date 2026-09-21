output "protected_service_account_email" {
  description = "Email of the protected (prod-admin) service account."
  value       = google_service_account.protected.email
}

output "ci_deployer_service_account_email" {
  description = "Email of the approved CI/deployer service account."
  value       = google_service_account.ci_deployer.email
}

output "app_runtime_service_account_email" {
  description = "Email of the low-privilege app runtime service account."
  value       = google_service_account.app_runtime.email
}
