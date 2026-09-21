output "project_id" {
  description = "GCP project the lab is deployed to."
  value       = var.project_id
}

output "network_name" {
  description = "Name of the CloudShield VPC."
  value       = module.vpc.network_name
}

output "subnet_name" {
  description = "Name of the CloudShield subnet."
  value       = module.vpc.subnet_name
}

output "subnet_self_link" {
  description = "Self link of the CloudShield subnet."
  value       = module.vpc.subnet_self_link
}

output "protected_service_account_email" {
  description = "Email of the protected (prod-admin) service account."
  value       = module.iam.protected_service_account_email
}

output "ci_deployer_service_account_email" {
  description = "Email of the approved CI/deployer service account."
  value       = module.iam.ci_deployer_service_account_email
}

output "app_runtime_service_account_email" {
  description = "Email of the low-privilege app runtime service account."
  value       = module.iam.app_runtime_service_account_email
}
