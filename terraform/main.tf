# CloudShield GCP lab foundation.
#
# Bootstrap note: enabling APIs through Terraform needs serviceusage and
# cloudresourcemanager to already be on. On a brand-new project run once:
#   gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com
# Both are still listed below so Terraform tracks them afterwards.

locals {
  required_apis = toset([
    "cloudresourcemanager.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "serviceusage.googleapis.com",
  ])
}

resource "google_project_service" "apis" {
  for_each = local.required_apis

  project = var.project_id
  service = each.key

  # Leave APIs on if this configuration is destroyed; disabling them can
  # break unrelated resources in the project.
  disable_on_destroy = false
}

module "vpc" {
  source = "./modules/vpc"

  project_id   = var.project_id
  region       = var.region
  network_name = var.network_name
  subnet_name  = var.subnet_name
  subnet_cidr  = var.subnet_cidr

  depends_on = [google_project_service.apis]
}

module "iam" {
  source = "./modules/iam"

  project_id                    = var.project_id
  environment                   = var.environment
  impersonation_test_principals = var.impersonation_test_principals

  depends_on = [google_project_service.apis]
}

# Cloud Audit Logs
#
# Admin Activity audit logs (IAM policy changes, service account creation,
# GenerateAccessToken / SignJwt calls on iamcredentials.googleapis.com, ...)
# are always on and cannot be disabled, so nothing is configured for them here.
# Data Access audit logs are deliberately NOT enabled project-wide: they add
# cost and noise. If a later detection needs them, enable them per service
# with a google_project_iam_audit_config scoped to that service.
