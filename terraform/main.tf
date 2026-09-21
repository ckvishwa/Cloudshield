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
# GCP-IAM-001 (IAM policy changes, service account creation, ...) relies on
# Admin Activity audit logs. Those are always on and cannot be disabled, so
# nothing is configured for them here.
#
# GCP-IAM-002 relies on Service Account Credentials events
# (iamcredentials.googleapis.com: GenerateAccessToken, GenerateIdToken, SignJwt,
# SignBlob). Those are Data Access audit logs, which are OFF by default. Google
# does not allow enabling them for iamcredentials.googleapis.com on its own: the
# documented way is to enable Data Access audit logs for the IAM API
# (iam.googleapis.com), which also covers the Service Account Credentials API.
#
# Log types, per Google's Service Account Credentials audit logging reference:
#   GenerateAccessToken -> ADMIN_READ
#   GenerateIdToken, SignJwt, SignBlob -> DATA_READ and ADMIN_READ
# so ADMIN_READ and DATA_READ are the minimum set. DATA_WRITE is not needed by
# any of these methods and stays off.
#
# Cost/noise: this also logs other IAM API read calls (for example
# GetServiceAccount, ListServiceAccounts). It is scoped to iam.googleapis.com
# only; Data Access logging is NOT enabled for "allServices".
#
# Provider semantics: google_project_iam_audit_config is authoritative for ONE
# service in the project's IAM policy. It leaves audit configs of other services
# untouched, but it replaces any existing log types or exempted_members already
# set for iam.googleapis.com, and destroying it removes the iam.googleapis.com
# config. Do not combine it with google_project_iam_policy (authoritative for
# the whole policy). No exempted_members are set, so nobody is excluded from
# the logs CloudShield needs.
resource "google_project_iam_audit_config" "iam_data_access" {
  project = var.project_id
  service = "iam.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  depends_on = [google_project_service.apis]
}
