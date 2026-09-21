# Service accounts for CloudShield detection scenarios.
#
# Deliberately NO service account keys (google_service_account_key) and NO
# project-level role bindings: none of these identities holds Owner, Editor or
# any other project role. "Protected" describes how the detections treat
# prod-admin, not privileges it holds. Add a project role later only for a
# concrete task, as narrowly as possible.

resource "google_service_account" "protected" {
  project      = var.project_id
  account_id   = "prod-admin"
  display_name = "CloudShield protected admin-like identity"
  description  = "Sensitive identity watched by GCP-IAM-002 (${var.environment}). Holds no project roles."
}

resource "google_service_account" "ci_deployer" {
  project      = var.project_id
  account_id   = "ci-deployer"
  display_name = "CloudShield approved CI deployer"
  description  = "Approved caller allowed to impersonate prod-admin (${var.environment})."
}

resource "google_service_account" "app_runtime" {
  project      = var.project_id
  account_id   = "app-runtime"
  display_name = "CloudShield app runtime workload"
  description  = "Low-privilege workload identity (${var.environment}). Holds no project roles."
}

# Impersonation lab support. roles/iam.serviceAccountTokenCreator lets a member
# mint access tokens, ID tokens, signed JWTs and signed blobs AS the target
# service account, i.e. it is equivalent to holding whatever that account can
# do. It is therefore bound to the single protected service account (resource
# level, additive google_service_account_iam_member), never at project level
# and never to wildcard principals.

# Approved caller: the identity GCP-IAM-002 allows.
resource "google_service_account_iam_member" "ci_deployer_token_creator" {
  service_account_id = google_service_account.protected.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.ci_deployer.email}"
}

# Optional unapproved callers used to trigger GCP-IAM-002 on purpose.
resource "google_service_account_iam_member" "test_principal_token_creator" {
  for_each = toset(var.impersonation_test_principals)

  service_account_id = google_service_account.protected.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = each.value
}
