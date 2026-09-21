terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

# Credentials are never configured here. Authenticate with Application Default
# Credentials (`gcloud auth application-default login`) or workload identity.
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
