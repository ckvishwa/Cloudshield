variable "project_id" {
  description = "GCP project ID for the CloudShield lab. Supply it via terraform.tfvars (not committed)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid GCP project ID (6-30 chars, lowercase letters, digits, hyphens)."
  }
}

variable "region" {
  description = "Default GCP region."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Default GCP zone."
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment label used in service account descriptions."
  type        = string
  default     = "lab"

  validation {
    condition     = contains(["lab", "dev", "test"], var.environment)
    error_message = "environment must be one of: lab, dev, test. CloudShield is a lab, not a production system."
  }
}

variable "network_name" {
  description = "Name of the custom-mode VPC."
  type        = string
  default     = "cloudshield-vpc"
}

variable "subnet_name" {
  description = "Name of the lab subnet."
  type        = string
  default     = "cloudshield-subnet"
}

variable "subnet_cidr" {
  description = "Primary RFC1918 range of the lab subnet."
  type        = string
  default     = "10.20.0.0/24"

  validation {
    condition     = can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", var.subnet_cidr)) && can(cidrnetmask(var.subnet_cidr))
    error_message = "subnet_cidr must be a valid private RFC1918 CIDR block."
  }
}

variable "impersonation_test_principals" {
  description = <<-EOT
    Explicit IAM members (user:, group: or serviceAccount:) allowed to mint
    short-lived tokens for the protected prod-admin service account, used to
    generate GCP-IAM-002 telemetry. Empty by default: nobody gets token
    creation unless listed. Bound to that one service account only, never at
    project level.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for m in var.impersonation_test_principals :
      can(regex("^(user|group|serviceAccount):[^*\\s]+@[^*\\s]+$", m))
    ])
    error_message = "Each principal must look like user:x@y, group:x@y or serviceAccount:x@y. Wildcards, allUsers, allAuthenticatedUsers and domain: are not allowed."
  }
}
