variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment label used in service account descriptions."
  type        = string
}

variable "impersonation_test_principals" {
  description = "IAM members allowed to create tokens for the protected service account only."
  type        = list(string)
  default     = []
}
