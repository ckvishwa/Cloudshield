variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "Region of the subnet."
  type        = string
}

variable "network_name" {
  description = "Name of the custom-mode VPC."
  type        = string
}

variable "subnet_name" {
  description = "Name of the subnet."
  type        = string
}

variable "subnet_cidr" {
  description = "Primary RFC1918 range of the subnet."
  type        = string
}
