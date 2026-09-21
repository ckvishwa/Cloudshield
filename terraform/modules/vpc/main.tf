# Custom-mode VPC: no auto-created subnets. No firewall rules are created, so
# the implied VPC rules apply (deny all ingress, allow all egress). Add explicit,
# narrowly scoped rules only when a workload needs them; never 0.0.0.0/0 for
# SSH, RDP or other admin ports.
resource "google_compute_network" "this" {
  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
  description             = "CloudShield lab VPC (custom mode)"
}

resource "google_compute_subnetwork" "this" {
  project                  = var.project_id
  name                     = var.subnet_name
  region                   = var.region
  network                  = google_compute_network.this.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
  description              = "CloudShield lab subnet"

  # VPC Flow Logs (log_config) are intentionally not enabled yet; they are
  # added together with the network detections.
}
