variable "project_id" {
  description = "Scaleway project ID used for the disposable Nomad WAN lab."
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "Ephemeral SSH public key injected into the lab nodes."
  type        = string
}

variable "admin_ipv4_cidr" {
  description = "Single IPv4 CIDR allowed to SSH to the lab nodes, normally the current GitHub runner /32."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_ipv4_cidr, 0)) && can(regex("/32$", var.admin_ipv4_cidr))
    error_message = "admin_ipv4_cidr must be a single IPv4 /32."
  }
}

variable "deployment_id" {
  description = "Short identifier used in resource names and tags."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{3,40}$", var.deployment_id))
    error_message = "deployment_id must contain only letters, digits and hyphens (3-40 chars)."
  }
}

variable "ttl_hours" {
  description = "Public lab TTL recorded in tags/cloud-init. Nodes power themselves off after this many hours as a cost backstop; Terraform destroy is still required to release billed IPv4 addresses."
  type        = number
  default     = 24

  validation {
    condition     = var.ttl_hours >= 1 && var.ttl_hours <= 72 && floor(var.ttl_hours) == var.ttl_hours
    error_message = "ttl_hours must be a whole number from 1 through 72."
  }
}
