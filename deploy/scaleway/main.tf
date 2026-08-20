terraform {
  required_version = ">= 1.8.0"

  required_providers {
    scaleway = {
      source  = "scaleway/scaleway"
      version = "~> 2.80"
    }
  }
}

provider "scaleway" {
  project_id = var.project_id
}

locals {
  # STARDUST1-S is intentionally fixed here: the WAN lab is a measurement
  # fixture, not a performance environment. Keeping the instance type out of
  # user input prevents an accidental expensive apply.
  nodes = {
    operator-a = {
      zone  = "fr-par-1"
      index = 1
      wg_ip = "10.77.0.1"
    }
    operator-b = {
      zone  = "nl-ams-1"
      index = 2
      wg_ip = "10.77.0.2"
    }
    operator-c = {
      zone  = "pl-waw-2"
      index = 3
      wg_ip = "10.77.0.3"
    }
  }

  tags = [
    "nomad",
    "nomad-wan-lab",
    "deployment-${var.deployment_id}",
    "ttl-${var.ttl_hours}h",
    "single-admin-not-independent",
  ]
}

resource "scaleway_instance_ip" "ipv4" {
  for_each   = local.nodes
  project_id = var.project_id
  zone       = each.value.zone
  type       = "routed_ipv4"
  tags       = concat(local.tags, [each.key, "ipv4"])
}

resource "scaleway_instance_ip" "ipv6" {
  for_each   = local.nodes
  project_id = var.project_id
  zone       = each.value.zone
  type       = "routed_ipv6"
  tags       = concat(local.tags, [each.key, "ipv6"])
}

resource "scaleway_instance_security_group" "node" {
  for_each                = local.nodes
  project_id              = var.project_id
  zone                    = each.value.zone
  name                    = "nomad-wan-${var.deployment_id}-${each.key}"
  description             = "Disposable Nomad WAN lab; SSH restricted to the orchestrator, protocol ports restricted to lab peers on IPv4."
  inbound_default_policy  = "drop"
  outbound_default_policy = "accept"
  stateful                = true
  external_rules          = true
  tags                    = concat(local.tags, [each.key])
}

resource "scaleway_instance_security_group_rules" "node" {
  for_each          = local.nodes
  zone              = each.value.zone
  security_group_id = scaleway_instance_security_group.node[each.key].id

  # The GitHub runner creates an ephemeral SSH key for every apply. Only the
  # runner's observed public IPv4 can reach port 22.
  inbound_rule {
    action   = "accept"
    protocol = "TCP"
    port     = 22
    ip_range = var.admin_ipv4_cidr
  }

  # Fixed-cadence Nomad cells, DKG TLS and WireGuard are reachable only from
  # the other provisioned IPv4 addresses. Application-layer authentication is
  # still mandatory; these rules are only a network reduction layer.
  dynamic "inbound_rule" {
    for_each = scaleway_instance_ip.ipv4
    content {
      action   = "accept"
      protocol = "UDP"
      port     = 4200
      ip_range = "${inbound_rule.value.address}/32"
    }
  }

  dynamic "inbound_rule" {
    for_each = scaleway_instance_ip.ipv4
    content {
      action   = "accept"
      protocol = "TCP"
      port     = 4400
      ip_range = "${inbound_rule.value.address}/32"
    }
  }

  dynamic "inbound_rule" {
    for_each = scaleway_instance_ip.ipv4
    content {
      action   = "accept"
      protocol = "UDP"
      port     = 51820
      ip_range = "${inbound_rule.value.address}/32"
    }
  }

  # IPv6 is always allocated so dual-stack campaigns do not require replacing
  # hosts. Inbound IPv6 remains closed unless a campaign explicitly enables it.
  dynamic "inbound_rule" {
    for_each = var.enable_ipv6_wan ? toset([4200, 4400, 51820]) : toset([])
    content {
      action   = "accept"
      protocol = inbound_rule.value == 4400 ? "TCP" : "UDP"
      port     = inbound_rule.value
      ip_range = "::/0"
    }
  }
}

resource "scaleway_instance_server" "node" {
  for_each   = local.nodes
  project_id = var.project_id
  zone       = each.value.zone

  name  = "nomad-wan-${var.deployment_id}-${each.key}"
  type  = "STARDUST1-S"
  image = "ubuntu_noble"
  state = "started"

  ip_ids = [
    scaleway_instance_ip.ipv4[each.key].id,
    scaleway_instance_ip.ipv6[each.key].id,
  ]

  security_group_id = scaleway_instance_security_group.node[each.key].id
  tags              = concat(local.tags, [each.key, each.value.zone])

  user_data = {
    cloud-init = templatefile("${path.module}/cloud-init.yaml.tftpl", {
      ssh_public_key = var.ssh_public_key
      operator_id    = each.key
      ttl_hours      = var.ttl_hours
    })
  }

  # Never protect disposable lab nodes from Terraform deletion.
  protected = false
}
