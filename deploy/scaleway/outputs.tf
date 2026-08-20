output "nodes" {
  description = "Public and lab addresses for the three disposable WAN nodes."
  value = {
    for name, server in scaleway_instance_server.node : name => {
      id    = server.id
      zone  = local.nodes[name].zone
      index = local.nodes[name].index
      wg_ip = local.nodes[name].wg_ip
      ipv4 = one([
        for address in server.public_ips : address.address
        if address.family == "inet"
      ])
      ipv6 = one([
        for address in server.public_ips : address.address
        if address.family == "inet6"
      ])
    }
  }
}

output "deployment_id" {
  value = var.deployment_id
}

output "cost_guard" {
  description = "Human-readable reminder that shutdown does not release billed flexible IPv4 addresses."
  value       = "STARDUST1-S is fixed; ttl=${var.ttl_hours}h powers hosts off, but run Terraform destroy to release IPv4 resources."
}
