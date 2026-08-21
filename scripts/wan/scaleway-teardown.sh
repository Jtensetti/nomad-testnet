#!/usr/bin/env bash
# Destroy every Scaleway resource belonging to a WAN campaign deployment.
#
# It is written first, and separately from the provisioner, deliberately: a
# provisioner that dies between "create" and "delete" leaves paid resources
# running, so teardown has to be runnable on its own with nothing but the
# deployment tag. It is idempotent and safe to run when nothing exists.
set -uo pipefail

deployment=${1:?usage: scaleway-teardown.sh DEPLOYMENT_ID}
zones=${WAN_ZONES:-fr-par-1 nl-ams-1 pl-waw-1}
: "${SCW_SECRET_KEY:?SCW_SECRET_KEY is required}"

api() {
  local method=$1 path=$2
  curl -sS --max-time 30 -X "$method" \
    -H "X-Auth-Token: $SCW_SECRET_KEY" \
    -H "Content-Type: application/json" \
    "https://api.scaleway.com$path" "${@:3}"
}

# Release every address carrying the deployment tag that no longer has a server
# on it. Run twice, because an address stays attached for a few seconds after
# its server is terminated and a single pass would declare it in use and leave
# it billing.
sweep_orphan_ips() {
  local zone=$1
  local orphans
  orphans=$(api GET "/instance/v1/zones/$zone/ips?per_page=100" \
    | python3 -c "
import sys, json
try: data = json.load(sys.stdin)
except Exception: sys.exit()
for ip in data.get('ips', []):
    if ip.get('server') is None and '$deployment' in ' '.join(ip.get('tags') or []):
        print(ip['id'], ip.get('address'))
" 2>/dev/null)
  while read -r ip_id address; do
    [ -n "${ip_id:-}" ] || continue
    api DELETE "/instance/v1/zones/$zone/ips/$ip_id" >/dev/null 2>&1 && \
      echo "  $zone: released $address"
  done <<< "$orphans"
}

removed=0
for zone in $zones; do
  servers=$(api GET "/instance/v1/zones/$zone/servers?per_page=100" \
    | python3 -c "
import sys, json
try: data = json.load(sys.stdin)
except Exception: sys.exit()
for server in data.get('servers', []):
    if '$deployment' not in (server.get('name') or ''):
        continue
    # A server reserves its address under 'public_ips' and, for the legacy
    # dynamic path, under 'public_ip'. Reading only one of the two leaves the
    # other kind of address allocated and billing after the server is gone.
    ids = {ip['id'] for ip in (server.get('public_ips') or []) if ip.get('id')}
    legacy = (server.get('public_ip') or {}).get('id')
    if legacy:
        ids.add(legacy)
    print(server['id'], server.get('state'), ','.join(sorted(ids)) or '-')
" 2>/dev/null)

  while read -r id state ip_ids; do
    [ -n "${id:-}" ] || continue
    echo "  $zone: terminating $id (state $state)"
    # terminate releases the server and its attached local volumes.
    api POST "/instance/v1/zones/$zone/servers/$id/action" \
      -d '{"action":"terminate"}' >/dev/null 2>&1
    removed=$((removed + 1))
    if [ "$ip_ids" != "-" ]; then
      # A flexible IP outlives the server it was attached to and keeps
      # billing, so it is released explicitly rather than assumed gone.
      sleep 2
      for ip_id in ${ip_ids//,/ }; do
        api DELETE "/instance/v1/zones/$zone/ips/$ip_id" >/dev/null 2>&1 && \
          echo "  $zone: released IP $ip_id"
      done
    fi
  done <<< "$servers"

  sweep_orphan_ips "$zone"
done

# Second pass, after the terminations have settled, for addresses that were
# still shown as attached during the first.
sleep 15
for zone in $zones; do
  sweep_orphan_ips "$zone"
done

echo "teardown of '$deployment' complete; $removed server(s) terminated"
