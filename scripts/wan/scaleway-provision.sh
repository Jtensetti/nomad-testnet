#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 NODES_JSON SSH_PRIVATE_KEY BIN_DIR EVIDENCE_DIR" >&2
  exit 2
fi

nodes_json=$1
ssh_key=$2
bin_dir=$3
evidence_dir=$4
capture_seconds=${CAPTURE_SECONDS:-300}
ttl_hours=${TTL_HOURS:-24}
deployment_id=${DEPLOYMENT_ID:-manual}
ssh_user=${SSH_USER:-nomad-admin}
expected_interval_ms=${EXPECTED_INTERVAL_MS:-50}

for command in jq ssh scp openssl sha256sum; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
for binary in nomad-operator nomad-topology nomad-dkg nomad-node nomad-shaper; do
  [[ -x "$bin_dir/$binary" ]] || { echo "missing executable $bin_dir/$binary" >&2; exit 1; }
done
[[ -s "$nodes_json" ]] || { echo "nodes JSON missing: $nodes_json" >&2; exit 1; }
[[ -s "$ssh_key" ]] || { echo "SSH private key missing: $ssh_key" >&2; exit 1; }
[[ "$capture_seconds" =~ ^[0-9]+$ ]] && (( capture_seconds >= 30 && capture_seconds <= 3600 )) || {
  echo "CAPTURE_SECONDS must be 30..3600" >&2; exit 1;
}
[[ "$ttl_hours" =~ ^[0-9]+$ ]] && (( ttl_hours >= 1 && ttl_hours <= 72 )) || {
  echo "TTL_HOURS must be 1..72" >&2; exit 1;
}
(( ttl_hours * 3600 >= capture_seconds + 900 )) || {
  echo "TTL_HOURS must leave at least 15 minutes beyond CAPTURE_SECONDS" >&2; exit 1;
}

mkdir -p "$evidence_dir"/{enrollments,attestations,dkg,pcap,health,logs,tls}
work_dir=$(mktemp -d)
known_hosts="$work_dir/known_hosts"
trap 'rm -rf "$work_dir"' EXIT
chmod 600 "$ssh_key"

mapfile -t operators < <(jq -r 'keys[]' "$nodes_json")
if [[ ${#operators[@]} -ne 3 ]]; then
  echo "expected exactly three WAN nodes, found ${#operators[@]}" >&2
  exit 1
fi

declare -A ipv4 zone wg_ip
for operator in "${operators[@]}"; do
  ipv4[$operator]=$(jq -r --arg operator "$operator" '.[$operator].ipv4' "$nodes_json")
  zone[$operator]=$(jq -r --arg operator "$operator" '.[$operator].zone' "$nodes_json")
  wg_ip[$operator]=$(jq -r --arg operator "$operator" '.[$operator].wg_ip' "$nodes_json")
  [[ "${ipv4[$operator]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "invalid IPv4 for $operator: ${ipv4[$operator]}" >&2; exit 1;
  }
done

ssh_opts=(-i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$known_hosts" -o ConnectTimeout=8)
scp_opts=(-i "$ssh_key" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$known_hosts" -o ConnectTimeout=8)

remote() {
  local operator=$1
  shift
  ssh "${ssh_opts[@]}" "$ssh_user@${ipv4[$operator]}" "$@"
}

copy_to() {
  local operator=$1 source=$2 destination=$3
  scp "${scp_opts[@]}" "$source" "$ssh_user@${ipv4[$operator]}:$destination"
}

collect_root_file() {
  local operator=$1 source=$2 destination=$3
  remote "$operator" "sudo test -f '$source' && sudo cat '$source'" > "$destination"
  [[ -s "$destination" ]] || { echo "empty collected file $source from $operator" >&2; return 1; }
}

wait_for_node() {
  local operator=$1 deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    if remote "$operator" 'sudo test -f /var/lib/nomad/cloud-init-ready' >/dev/null 2>&1; then
      return 0
    fi
    sleep 5
  done
  echo "$operator did not finish cloud-init" >&2
  return 1
}

printf 'Waiting for Scaleway cloud-init on %s\n' "${operators[*]}"
for operator in "${operators[@]}"; do
  wait_for_node "$operator"
done

# Install the exact workflow-built binaries. Operator private material is then
# generated on each host and never copied back to the coordinator.
for operator in "${operators[@]}"; do
  remote "$operator" 'rm -rf /tmp/nomad-bin && mkdir -m 0700 /tmp/nomad-bin'
  for binary in nomad-operator nomad-dkg nomad-node nomad-shaper; do
    copy_to "$operator" "$bin_dir/$binary" "/tmp/nomad-bin/$binary"
  done
  remote "$operator" 'sudo install -o root -g root -m 0755 /tmp/nomad-bin/* /usr/local/bin/ && rm -rf /tmp/nomad-bin'
done

# Generate one short-lived lab TLS CA on the orchestrator. Server private keys
# are generated on-node; only CSRs leave the node. DKG messages are signed by
# the protocol as well, so TLS is transport authentication, not the trust root.
openssl genrsa -out "$work_dir/dkg-ca.key" 3072 >/dev/null 2>&1
openssl req -x509 -new -key "$work_dir/dkg-ca.key" -sha256 -days 4 \
  -subj "/CN=Nomad Scaleway WAN lab ${deployment_id}" -out "$work_dir/dkg-ca.crt"
cp "$work_dir/dkg-ca.crt" "$evidence_dir/tls/dkg-ca.crt"

for operator in "${operators[@]}"; do
  ip=${ipv4[$operator]}
  remote "$operator" "sudo rm -f /etc/nomad/tls/dkg.key /etc/nomad/tls/dkg.csr /etc/nomad/tls/dkg.crt; \
    sudo -u nomad openssl genrsa -out /etc/nomad/tls/dkg.key 2048 >/dev/null 2>&1; \
    sudo -u nomad openssl req -new -key /etc/nomad/tls/dkg.key -subj '/CN=$ip' \
      -addext 'subjectAltName=IP:$ip' -out /etc/nomad/tls/dkg.csr"
  collect_root_file "$operator" /etc/nomad/tls/dkg.csr "$work_dir/$operator.csr"
  cat > "$work_dir/$operator.ext" <<EXT
subjectAltName=IP:$ip
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EXT
  openssl x509 -req -in "$work_dir/$operator.csr" -CA "$work_dir/dkg-ca.crt" \
    -CAkey "$work_dir/dkg-ca.key" -CAcreateserial -days 3 -sha256 \
    -extfile "$work_dir/$operator.ext" -out "$work_dir/$operator.crt" >/dev/null 2>&1
  copy_to "$operator" "$work_dir/$operator.crt" /tmp/dkg.crt
  copy_to "$operator" "$work_dir/dkg-ca.crt" /tmp/nomad-dkg-ca.crt
  remote "$operator" 'sudo install -o nomad -g nomad -m 0644 /tmp/dkg.crt /etc/nomad/tls/dkg.crt; \
    sudo install -o root -g root -m 0644 /tmp/nomad-dkg-ca.crt /usr/local/share/ca-certificates/nomad-dkg-ca.crt; \
    sudo update-ca-certificates >/dev/null; rm -f /tmp/dkg.crt /tmp/nomad-dkg-ca.crt'
done

# Independent-in-process ceremony: each host creates its own identity and only
# the signed public enrollment returns to the coordinator.
for operator in "${operators[@]}"; do
  ip=${ipv4[$operator]}
  remote "$operator" "sudo rm -f /etc/nomad/private/operator-secret.json /var/lib/nomad/enrollment.json; \
    sudo -u nomad /usr/local/bin/nomad-operator init \
      --id '$operator' \
      --endpoint '$ip:4200' \
      --partial-endpoint 'http://$ip:4300/' \
      --dkg-endpoint 'https://$ip:4400/' \
      --secret /etc/nomad/private/operator-secret.json \
      --enrollment /var/lib/nomad/enrollment.json"
  collect_root_file "$operator" /var/lib/nomad/enrollment.json "$evidence_dir/enrollments/$operator.json"
done

mkdir -p "$work_dir/authority"
"$bin_dir/nomad-topology" authority-init \
  --private "$work_dir/authority/authority.key" \
  --public "$work_dir/authority/authority.pub" > "$evidence_dir/authority-init.json"
chmod 600 "$work_dir/authority/authority.key"
cp "$work_dir/authority/authority.pub" "$evidence_dir/authority.pub"

enrollments=""
for operator in "${operators[@]}"; do
  [[ -z "$enrollments" ]] || enrollments+=,
  enrollments+="$evidence_dir/enrollments/$operator.json"
done

"$bin_dir/nomad-topology" draft \
  --network-id "nomad-scaleway-${deployment_id}" \
  --epoch 1 \
  --cell-interval-ms "$expected_interval_ms" \
  --valid-for "${ttl_hours}h" \
  --dkg-start-delay 3m \
  --dkg-phase-duration 10s \
  --dkg-threshold 2 \
  --enrollments "$enrollments" \
  --out "$work_dir/topology-draft.json" > "$evidence_dir/topology-draft-summary.json"
cp "$work_dir/topology-draft.json" "$evidence_dir/topology-draft.json"

attestations=""
for operator in "${operators[@]}"; do
  copy_to "$operator" "$work_dir/topology-draft.json" /tmp/topology-draft.json
  remote "$operator" 'sudo install -o nomad -g nomad -m 0644 /tmp/topology-draft.json /etc/nomad/topology-draft.json; rm -f /tmp/topology-draft.json; \
    sudo rm -f /var/lib/nomad/attestation.json; \
    sudo -u nomad /usr/local/bin/nomad-operator attest \
      --secret /etc/nomad/private/operator-secret.json \
      --draft /etc/nomad/topology-draft.json \
      --out /var/lib/nomad/attestation.json'
  collect_root_file "$operator" /var/lib/nomad/attestation.json "$evidence_dir/attestations/$operator.json"
  [[ -z "$attestations" ]] || attestations+=,
  attestations+="$evidence_dir/attestations/$operator.json"
done

"$bin_dir/nomad-topology" finalize \
  --draft "$work_dir/topology-draft.json" \
  --attestations "$attestations" \
  --authority-private "$work_dir/authority/authority.key" \
  --out "$work_dir/topology.json" > "$evidence_dir/topology-final-summary.json"
cp "$work_dir/topology.json" "$evidence_dir/topology.json"

for operator in "${operators[@]}"; do
  copy_to "$operator" "$work_dir/topology.json" /tmp/topology.json
  copy_to "$operator" "$work_dir/authority/authority.pub" /tmp/authority.pub
  remote "$operator" 'sudo install -o root -g root -m 0644 /tmp/topology.json /etc/nomad/topology.json; \
    sudo install -o root -g root -m 0644 /tmp/authority.pub /etc/nomad/authority.pub; \
    rm -f /tmp/topology.json /tmp/authority.pub; \
    sudo -u nomad /usr/local/bin/nomad-operator verify \
      --secret /etc/nomad/private/operator-secret.json \
      --topology /etc/nomad/topology.json \
      --authority-key /etc/nomad/authority.pub'
done

# Start all three DKG processes before the signed start boundary and wait for
# their independently written shares/certificates. No threshold share leaves a
# host. Only the public certificate is collected and compared.
for operator in "${operators[@]}"; do
  remote "$operator" 'sudo rm -rf /var/lib/nomad/dkg; sudo install -d -o nomad -g nomad -m 0700 /var/lib/nomad/dkg; \
    sudo rm -f /etc/nomad/private/threshold-share.json /var/lib/nomad/dkg-certificate.json /var/log/nomad/dkg.log; \
    sudo -u nomad sh -c "nohup /usr/local/bin/nomad-dkg \
      --topology /etc/nomad/topology.json \
      --authority-key /etc/nomad/authority.pub \
      --secrets /etc/nomad/private/operator-secret.json \
      --listen :4400 \
      --state /var/lib/nomad/dkg \
      --share-out /etc/nomad/private/threshold-share.json \
      --certificate-out /var/lib/nomad/dkg-certificate.json \
      --tls-certificate /etc/nomad/tls/dkg.crt \
      --tls-private-key /etc/nomad/tls/dkg.key \
      > /var/log/nomad/dkg.log 2>&1 & echo \$! > /var/lib/nomad/dkg.pid"'
done

dkg_deadline=$((SECONDS + 240))
while (( SECONDS < dkg_deadline )); do
  ready=0
  for operator in "${operators[@]}"; do
    if remote "$operator" 'sudo test -s /var/lib/nomad/dkg-certificate.json && sudo test -s /etc/nomad/private/threshold-share.json' >/dev/null 2>&1; then
      ((ready += 1))
    fi
  done
  (( ready == 3 )) && break
  sleep 3
done

for operator in "${operators[@]}"; do
  if ! remote "$operator" 'sudo test -s /var/lib/nomad/dkg-certificate.json && sudo test -s /etc/nomad/private/threshold-share.json' >/dev/null 2>&1; then
    remote "$operator" 'sudo cat /var/log/nomad/dkg.log || true' > "$evidence_dir/logs/$operator-dkg.log" || true
    echo "distributed DKG did not complete on $operator" >&2
    exit 1
  fi
  collect_root_file "$operator" /var/lib/nomad/dkg-certificate.json "$evidence_dir/dkg/$operator-certificate.json"
  remote "$operator" 'sudo cat /var/log/nomad/dkg.log || true' > "$evidence_dir/logs/$operator-dkg.log" || true
done

first_cert="$evidence_dir/dkg/${operators[0]}-certificate.json"
first_digest=$(sha256sum "$first_cert" | awk '{print $1}')
for operator in "${operators[@]}"; do
  digest=$(sha256sum "$evidence_dir/dkg/$operator-certificate.json" | awk '{print $1}')
  [[ "$digest" == "$first_digest" ]] || {
    echo "DKG certificate mismatch for $operator: $digest != $first_digest" >&2
    exit 1
  }
done
printf '%s  dkg-certificate.json\n' "$first_digest" > "$evidence_dir/dkg/CERTIFICATE_SHA256"

# Production WAN timing uses two OS processes. nomad-shaper owns the public
# fixed-rate scheduler/sequence/UDP egress. nomad-node owns receive/cache/relay
# production and gets exactly one nonblocking Unix-datagram enqueue attempt per
# work opportunity. Shaper starts first so node can only attach to an existing
# local timing boundary.
for operator in "${operators[@]}"; do
  remote "$operator" "sudo tee /etc/systemd/system/nomad-shaper.service >/dev/null <<'UNIT'
[Unit]
Description=Nomad fixed-cadence WAN shaper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nomad
Group=nomad
RuntimeDirectory=nomad
RuntimeDirectoryMode=0700
ExecStart=/usr/local/bin/nomad-shaper --topology /etc/nomad/topology.json --authority-key /etc/nomad/authority.pub --secrets /etc/nomad/private/operator-secret.json --bind :0 --work-socket /run/nomad/shaper.sock --state /var/lib/nomad/sequence/state --stats-out /var/lib/nomad/shaper-stats.json
Restart=no
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/run/nomad /var/lib/nomad /var/log/nomad
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
sudo tee /etc/systemd/system/nomad-node.service >/dev/null <<'UNIT'
[Unit]
Description=Nomad WAN receive/cache/relay node
After=network-online.target nomad-shaper.service
Wants=network-online.target
Requires=nomad-shaper.service

[Service]
Type=simple
User=nomad
Group=nomad
ExecStart=/usr/local/bin/nomad-node --topology /etc/nomad/topology.json --authority-key /etc/nomad/authority.pub --secrets /etc/nomad/private/operator-secret.json --listen :4200 --cache /var/lib/nomad/raw --relay-socket /run/nomad/shaper.sock --health /var/lib/nomad/health.json
Restart=no
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/run/nomad /var/lib/nomad /var/log/nomad
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl disable --now nomad-node.service nomad-shaper.service >/dev/null 2>&1 || true
sudo rm -f /var/lib/nomad/evidence/$operator.pcap /var/lib/nomad/shaper-stats.json
sudo sh -c 'nohup timeout ${capture_seconds}s tcpdump -i any -U -nn -s 0 -w /var/lib/nomad/evidence/$operator.pcap \"udp port 4200\" >/var/log/nomad/tcpdump.log 2>&1 &'
sudo systemctl start nomad-shaper.service
for attempt in \$(seq 1 50); do
  sudo test -S /run/nomad/shaper.sock && break
  sleep 0.1
done
sudo test -S /run/nomad/shaper.sock
sudo systemctl start nomad-node.service"
done

sleep $((capture_seconds + 5))

# Stop cleanly after the capture. The shaper writes final local stats on SIGTERM;
# keeping services alive after the measurement would add cost without improving
# this baseline evidence run.
for operator in "${operators[@]}"; do
  remote "$operator" 'sudo systemctl stop nomad-node.service nomad-shaper.service || true'
done

for operator in "${operators[@]}"; do
  collect_root_file "$operator" "/var/lib/nomad/evidence/$operator.pcap" "$evidence_dir/pcap/$operator.pcap"
  remote "$operator" 'sudo cat /var/lib/nomad/health.json || true' > "$evidence_dir/health/$operator.json" || true
  remote "$operator" 'sudo cat /var/lib/nomad/shaper-stats.json || true' > "$evidence_dir/health/$operator-shaper.json" || true
  remote "$operator" 'sudo systemctl status --no-pager --full nomad-node.service || true' > "$evidence_dir/logs/$operator-node-status.txt" || true
  remote "$operator" 'sudo journalctl -u nomad-node.service --no-pager --since "10 minutes ago" || true' > "$evidence_dir/logs/$operator-node-journal.txt" || true
  remote "$operator" 'sudo systemctl status --no-pager --full nomad-shaper.service || true' > "$evidence_dir/logs/$operator-shaper-status.txt" || true
  remote "$operator" 'sudo journalctl -u nomad-shaper.service --no-pager --since "10 minutes ago" || true' > "$evidence_dir/logs/$operator-shaper-journal.txt" || true
  remote "$operator" 'ip -j address show; printf "\n--- routes ---\n"; ip route; printf "\n--- routes6 ---\n"; ip -6 route' > "$evidence_dir/logs/$operator-network.txt" || true
done

python3 "$(dirname "$0")/analyze-captures.py" "$evidence_dir/pcap" "$nodes_json" "$expected_interval_ms" > "$evidence_dir/cadence.json"

cat > "$evidence_dir/CLAIM_BOUNDARY.txt" <<BOUNDARY
Nomad Scaleway WAN lab
======================
deployment_id=$deployment_id
operators=3
regions=fr-par-1,nl-ams-1,pl-waw-2
administrative_domains=1
production_independence=false
transport_boundary=separate-nomad-shaper-process
capture_seconds=$capture_seconds
expected_cell_interval_ms=$expected_interval_ms

This evidence demonstrates real public-WAN emission and arrival cadence for one
administrator across three Scaleway regions using a dedicated fixed-rate shaper
process separated from receive/cache/relay production by bounded one-way local
IPC. It does NOT demonstrate independent operator governance, anonymous
publication, a 72-hour campaign, or an external security assessment.
BOUNDARY

cp "$nodes_json" "$evidence_dir/nodes.json"
(
  cd "$evidence_dir"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

# The TLS CA private key and topology authority private key are deliberately not
# persisted in evidence. They are ephemeral lab coordination material.
rm -f "$work_dir/dkg-ca.key" "$work_dir/authority/authority.key"

printf 'Nomad WAN baseline campaign complete. Evidence: %s\n' "$evidence_dir"
printf 'IMPORTANT: destroy the Terraform lab when no immediate follow-up campaign needs these hosts; powered-off routed IPv4 addresses remain billable.\n'
