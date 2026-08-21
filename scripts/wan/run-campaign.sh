#!/usr/bin/env bash
# Run one end-to-end multi-region WAN campaign on Scaleway.
#
# Egress mode is an explicit experiment input. Everything else comes from the
# corrected preregistered WAN harness. Paid resources are tagged and destroyed
# from the EXIT trap, including failed runs.
#
# Requires SCW_ACCESS_KEY, SCW_SECRET_KEY, SCW_DEFAULT_PROJECT_ID.
set -uo pipefail

out_dir=${1:?usage: run-campaign.sh OUT_DIR [CAPTURE_SECONDS] [coupled|isolated]}
capture_seconds=${2:-150}
egress_mode=${3:-coupled}
case "$egress_mode" in
  coupled|isolated) ;;
  *) echo "egress mode must be coupled or isolated" >&2; exit 2 ;;
esac
: "${SCW_SECRET_KEY:?}" ; : "${SCW_ACCESS_KEY:?}" ; : "${SCW_DEFAULT_PROJECT_ID:?}"

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
deployment="nomad-wan-${egress_mode}-$(date -u +%Y%m%d-%H%M%S)"
work="$out_dir/$deployment"
mkdir -p "$work"
echo "deployment $deployment (egress=$egress_mode)" >&2
echo "$deployment" > "$out_dir/deployment_id"
echo "$egress_mode" > "$work/egress_mode"

keep=${WAN_KEEP:-0}
cleanup() {
  local status=$?
  if [ "$keep" = "1" ]; then
    echo "WAN_KEEP=1: leaving $deployment running; tear it down by hand" >&2
    return
  fi
  echo "--- teardown of $deployment ---" >&2
  "$here/scaleway-teardown.sh" "$deployment" >&2
  for zone in fr-par-1 nl-ams-1 pl-waw-1; do
    local remaining
    remaining=$(curl -sS --max-time 30 -H "X-Auth-Token: $SCW_SECRET_KEY" \
      "https://api.scaleway.com/instance/v1/zones/$zone/servers?per_page=100" \
      | python3 -c "import sys,json; print(sum(1 for s in json.load(sys.stdin).get('servers',[]) if '$deployment' in (s.get('name') or '')))" 2>/dev/null || echo "?")
    echo "  $zone: $remaining server(s) of this deployment remain" >&2
  done
  exit $status
}
trap cleanup EXIT

echo "--- building exact campaign binaries from one commit ---" >&2
mkdir -p "$work/bin"
( cd "$repo" && go build -o "$work/bin/" ./cmd/nomad-node ./cmd/nomad-shaper ./cmd/nomad-bootstrap ) || exit 1
sha256sum "$work/bin/nomad-node" "$work/bin/nomad-shaper" "$work/bin/nomad-bootstrap" > "$work/bin/SHA256SUMS"

echo "--- reserving public addresses ---" >&2
endpoints=$(python3 "$here/reserve-ips.py" "$deployment" "$work/reserved-ips.json") || exit 1
echo "endpoints $endpoints" >&2

echo "--- bootstrapping signed topology for those addresses ---" >&2
"$work/bin/nomad-bootstrap" \
  --out="$work/runtime" \
  --envelope="$repo/deploy/fixture/demo.nomadobject" \
  --network-id=nomad-wan-live \
  --endpoints="$endpoints" \
  --cell-interval-ms=50 \
  --valid-for=6h \
  --authority-private-out="$work/authority.key" || exit 1

bucket="$deployment"
echo "--- creating campaign bucket $bucket ---" >&2
python3 - "$bucket" <<'PY' || exit 1
import os, sys, boto3
boto3.client("s3", region_name="fr-par", endpoint_url="https://s3.fr-par.scw.cloud",
             aws_access_key_id=os.environ["SCW_ACCESS_KEY"],
             aws_secret_access_key=os.environ["SCW_SECRET_KEY"]).create_bucket(Bucket=sys.argv[1])
print(f"created bucket {sys.argv[1]}", file=sys.stderr)
PY
echo "$bucket" > "$work/bucket"

echo "--- staging payload and minting presigned URLs ---" >&2
python3 "$here/stage-payload.py" "$bucket" "$work/runtime" "$work/urls.json" || exit 1

echo "--- building per-operator cloud-init ($egress_mode) ---" >&2
ssh-keygen -q -t ed25519 -N "" -f "$work/id_ed25519" <<< y >/dev/null 2>&1
base_epoch=$(( $(date -u +%s) + 420 ))
echo "first world slot at $(date -u -d "@$base_epoch" +%H:%M:%SZ)" >&2
for operator in operator-a operator-b operator-c; do
  python3 "$here/build-cloud-init.py" "$work/urls.json" "$operator" \
    "$work/id_ed25519.pub" "$capture_seconds" "$base_epoch" "$egress_mode" \
    "$work/cloud-init-$operator.yaml" || exit 1
done

echo "--- provisioning hosts ---" >&2
python3 "$here/provision.py" "$deployment" "$work/id_ed25519.pub" \
  "$work/servers.json" "$work" "$work/reserved-ips.json" || exit 1

echo "--- waiting for results ---" >&2
deadline=$(( capture_seconds * 3 + 1100 ))
python3 "$here/collect.py" "$bucket" "$work/results" "$deadline"
collect_status=$?

echo "--- results ---" >&2
ls -l "$work/results" >&2
echo "$work" > "$out_dir/last_run"
exit $collect_status
