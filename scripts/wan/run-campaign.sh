#!/usr/bin/env bash
# Run one end-to-end multi-region WAN two-world campaign on Scaleway.
#
# One script rather than a sequence of steps run by hand, because the result is
# meant to be evidence: a reviewer who cannot re-run the measurement cannot
# check it. Everything paid for is created under a single deployment tag and
# torn down by an EXIT trap, so an abort between "create" and "measure" does
# not leave instances billing.
#
# Requires SCW_ACCESS_KEY, SCW_SECRET_KEY, SCW_DEFAULT_PROJECT_ID.
set -uo pipefail

out_dir=${1:?usage: run-campaign.sh OUT_DIR [CAPTURE_SECONDS]}
capture_seconds=${2:-150}
: "${SCW_SECRET_KEY:?}" ; : "${SCW_ACCESS_KEY:?}" ; : "${SCW_DEFAULT_PROJECT_ID:?}"

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
deployment="nomad-wan-$(date -u +%Y%m%d-%H%M%S)"
work="$out_dir/$deployment"
mkdir -p "$work"
echo "deployment $deployment" >&2
echo "$deployment" > "$out_dir/deployment_id"

keep=${WAN_KEEP:-0}
cleanup() {
  local status=$?
  if [ "$keep" = "1" ]; then
    echo "WAN_KEEP=1: leaving $deployment running; tear it down by hand" >&2
    return
  fi
  echo "--- teardown of $deployment ---" >&2
  "$here/scaleway-teardown.sh" "$deployment" >&2
  # Prove it rather than assume it: a teardown that silently did nothing looks
  # exactly like one that worked.
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

echo "--- building campaign binaries ---" >&2
mkdir -p "$work/bin"
( cd "$repo" && go build -o "$work/bin/" ./cmd/nomad-node ./cmd/nomad-bootstrap ) || exit 1

echo "--- reserving public addresses ---" >&2
endpoints=$(python3 "$here/reserve-ips.py" "$deployment" "$work/reserved-ips.json") || exit 1
echo "endpoints $endpoints" >&2

echo "--- bootstrapping signed topology for those addresses ---" >&2
# The topology has to outlive the campaign by enough that a slow boot does not
# expire it mid-run, and no longer than the credentials it travels with.
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

echo "--- building per-operator cloud-init ---" >&2
ssh-keygen -q -t ed25519 -N "" -f "$work/id_ed25519" <<< y >/dev/null 2>&1
# Every host runs its worlds on the same absolute schedule, so no node sees a
# peer restart inside its own world. The offset is the slack a host needs to be
# provisioned, boot, install tcpdump and pass preflight before the first slot.
base_epoch=$(( $(date -u +%s) + 420 ))
echo "first world slot at $(date -u -d "@$base_epoch" +%H:%M:%SZ)" >&2
for operator in operator-a operator-b operator-c; do
  python3 "$here/build-cloud-init.py" "$work/urls.json" "$operator" \
    "$work/id_ed25519.pub" "$capture_seconds" "$base_epoch" \
    "$work/cloud-init-$operator.yaml" || exit 1
done

echo "--- provisioning hosts ---" >&2
python3 "$here/provision.py" "$deployment" "$work/id_ed25519.pub" \
  "$work/servers.json" "$work" "$work/reserved-ips.json" || exit 1

echo "--- waiting for results ---" >&2
# Boot, package install, two captures and the uploads, with room for a slow
# apt mirror in one region not to fail the whole campaign.
deadline=$(( capture_seconds * 3 + 1100 ))
python3 "$here/collect.py" "$bucket" "$work/results" "$deadline"
collect_status=$?

echo "--- results ---" >&2
ls -l "$work/results" >&2
echo "$work" > "$out_dir/last_run"
exit $collect_status
