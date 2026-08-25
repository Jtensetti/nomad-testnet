#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
evidence_root=${NOMAD_EVIDENCE_DIR:-"$repo_root/runtime/evidence"}
verified_root=${NOMAD_VERIFIED_CACHE:-"$repo_root/runtime/verified"}
compose_file="$repo_root/deploy/compose.yaml"
project_name=${NOMAD_COMPOSE_PROJECT:-nomad-live-e2e}
object_name=1f5863a9defd07015bcf20956b50369adc6ad62c8464e9da114a56c42a1d343c.nomadobject

mkdir -p "$evidence_root" "$verified_root"
chmod 0777 "$verified_root"
export NOMAD_VERIFIED_CACHE="$verified_root"

cleanup() {
    docker compose -p "$project_name" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose -p "$project_name" -f "$compose_file" up --build --detach

deadline=$(( $(date +%s) + 180 ))
while [ ! -s "$verified_root/$object_name" ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        docker compose -p "$project_name" -f "$compose_file" ps
        docker compose -p "$project_name" -f "$compose_file" logs --no-color
        echo "timed out waiting for verified browser object" >&2
        exit 1
    fi
    sleep 2
done

for service in operator-a operator-b operator-c share-a share-b share-c partial-fetcher materializer; do
    container_id=$(docker compose -p "$project_name" -f "$compose_file" ps -q "$service")
    test -n "$container_id"
    test "$(docker inspect -f '{{.State.Running}}' "$container_id")" = true
    test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" = true
    test "$(docker inspect -f '{{.Config.User}}' "$container_id")" = 65532:65532
    docker inspect -f '{{json .HostConfig.CapDrop}}' "$container_id" | grep -Fq '"ALL"'
    docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container_id" | grep -Fq 'no-new-privileges:true'
    test "$(docker inspect -f '{{.HostConfig.PidsLimit}}' "$container_id")" = 128
done
for service in operator-a operator-b operator-c; do
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        grep -Fq '"version": "nomad-operator-secrets-v3"' /operator/node-secrets.json
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        grep -Fq '"kex_private":' /operator/node-secrets.json
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        grep -Fq '"dkg_private":' /operator/node-secrets.json
    if docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        grep -Eq 'outbound_keys|inbound_keys' /operator/node-secrets.json; then
        echo "$service received centrally distributed peer keys" >&2
        exit 1
    fi
done
materializer_id=$(docker compose -p "$project_name" -f "$compose_file" ps -q materializer)
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$materializer_id")" = none
bootstrap_id=$(docker compose -p "$project_name" -f "$compose_file" ps -a -q bootstrap)
test -n "$bootstrap_id"
test "$(docker inspect -f '{{.State.ExitCode}}' "$bootstrap_id")" = 0
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$bootstrap_id")" = none
test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$bootstrap_id")" = true
test "$(docker inspect -f '{{.Config.User}}' "$bootstrap_id")" = 65532:65532

for service in dkg-a dkg-b dkg-c fixture-publisher; do
    container_id=$(docker compose -p "$project_name" -f "$compose_file" ps -a -q "$service")
    test -n "$container_id"
    test "$(docker inspect -f '{{.State.ExitCode}}' "$container_id")" = 0
    test "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container_id")" = true
    test "$(docker inspect -f '{{.Config.User}}' "$container_id")" = 65532:65532
    docker inspect -f '{{json .HostConfig.CapDrop}}' "$container_id" | grep -Fq '"ALL"'
    docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container_id" | grep -Fq 'no-new-privileges:true'
done
fixture_publisher_id=$(docker compose -p "$project_name" -f "$compose_file" ps -a -q fixture-publisher)
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$fixture_publisher_id")" = none

for name in a b c; do
    dkg_id=$(docker compose -p "$project_name" -f "$compose_file" ps -a -q "dkg-$name")
    docker cp "$dkg_id:/certificate/dkg-certificate.json" "$evidence_root/dkg-$name-certificate.json"
    docker compose -p "$project_name" -f "$compose_file" exec -T "operator-$name" \
        sha256sum /operator/distributed-threshold-share.json > "$evidence_root/operator-$name-share.sha256"
done
cmp "$evidence_root/dkg-a-certificate.json" "$evidence_root/dkg-b-certificate.json"
cmp "$evidence_root/dkg-a-certificate.json" "$evidence_root/dkg-c-certificate.json"
grep -Fq '"version": "nomad-dkg-certificate-v1"' "$evidence_root/dkg-a-certificate.json"
docker compose -p "$project_name" -f "$compose_file" exec -T operator-a \
    cat /published/descriptor.json > "$evidence_root/descriptor.json"
python3 - "$evidence_root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
certificate = json.loads((root / "dkg-a-certificate.json").read_text())
descriptor = json.loads((root / "descriptor.json").read_text())
if descriptor.get("version") != "nomad-batch-descriptor-v2":
    raise SystemExit("live descriptor is not the certified DKG format")
if descriptor.get("dkg_certificate") != certificate:
    raise SystemExit("live descriptor does not embed the distributed DKG certificate")
PY
test "$(cut -d ' ' -f 1 "$evidence_root/operator-a-share.sha256")" != "$(cut -d ' ' -f 1 "$evidence_root/operator-b-share.sha256")"
test "$(cut -d ' ' -f 1 "$evidence_root/operator-a-share.sha256")" != "$(cut -d ' ' -f 1 "$evidence_root/operator-c-share.sha256")"
test "$(cut -d ' ' -f 1 "$evidence_root/operator-b-share.sha256")" != "$(cut -d ' ' -f 1 "$evidence_root/operator-c-share.sha256")"

pcap="$evidence_root/fabric.pcap"
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "tcpdump is required for the live release gate" >&2
    exit 1
fi
network_id=$(docker network inspect -f '{{.Id}}' "${project_name}_fabric")
capture_interface="br-$(printf '%s' "$network_id" | cut -c1-12)"
ip link show "$capture_interface" >/dev/null
set +e
if [ "$(id -u)" -eq 0 ]; then
    timeout 6 tcpdump -i "$capture_interface" -s 0 -U -w "$pcap" udp port 4200 >/dev/null 2>&1
    capture_status=$?
elif command -v sudo >/dev/null 2>&1; then
    sudo timeout 6 tcpdump -i "$capture_interface" -s 0 -U -w "$pcap" udp port 4200 >/dev/null 2>&1
    capture_status=$?
    sudo chown "$(id -u):$(id -g)" "$pcap"
else
    echo "packet capture requires root or sudo" >&2
    exit 1
fi
set -e
if [ "$capture_status" -ne 0 ] && [ "$capture_status" -ne 124 ]; then
    echo "tcpdump failed with status $capture_status" >&2
    exit "$capture_status"
fi
test -s "$pcap"
python3 "$repo_root/scripts/verify-pcap.py" "$pcap" 50 > "$evidence_root/pcap-evidence.json"
test -s "$evidence_root/pcap-evidence.json"
cat "$evidence_root/pcap-evidence.json"

for service in operator-a operator-b operator-c; do
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" cat /state/health.json > "$evidence_root/$service-health.json"
done
python3 - "$evidence_root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
health = [json.loads((root / f"operator-{name}-health.json").read_text()) for name in "abc"]
if {item["operator_id"] for item in health} != {"operator-a", "operator-b", "operator-c"}:
    raise SystemExit("health evidence does not contain the three signed operators")
if len({item["topology_digest"] for item in health}) != 1:
    raise SystemExit("operators disagree on the topology digest")
for item in health:
    if item["sent"] < 20 or item["received"] < 20:
        raise SystemExit(f"insufficient live traffic in {item['operator_id']}")
    # send_dropped and health_deferred must be zero on a healthy run. They
    # exist so that a local failure costs one cell instead of the node, and a
    # live run that trips them means the emission path is failing for a reason
    # nothing here has explained.
    for counter in ("wrong_size", "unknown_peer", "auth_rejected", "replay_rejected",
                    "cache_rejected", "send_dropped", "health_deferred"):
        if item[counter] != 0:
            raise SystemExit(f"{item['operator_id']} reports {counter}={item[counter]}")
    # The node stays up through a local emission failure now, so "the process
    # is running" no longer means it emitted anything. Check what it did.
    if not item.get("last_sent_at", "").startswith("2"):
        raise SystemExit(f"{item['operator_id']} never recorded an emission")
PY

(cd "$verified_root" && sha256sum "$object_name") | tee "$evidence_root/object.sha256"
test "$(cut -d ' ' -f 1 "$evidence_root/object.sha256")" = e3d49edcf2c3840e1be80db008116367f2e35c2ff5d582d63ee7ddd68fe8b965
(cd "$evidence_root" && sha256sum fabric.pcap) > "$evidence_root/pcap.sha256"
docker compose -p "$project_name" -f "$compose_file" ps --format json |
    python3 -c 'import json,sys; print(json.dumps([json.loads(line) for line in sys.stdin if line.strip()], sort_keys=True))' \
    > "$evidence_root/processes.json"
python3 -m json.tool "$evidence_root/processes.json" >/dev/null
echo "live multi-process fabric-to-cache e2e passed"
