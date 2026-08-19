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
done

pcap="$evidence_root/fabric.pcap"
if command -v tcpdump >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
        sudo timeout 6 tcpdump -i any -s 0 -U -w "$pcap" udp port 4200 >/dev/null 2>&1 || test "$?" = 124
        sudo chown "$(id -u):$(id -g)" "$pcap"
    else
        timeout 6 tcpdump -i any -s 0 -U -w "$pcap" udp port 4200 >/dev/null 2>&1 || test "$?" = 124
    fi
    python3 "$repo_root/scripts/verify-pcap.py" "$pcap" | tee "$evidence_root/pcap-evidence.json"
fi

sha256sum "$verified_root/$object_name" | tee "$evidence_root/object.sha256"
docker compose -p "$project_name" -f "$compose_file" ps --format json > "$evidence_root/processes.json"
echo "live multi-process fabric-to-cache e2e passed"
