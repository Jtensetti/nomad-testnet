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
    # The core-dump limit, read from the running container rather than from the
    # compose file. A core file is the whole address space, so no telemetry
    # allowlist makes one safe; deploy/compose_test.go checks that the file
    # asks for this, and this checks that the container got it.
    core_limit=$(docker inspect \
        -f '{{range .HostConfig.Ulimits}}{{if eq .Name "core"}}{{.Soft}}/{{.Hard}}{{end}}{{end}}' \
        "$container_id")
    if [ "$core_limit" != "0/0" ]; then
        echo "$service has core ulimit '${core_limit:-unset}', not 0/0: a crash there" >&2
        echo "would write the process address space to disk" >&2
        exit 1
    fi
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
if descriptor.get("version") != "nomad-batch-descriptor-v3":
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
# capture_window writes one window of fabric traffic to $1 over $2 seconds.
#
# It is a function because the load gate below needs two windows that differ
# by exactly one thing. Two copies of this would drift, and the direction they
# would drift is toward the quiet window being captured more carefully than
# the loaded one.
capture_window() {
    local destination="$1" seconds="$2" status
    set +e
    if [ "$(id -u)" -eq 0 ]; then
        timeout "$seconds" tcpdump -i "$capture_interface" -s 0 -U -B 16384 \
            -w "$destination" udp port 4200 >/dev/null 2>&1
        status=$?
    elif command -v sudo >/dev/null 2>&1; then
        sudo timeout "$seconds" tcpdump -i "$capture_interface" -s 0 -U -B 16384 \
            -w "$destination" udp port 4200 >/dev/null 2>&1
        status=$?
        sudo chown "$(id -u):$(id -g)" "$destination"
    else
        echo "packet capture requires root or sudo" >&2
        exit 1
    fi
    set -e
    # 124 is timeout's own exit for the deadline it was given, which is how
    # every one of these captures is meant to end.
    if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
        echo "tcpdump failed with status $status" >&2
        exit "$status"
    fi
    test -s "$destination"
}

capture_window "$pcap" 6
python3 "$repo_root/scripts/verify-pcap.py" "$pcap" 50 > "$evidence_root/pcap-evidence.json"
test -s "$evidence_root/pcap-evidence.json"
cat "$evidence_root/pcap-evidence.json"

for service in operator-a operator-b operator-c; do
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        cat /state/health.json > "$evidence_root/$service-health-quiet.json"
done

# The load gate. PROD-14 claims a resource limit does not change what a node
# emits, and every measurement behind that claim was in-process: a goroutine
# writing to a channel is not an interface, and a test binary holding both
# ends is not a deployment. This is the composed stack, on the fabric bridge,
# with an unrecognised sender flooding an operator's port.
#
# The flood comes from the host rather than a container, so the release image
# does not ship a flood generator. Host-to-container traffic crosses the same
# bridge, so it lands in the same capture the cadence is read from -- which is
# the point: the gate refuses a run where the flood is not visible on the
# wire, because a flood that never arrived produces a second quiet window and
# reads as a pass.
operator_a_address=$(docker inspect -f \
    "{{(index .NetworkSettings.Networks \"${project_name}_fabric\").IPAddress}}" \
    "$(docker compose -p "$project_name" -f "$compose_file" ps -q operator-a)")
test -n "$operator_a_address"
flood_source=$(ip -4 -o addr show dev "$capture_interface" | awk '{print $4}' | cut -d/ -f1)
test -n "$flood_source"

go build -o "$evidence_root/nomad-load" "$repo_root/cmd/nomad-load"
"$evidence_root/nomad-load" --target "${operator_a_address}:4200" --rate 3000 \
    --duration 9s --report "$evidence_root/load.json" > /dev/null &
load_pid=$!
# Started after the flood so the whole window is loaded, and shorter than it
# so the flood outlives the capture at both ends.
sleep 1
capture_window "$evidence_root/fabric-loaded.pcap" 6
wait "$load_pid"
cat "$evidence_root/load.json"

python3 "$repo_root/scripts/verify-pcap.py" "$evidence_root/fabric-loaded.pcap" 50 \
    --filter "udp port 4200 and not src host $flood_source" \
    > "$evidence_root/pcap-evidence-loaded.json"
test -s "$evidence_root/pcap-evidence-loaded.json"
cat "$evidence_root/pcap-evidence-loaded.json"

python3 "$repo_root/scripts/verify-load.py" \
    "$evidence_root/pcap-evidence.json" \
    "$evidence_root/pcap-evidence-loaded.json" \
    "$pcap" \
    "$evidence_root/fabric-loaded.pcap" \
    "$flood_source" > "$evidence_root/load-evidence.json"
test -s "$evidence_root/load-evidence.json"
cat "$evidence_root/load-evidence.json"

for service in operator-a operator-b operator-c; do
    docker compose -p "$project_name" -f "$compose_file" exec -T "$service" \
        cat /state/health.json > "$evidence_root/$service-health-loaded.json"
done
python3 - "$evidence_root" <<'LOADPY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
findings = []
for name in "abc":
    operator = f"operator-{name}"
    quiet = json.loads((root / f"{operator}-health-quiet.json").read_text())
    loaded = json.loads((root / f"{operator}-health-loaded.json").read_text())

    # A flood costs cells, never the node. send_dropped exists so that a local
    # emission failure costs one cell instead of the process; under load it
    # must still be zero, and health_deferred with it. The other three would
    # mean the flood was mistaken for something it is not.
    for counter in ("send_dropped", "health_deferred", "wrong_size",
                    "auth_rejected", "replay_rejected", "cache_rejected"):
        if loaded[counter] != 0:
            findings.append(f"{operator} reports {counter}={loaded[counter]} under load")

    # Emission continued. A node that stopped emitting altogether would show
    # exactly the same zero counters as one that carried on.
    if loaded["sent"] <= quiet["sent"]:
        findings.append(
            f"{operator} had sent {quiet['sent']} cells before the flood and "
            f"{loaded['sent']} after, so it emitted nothing during it")

# The positive control, inside the process this time. The capture proves the
# flood was on the wire; this proves it reached the code that had to refuse
# it. Only operator-a was targeted, so only operator-a shows the refusals.
quiet = json.loads((root / "operator-a-health-quiet.json").read_text())
loaded = json.loads((root / "operator-a-health-loaded.json").read_text())
refused = loaded["unknown_peer"] - quiet["unknown_peer"]
if refused < 1000:
    findings.append(
        f"operator-a refused {refused} datagrams from unrecognised senders across the "
        "flood. The flood is supposed to reach the peer lookup and be refused there, "
        "so a count this low means it never cost the process anything -- and the zero "
        "counters above then say nothing about behaviour under load")

if findings:
    for finding in findings:
        print(finding, file=sys.stderr)
    raise SystemExit("the fabric did not survive the load gate")
print(json.dumps({"operator_a_unknown_peer_refusals_under_load": refused}, sort_keys=True))
LOADPY

python3 - "$evidence_root" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
# The quiet snapshot, taken before the load gate ran. The strict zero
# counters below are what a fabric with nothing attacking it must show; the
# loaded snapshot is judged separately, and differently, further down.
health = [json.loads((root / f"operator-{name}-health-quiet.json").read_text()) for name in "abc"]
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
# The healthcheck's verdict is worth nothing if nothing reads it. A node no
# longer stops when its emission path breaks, so "the container is running" is
# not evidence that it emitted anything; the healthcheck asks what it emitted,
# and this asserts the answer.
python3 - "$evidence_root/processes.json" <<'PY'
import json
import pathlib
import sys

processes = json.loads(pathlib.Path(sys.argv[1]).read_text())
operators = [p for p in processes if p.get("Service", "").startswith("operator-")]
if len(operators) != 3:
    raise SystemExit(f"expected three operator containers, found {len(operators)}")
for process in operators:
    health = process.get("Health", "")
    if health != "healthy":
        raise SystemExit(
            f"{process['Service']} reports health {health!r}: the node is running but "
            "its emission liveness check did not pass"
        )
PY
echo "live multi-process fabric-to-cache e2e passed"
