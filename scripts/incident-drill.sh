#!/usr/bin/env bash
# An incident drill that runs, against real binaries and real sockets.
#
# PROD-28 asks that incident response is exercised. Two scenarios, both taken
# from deploy/RECOVERY.md, both with a verifiable outcome rather than a
# narrative:
#
#   1. A node that stops reporting. The crude alarm -- the process exiting --
#      is gone by design, so this checks that the liveness gate catches a node
#      that is present and not working, and clears when it recovers.
#
#   2. A hop sequence file restored from backup. The node looks healthy to
#      itself while every peer discards its traffic. This is the scenario an
#      operator is least likely to guess at and the one RECOVERY.md is built
#      around, so the drill proves the documented signal actually appears.
#
# It uses loopback endpoints and native binaries: no container runtime, so it
# runs anywhere the tests do.
set -u -o pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
if ! grep -qx 'module github.com/Jtensetti/nomad-testnet' "$repo_root/go.mod" 2>/dev/null; then
    echo "refusing to run: $repo_root is not the nomad-testnet repository" >&2
    exit 2
fi

declare -A node_pid
work="$(mktemp -d)"
bin="$work/bin"
runtime="$work/runtime"
failures=0
pids=()

cleanup() {
    for pid in "${pids[@]:-}"; do
        kill -CONT "$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
    done
    sleep 1
    for pid in "${pids[@]:-}"; do kill -9 "$pid" 2>/dev/null; done
    rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n=== %s ===\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

step "Build"
go build -o "$bin/" ./cmd/nomad-bootstrap ./cmd/nomad-node || exit 1

step "Bootstrap a three-operator network on loopback"
"$bin/nomad-bootstrap" -out "$runtime" \
    -envelope deploy/fixture/demo.nomadobject \
    -endpoints "127.0.0.1:4211,127.0.0.1:4212,127.0.0.1:4213" \
    -cell-interval-ms 50 >/dev/null || exit 1

start_operator() {
    local name=$1 port=$2 seed=$3
    local state="$work/$name/state" cache="$work/$name/cache"
    mkdir -p "$state" "$cache"
    local seed_flag=()
    [ "$seed" = "seed" ] && seed_flag=(--seed="$runtime/public/seed.json")
    "$bin/nomad-node" \
        --topology="$runtime/public/topology.json" \
        --authority-key="$runtime/public/authority.pub" \
        --secrets="$runtime/operators/$name/node-secrets.json" \
        --listen="127.0.0.1:$port" \
        --cache="$cache" \
        --state="$state/sequence" \
        --health="$state/health.json" \
        --cache-sweep=10s \
        "${seed_flag[@]}" >"$work/$name.log" 2>&1 &
    pids+=($!)
    node_pid[$name]=$!
}

health() {
    "$bin/nomad-node" --check-health="$work/$1/state/health.json" --max-silence="${2:-5s}" 2>&1
}

counter() {
    python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],0))" \
        "$work/$1/state/health.json" "$2" 2>/dev/null || echo 0
}

step "Start the network"
start_operator operator-a 4211 seed
start_operator operator-b 4212 none
start_operator operator-c 4213 none
sleep 4

for name in operator-a operator-b operator-c; do
    if health "$name" >/dev/null 2>&1; then
        pass "$name is emitting"
    else
        fail "$name did not come up: $(health "$name" 2>&1 | tail -1)"
        echo "--- $name log ---"; tail -5 "$work/$name.log"
    fi
done
[ "$failures" -gt 0 ] && { echo; echo "the network did not start; no scenario can run"; exit 1; }

step "Scenario 1: a node that is present and not working"
echo "Stopping operator-b's process without killing it, which is what a hung"
echo "node looks like: the process exists, the port is bound, nothing is emitted."
kill -STOP "${node_pid[operator-b]}"
sleep 7

if health operator-b >/dev/null 2>&1; then
    fail "the liveness gate called a stopped node healthy"
else
    pass "detected: $(health operator-b 2>&1 | tail -1)"
fi
if health operator-a >/dev/null 2>&1; then
    pass "operator-a is unaffected by its peer being down"
else
    fail "operator-a followed its peer down: $(health operator-a 2>&1 | tail -1)"
fi

echo "Recovering it. A resumed node does not carry on: while it was stopped it"
echo "missed its lateness budget by seconds, and a fixed-cadence sender that"
echo "wakes up behind refuses to emit a catch-up burst -- it exits instead. So"
echo "recovery is a restart, which is what the runbook has to say."
kill -CONT "${node_pid[operator-b]}"
sleep 3
if health operator-b >/dev/null 2>&1; then
    fail "the resumed node carried on, which would mean it emitted a catch-up burst"
else
    pass "as designed, the resumed node exited rather than catching up"
fi
start_operator operator-b 4212 none
sleep 4
if health operator-b >/dev/null 2>&1; then
    pass "operator-b recovered after a restart"
else
    fail "operator-b did not recover after a restart: $(health operator-b 2>&1 | tail -1)"
    tail -3 "$work/operator-b.log"
fi

step "Scenario 2: a hop sequence file restored from backup"
echo "RECOVERY.md says this leaves a node looking healthy to itself while every"
echo "peer discards its traffic, and that the only signal is a peer's"
echo "replay_rejected. Checking that is true of the shipped binary."

# The reservation on disk only advances when the node opens it, so a backup
# and a restore either side of a single restart are the same bytes and the
# restore does nothing. That is what a first version of this drill did, and it
# duly reported that the documented signal never appears.
#
# The realistic shape is the one that bites: back up, let the node restart a
# few times over the following weeks, then restore the old copy.
backup="$work/sequence.backup"
cp "$work/operator-a/state/sequence" "$backup"
echo "backed up operator-a's sequence reservation"

kill "${node_pid[operator-a]}"
sleep 2
start_operator operator-a 4211 seed
sleep 4
echo "operator-a restarted once since the backup, so its reservation has moved on"

declare -A before_replays
for peer in operator-a operator-b operator-c; do
    before_replays[$peer]=$(counter "$peer" replay_rejected)
done

kill "${node_pid[operator-a]}"
sleep 2
cp "$backup" "$work/operator-a/state/sequence"
echo "restored the old sequence file, the way any other file would be restored"
start_operator operator-a 4211 seed
sleep 6

# Which peer hears operator-a is decided by the signed plan, not by naming,
# so ask all of them. A first version of this drill asked only operator-b and
# reported "the documented signal does not appear" when the plan simply sent
# operator-a's cells somewhere else.
gained=0
a_sent=$(counter operator-a sent)
a_dropped=$(counter operator-a send_dropped)
echo "operator-a: sent=$a_sent send_dropped=$a_dropped"
for peer in operator-a operator-b operator-c; do
    after=$(counter "$peer" replay_rejected)
    delta=$((after - ${before_replays[$peer]}))
    echo "$peer: replay_rejected ${before_replays[$peer]} -> $after (+$delta)"
    gained=$((gained + delta))
done

if health operator-a >/dev/null 2>&1; then
    pass "as documented, operator-a reports itself healthy after the rollback"
else
    fail "operator-a reported unhealthy; RECOVERY.md says it cannot tell"
fi
if [ "$a_dropped" -eq 0 ]; then
    pass "as documented, operator-a counted no local drops"
else
    fail "operator-a counted $a_dropped local drops; the finding is stated wrongly"
fi
if [ "$gained" -gt 0 ]; then
    pass "the documented signal appeared: peers refused $gained replays in total"
else
    fail "no peer's replay_rejected moved, so the signal RECOVERY.md tells"
    fail "operators to watch does not appear in practice"
fi

step "Result"
if [ "$failures" -eq 0 ]; then
    echo "incident drill passed: both scenarios behaved as deploy/RECOVERY.md describes"
    exit 0
fi
echo "incident drill failed with $failures unmet expectation(s)"
exit 1
