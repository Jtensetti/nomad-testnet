#!/usr/bin/env python3
"""Build the cloud-init payload that runs one operator's WAN campaign.

Each host runs every world itself, back to back, on the same machine and the
same network path. Running them on one host rather than spreading them over
several is deliberate -- two hosts differ in placement, neighbours and clock,
and those differences would sit inside the comparison rather than outside it.

Three worlds, not two: two idle series and one active. Without a pair of idle
series there is no noise floor, and a rejection cannot be told apart from any
two captures on that host differing. The first WAN campaign to reach a verdict
ran idle against active alone and rejected one host of three at KS p=0.00988,
with no control pair to say whether two idle captures would have done the same.

The order is rotated per operator so no world always occupies the same
position. Warm-up and drift within a run land on whichever world is scheduled
there, so a fixed order puts them systematically on one world; that is a
confound, not a leak.

The node is restarted between worlds so each capture starts from the same
state, and the capture is stopped and restarted with it, so no world's file
contains any of another's traffic.

World boundaries are absolute wall-clock times shared by every host, not
offsets from each host's own boot. Hosts boot up to half a minute apart, and in
a ring exactly one of them starts before its upstream peer: that host records
its peer's previous world, then sees the peer restart and its sequence counter
reset, and correctly rejects the rest of the world as replays. Measured on the
first three-world campaign, one host rejected 5574 of 5673 received cells that
way while the other two rejected none. Emissions are unaffected -- they are
fixed-cadence cover either way -- but the relay path is not exercised, so the
boundaries are aligned rather than left to boot order.
"""

import json
import sys
import time

TEMPLATE = """#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - {pubkey}
package_update: true
packages:
  - tcpdump
write_files:
  - path: /opt/campaign.sh
    permissions: '0700'
    content: |
      #!/bin/bash
      # Never abort on a single failed step: a half-finished campaign that
      # uploads its log is diagnosable, one that dies silently is not.
      set -x
      exec > /opt/campaign.log 2>&1
      set -u

      # curl honours the inherited umask, and the node refuses to load an
      # operator secret that is group- or world-readable. Without this the
      # fetched secrets land 0644 and every world captures nothing.
      umask 077

      mkdir -p /opt/cache /opt/state
      curl -fsSL --retry 5 --retry-delay 3 -o /opt/nomad-node '{node_url}'
      chmod 700 /opt/nomad-node
      curl -fsSL --retry 5 -o /opt/topology.json '{topology_url}'
      curl -fsSL --retry 5 -o /opt/authority.pub '{authority_url}'
      curl -fsSL --retry 5 -o /opt/node-secrets.json '{secrets_url}'
      curl -fsSL --retry 5 -o /opt/seed.json '{seed_url}'
      chmod 600 /opt/node-secrets.json
      ls -l /opt

      start_node() {{
        local seed_flag=$1
        /opt/nomad-node --topology=/opt/topology.json --authority-key=/opt/authority.pub \\
          --secrets=/opt/node-secrets.json --listen=:4200 --cache=/opt/cache \\
          --state=/opt/state/sequence --health=/opt/state/health.json \\
          --cache-sweep=30s $seed_flag &
        NODE_PID=$!
      }}

      stop_node() {{
        kill $NODE_PID 2>/dev/null; sleep 2; kill -9 $NODE_PID 2>/dev/null
      }}

      # Preflight. A node that refuses to start does so within a second, and
      # without this the campaign would spend two 150s captures recording
      # nothing before anyone found out.
      rm -rf /opt/cache /opt/state; mkdir -p /opt/cache /opt/state
      start_node ""
      sleep 8
      if ! kill -0 $NODE_PID 2>/dev/null; then
        echo "PREFLIGHT FAILED: node exited during startup; not running any world"
        stop_node
        curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
        exit 1
      fi
      # A live process is no longer evidence that the node emits. It does not
      # stop when a local condition breaks its emission path, so a full disk
      # or a firewall rule yields a full-length world with an empty capture
      # and a process that passes every liveness check. Ask what it emitted.
      if ! /opt/nomad-node --check-health=/opt/state/health.json --max-silence=10s; then
        echo "PREFLIGHT FAILED: node is running but emitting nothing"
        stop_node
        curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
        exit 1
      fi
      echo "preflight ok: node alive and emitting after 8s"
      stop_node
      sleep 2

      # Wait until this world's shared start time. Every host computes the
      # same instants, so no node sees a peer restart inside its own world.
      wait_until() {{
        local target=$1 now
        now=$(date +%s)
        if [ "$now" -lt "$target" ]; then
          sleep $((target - now))
        elif [ "$now" -gt $((target + {capture_seconds})) ]; then
          echo "WARNING late by $((now - target))s for slot $target; worlds are not aligned"
        fi
      }}

      run_world() {{
        local world=$1 capture=$2 seed_flag=$3
        rm -rf /opt/cache /opt/state
        mkdir -p /opt/cache /opt/state
        # -U writes packets as they arrive, so a killed tcpdump still leaves a
        # readable file rather than a truncated buffer.
        tcpdump -i any -n -s 96 -U -w "$capture" 'udp port 4200' &
        local tcpdump_pid=$!
        sleep 3
        start_node "$seed_flag"
        sleep {capture_seconds}
        # A node that died mid-world makes the capture meaningless rather than
        # merely short, so say so in the log next to the packet count.
        if ! kill -0 $NODE_PID 2>/dev/null; then
          echo "world $world: WARNING node exited before the world ended"
        elif ! /opt/nomad-node --check-health=/opt/state/health.json --max-silence=10s; then
          echo "world $world: WARNING node alive but emitted nothing; capture is not a measurement"
        else
          echo "world $world: node alive and emitting at end"
        fi
        stop_node
        sleep 2
        kill -INT $tcpdump_pid 2>/dev/null; sleep 3; kill -9 $tcpdump_pid 2>/dev/null
        echo "world $world captured $(tcpdump -r "$capture" 2>/dev/null | wc -l) packets"
      }}

      # Idle: the node relays nothing of its own, so every cell it emits is
      # cover. Active: the same node with a published object seeded into its
      # cache, so real work competes for the same fixed cadence. Two idle
      # series give the noise floor the active one is judged against.
{world_runs}

      curl -fsS --retry 3 -X PUT -T /opt/state/health.json '{health_put}'
      echo "campaign complete"
      curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
runcmd:
  - [ /opt/campaign.sh ]
"""


# Each operator runs the same three worlds in a different order, so position
# and world are independent across the campaign.
WORLD_ORDER = {
    "operator-a": ("idle1", "idle2", "active"),
    "operator-b": ("idle1", "active", "idle2"),
    "operator-c": ("active", "idle1", "idle2"),
}
SEED_FLAG = {"active": "--seed=/opt/seed.json", "idle1": "", "idle2": ""}
# Slack between worlds: node and capture shutdown, then a fresh start.
SLOT_GAP_SECONDS = 30


def world_runs(operator, urls, base_epoch, capture_seconds):
    """Render the run and upload lines for one operator's world order."""
    lines = []
    for position, world in enumerate(WORLD_ORDER[operator]):
        slot = base_epoch + position * (capture_seconds + SLOT_GAP_SECONDS)
        lines.append(f"      wait_until {slot}")
        lines.append(f'      run_world {world} /opt/{world}.pcap "{SEED_FLAG[world]}"')
    lines.append("")
    for world in WORLD_ORDER[operator]:
        url = urls["put"][f"results/{operator}-{world}.pcap"]
        lines.append(f"      curl -fsS --retry 3 -X PUT -T /opt/{world}.pcap '{url}'")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 7:
        print("usage: build-cloud-init.py URLS_JSON OPERATOR PUBKEY_PATH CAPTURE_SECONDS "
              "BASE_EPOCH OUT", file=sys.stderr)
        return 2
    urls_path, operator, pubkey_path, capture_seconds, base_epoch, out_path = sys.argv[1:7]
    base_epoch = int(base_epoch)
    urls = json.load(open(urls_path))
    payload = TEMPLATE.format(
        pubkey=open(pubkey_path).read().strip(),
        node_url=urls["get"]["nomad-node"],
        topology_url=urls["get"]["topology.json"],
        authority_url=urls["get"]["authority.pub"],
        secrets_url=urls["get"][f"{operator}/node-secrets.json"],
        seed_url=urls["get"]["seed.json"],
        capture_seconds=int(capture_seconds),
        world_runs=world_runs(operator, urls, base_epoch, int(capture_seconds)),
        health_put=urls["put"][f"results/{operator}-health.json"],
        log_put=urls["put"][f"results/{operator}-log.txt"],
    )
    with open(out_path, "w") as handle:
        handle.write(payload)
    print(f"{operator}: {len(payload)} bytes of cloud-init, worlds "
          f"{' -> '.join(WORLD_ORDER[operator])}, first slot at "
          f"{time.strftime('%H:%M:%SZ', time.gmtime(base_epoch))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
