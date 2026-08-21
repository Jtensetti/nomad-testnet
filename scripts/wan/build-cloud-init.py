#!/usr/bin/env python3
"""Build the cloud-init payload that runs one operator's WAN campaign.

Each host runs both worlds itself, back to back, on the same machine and the
same network path: idle first, then active. Running them on one host rather
than on a pair is deliberate -- two hosts differ in placement, neighbours and
clock, and those differences would sit inside the comparison rather than
outside it.

The node is restarted between worlds so the second capture starts from the
same state as the first, and the capture is stopped and restarted with it, so
neither world's file contains any of the other's traffic.
"""

import json
import sys

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
      echo "preflight ok: node alive after 8s"
      stop_node
      sleep 2

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
        kill -0 $NODE_PID 2>/dev/null && echo "world $world: node still alive at end" \\
          || echo "world $world: WARNING node exited before the world ended"
        stop_node
        sleep 2
        kill -INT $tcpdump_pid 2>/dev/null; sleep 3; kill -9 $tcpdump_pid 2>/dev/null
        echo "world $world captured $(tcpdump -r "$capture" 2>/dev/null | wc -l) packets"
      }}

      # Idle: the node relays nothing of its own, so every cell it emits is
      # cover. Active: the same node with a published object seeded into its
      # cache, so real work competes for the same fixed cadence.
      run_world idle /opt/idle.pcap ""
      sleep 5
      run_world active /opt/active.pcap "--seed=/opt/seed.json"

      curl -fsS --retry 3 -X PUT -T /opt/idle.pcap '{idle_put}'
      curl -fsS --retry 3 -X PUT -T /opt/active.pcap '{active_put}'
      curl -fsS --retry 3 -X PUT -T /opt/state/health.json '{health_put}'
      echo "campaign complete"
      curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
runcmd:
  - [ /opt/campaign.sh ]
"""


def main():
    if len(sys.argv) != 6:
        print("usage: build-cloud-init.py URLS_JSON OPERATOR PUBKEY_PATH CAPTURE_SECONDS OUT",
              file=sys.stderr)
        return 2
    urls_path, operator, pubkey_path, capture_seconds, out_path = sys.argv[1:6]
    urls = json.load(open(urls_path))
    payload = TEMPLATE.format(
        pubkey=open(pubkey_path).read().strip(),
        node_url=urls["get"]["nomad-node"],
        topology_url=urls["get"]["topology.json"],
        authority_url=urls["get"]["authority.pub"],
        secrets_url=urls["get"][f"{operator}/node-secrets.json"],
        seed_url=urls["get"]["seed.json"],
        capture_seconds=int(capture_seconds),
        idle_put=urls["put"][f"results/{operator}-idle.pcap"],
        active_put=urls["put"][f"results/{operator}-active.pcap"],
        health_put=urls["put"][f"results/{operator}-health.json"],
        log_put=urls["put"][f"results/{operator}-log.txt"],
    )
    with open(out_path, "w") as handle:
        handle.write(payload)
    print(f"{operator}: {len(payload)} bytes of cloud-init", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
