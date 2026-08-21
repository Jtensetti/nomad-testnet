#!/usr/bin/env python3
"""Build one operator's mode-controlled WAN campaign payload.

The world order and absolute boundaries are Claude's corrected WAN instrument.
The only added variable is egress_mode: coupled or isolated. Analysis, packet
capture, timing thresholds and world definitions are unchanged.
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
      set -x
      exec > /opt/campaign.log 2>&1
      set -u
      umask 077
      EGRESS_MODE='{egress_mode}'

      mkdir -p /opt/cache /opt/state /run/nomad
      curl -fsSL --retry 5 --retry-delay 3 -o /opt/nomad-node '{node_url}'
      curl -fsSL --retry 5 --retry-delay 3 -o /opt/nomad-shaper '{shaper_url}'
      chmod 700 /opt/nomad-node /opt/nomad-shaper
      curl -fsSL --retry 5 -o /opt/topology.json '{topology_url}'
      curl -fsSL --retry 5 -o /opt/authority.pub '{authority_url}'
      curl -fsSL --retry 5 -o /opt/node-secrets.json '{secrets_url}'
      curl -fsSL --retry 5 -o /opt/seed.json '{seed_url}'
      chmod 600 /opt/node-secrets.json
      ls -l /opt

      start_node() {{
        local seed_flag=$1
        SHAPER_PID=""
        if [ "$EGRESS_MODE" = "isolated" ]; then
          rm -f /run/nomad/relay.sock
          /opt/nomad-shaper --topology=/opt/topology.json --authority-key=/opt/authority.pub \\
            --secrets=/opt/node-secrets.json --bind=0.0.0.0:0 \\
            --work-socket=/run/nomad/relay.sock --state=/opt/state/shaper-sequence \\
            --stats-out=/opt/state/shaper-stats.json &
          SHAPER_PID=$!
          for _ in $(seq 1 100); do
            [ -S /run/nomad/relay.sock ] && break
            kill -0 "$SHAPER_PID" 2>/dev/null || break
            sleep 0.1
          done
          if [ ! -S /run/nomad/relay.sock ]; then
            echo "isolated preflight: shaper socket did not appear"
            return 1
          fi
          /opt/nomad-node --topology=/opt/topology.json --authority-key=/opt/authority.pub \\
            --secrets=/opt/node-secrets.json --listen=:4200 --cache=/opt/cache \\
            --health=/opt/state/health.json --cache-sweep=30s \\
            --egress-mode=isolated --relay-socket=/run/nomad/relay.sock $seed_flag &
        else
          /opt/nomad-node --topology=/opt/topology.json --authority-key=/opt/authority.pub \\
            --secrets=/opt/node-secrets.json --listen=:4200 --cache=/opt/cache \\
            --state=/opt/state/sequence --health=/opt/state/health.json \\
            --cache-sweep=30s --egress-mode=coupled $seed_flag &
        fi
        NODE_PID=$!
      }}

      stop_node() {{
        kill "$NODE_PID" 2>/dev/null || true
        sleep 2
        kill -9 "$NODE_PID" 2>/dev/null || true
        if [ -n "${{SHAPER_PID:-}}" ]; then
          kill "$SHAPER_PID" 2>/dev/null || true
          for _ in $(seq 1 20); do
            kill -0 "$SHAPER_PID" 2>/dev/null || break
            sleep 0.1
          done
          kill -9 "$SHAPER_PID" 2>/dev/null || true
        fi
      }}

      rm -rf /opt/cache /opt/state; mkdir -p /opt/cache /opt/state /run/nomad
      if ! start_node ""; then
        echo "PREFLIGHT FAILED: start_node failed"
        curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
        exit 1
      fi
      sleep 8
      if ! kill -0 "$NODE_PID" 2>/dev/null; then
        echo "PREFLIGHT FAILED: node exited during startup"
        stop_node
        curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
        exit 1
      fi
      if [ "$EGRESS_MODE" = "isolated" ] && ! kill -0 "$SHAPER_PID" 2>/dev/null; then
        echo "PREFLIGHT FAILED: shaper exited during startup"
        stop_node
        curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
        exit 1
      fi
      echo "preflight ok: $EGRESS_MODE node path alive after 8s"
      stop_node
      sleep 2

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
        mkdir -p /opt/cache /opt/state /run/nomad
        rm -f /run/nomad/relay.sock
        tcpdump -i any -n -s 96 -U -w "$capture" 'udp port 4200' &
        local tcpdump_pid=$!
        sleep 3
        if ! start_node "$seed_flag"; then
          echo "world $world: WARNING start_node failed"
        fi
        sleep {capture_seconds}
        kill -0 "$NODE_PID" 2>/dev/null && echo "world $world: node still alive at end" \\
          || echo "world $world: WARNING node exited before the world ended"
        if [ "$EGRESS_MODE" = "isolated" ]; then
          kill -0 "$SHAPER_PID" 2>/dev/null && echo "world $world: shaper still alive at end" \\
            || echo "world $world: WARNING shaper exited before the world ended"
        fi
        stop_node
        sleep 2
        kill -INT "$tcpdump_pid" 2>/dev/null || true
        sleep 3
        kill -9 "$tcpdump_pid" 2>/dev/null || true
        echo "world $world captured $(tcpdump -r "$capture" 2>/dev/null | wc -l) packets"
      }}

{world_runs}

      curl -fsS --retry 3 -X PUT -T /opt/state/health.json '{health_put}' || true
      if [ -f /opt/state/shaper-stats.json ]; then
        curl -fsS --retry 3 -X PUT -T /opt/state/shaper-stats.json '{shaper_stats_put}' || true
      fi
      echo "campaign complete: egress_mode=$EGRESS_MODE"
      curl -fsS --retry 3 -X PUT -T /opt/campaign.log '{log_put}'
runcmd:
  - [ /opt/campaign.sh ]
"""

WORLD_ORDER = {
    "operator-a": ("idle1", "idle2", "active"),
    "operator-b": ("idle1", "active", "idle2"),
    "operator-c": ("active", "idle1", "idle2"),
}
SEED_FLAG = {"active": "--seed=/opt/seed.json", "idle1": "", "idle2": ""}
SLOT_GAP_SECONDS = 30


def world_runs(operator, urls, base_epoch, capture_seconds):
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
    if len(sys.argv) != 8:
        print("usage: build-cloud-init.py URLS_JSON OPERATOR PUBKEY_PATH CAPTURE_SECONDS "
              "BASE_EPOCH EGRESS_MODE OUT", file=sys.stderr)
        return 2
    urls_path, operator, pubkey_path, capture_seconds, base_epoch, egress_mode, out_path = sys.argv[1:8]
    if egress_mode not in ("coupled", "isolated"):
        print("EGRESS_MODE must be coupled or isolated", file=sys.stderr)
        return 2
    base_epoch = int(base_epoch)
    urls = json.load(open(urls_path))
    payload = TEMPLATE.format(
        pubkey=open(pubkey_path).read().strip(),
        egress_mode=egress_mode,
        node_url=urls["get"]["nomad-node"],
        shaper_url=urls["get"]["nomad-shaper"],
        topology_url=urls["get"]["topology.json"],
        authority_url=urls["get"]["authority.pub"],
        secrets_url=urls["get"][f"{operator}/node-secrets.json"],
        seed_url=urls["get"]["seed.json"],
        capture_seconds=int(capture_seconds),
        world_runs=world_runs(operator, urls, base_epoch, int(capture_seconds)),
        health_put=urls["put"][f"results/{operator}-health.json"],
        shaper_stats_put=urls["put"][f"results/{operator}-shaper-stats.json"],
        log_put=urls["put"][f"results/{operator}-log.txt"],
    )
    with open(out_path, "w") as handle:
        handle.write(payload)
    print(f"{operator}: {egress_mode}, {len(payload)} bytes, worlds "
          f"{' -> '.join(WORLD_ORDER[operator])}, first slot at "
          f"{time.strftime('%H:%M:%SZ', time.gmtime(base_epoch))}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
