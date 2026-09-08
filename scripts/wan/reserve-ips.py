#!/usr/bin/env python3
"""Reserve one flexible public address per campaign zone, before any host boots.

A campaign host is told its peers through a signed topology, and cloud-init can
only be supplied when a server is created -- so the addresses have to be known
before the servers exist. Reserving them first removes that ordering problem;
the alternative is booting bare hosts to discover their addresses and rebooting
them into the real payload, which cloud-init will not re-run.

Every address is tagged with the deployment so scaleway-teardown.sh reclaims it
even if this process dies before a server is ever attached.
"""

import json
import os
import sys
import urllib.error
import urllib.request

ZONES = {"fr-par-1": "operator-a", "nl-ams-1": "operator-b", "pl-waw-1": "operator-c"}
PORT = 4200


def api(method, zone, path, body=None):
    url = f"https://api.scaleway.com/instance/v1/zones/{zone}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-Auth-Token", os.environ["SCW_SECRET_KEY"])
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {path} in {zone}: {error.code} {error.read().decode()[:300]}")


def release(reserved):
    for entry in reserved:
        try:
            api("DELETE", entry["zone"], f"/ips/{entry['id']}")
            print(f"  released {entry['address']}", file=sys.stderr)
        except Exception as error:  # cleanup must not mask the original failure
            print(f"  RELEASE FAILED for {entry['address']}: {error}", file=sys.stderr)


def main():
    if len(sys.argv) != 3:
        print("usage: reserve-ips.py DEPLOYMENT OUT_JSON", file=sys.stderr)
        return 2
    deployment, out_path = sys.argv[1], sys.argv[2]
    project = os.environ["SCW_DEFAULT_PROJECT_ID"]

    reserved = []
    try:
        for zone, operator in ZONES.items():
            ip = api("POST", zone, "/ips", {
                "project": project,
                "type": "routed_ipv4",
                "tags": [deployment, "nomad-wan-campaign", operator],
            })["ip"]
            reserved.append({"zone": zone, "operator": operator,
                             "id": ip["id"], "address": ip["address"]})
            print(f"  {operator:12s} {zone:10s} {ip['address']}", file=sys.stderr)
    except Exception:
        print("reservation failed; releasing what this run took", file=sys.stderr)
        release(reserved)
        raise

    json.dump(reserved, open(out_path, "w"), indent=2)
    print(",".join(f"{entry['address']}:{PORT}" for entry in reserved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
