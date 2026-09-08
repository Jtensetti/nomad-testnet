#!/usr/bin/env python3
"""Provision one WAN campaign's hosts across three Scaleway regions.

Only dependency is the standard library, so it runs anywhere the campaign
does. Images are resolved at run time rather than pinned, because image IDs
are per-zone and rotate; a stale pin fails halfway through provisioning, which
is exactly the state that leaks paid resources.

Any failure tears down what this run created before re-raising. Teardown is
also available standalone (scaleway-teardown.sh) for the case where this
process dies without running its own cleanup.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ZONES = {"fr-par-1": "operator-a", "nl-ams-1": "operator-b", "pl-waw-1": "operator-c"}
IMAGE_NAME = "Ubuntu 24.04 Noble Numbat"
TYPE = os.environ.get("WAN_TYPE", "DEV1-S")


def api(method, zone, path, body=None, raw=None, content_type="application/json"):
    url = f"https://api.scaleway.com/instance/v1/zones/{zone}{path}"
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("X-Auth-Token", os.environ["SCW_SECRET_KEY"])
    if data is not None:
        request.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
            return json.loads(payload) if payload and content_type == "application/json" else {}
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {path} in {zone}: {error.code} {error.read().decode()[:300]}")


def resolve_image(zone):
    data = api("GET", zone, "/images?per_page=100&arch=x86_64")
    for image in data.get("images", []):
        if image.get("name") == IMAGE_NAME:
            return image["id"]
    raise RuntimeError(f"{IMAGE_NAME} not available in {zone}")


def destroy(created):
    for server in created:
        try:
            api("POST", server["zone"], f"/servers/{server['id']}/action", {"action": "terminate"})
            print(f"  rolled back {server['name']}", file=sys.stderr)
        except Exception as error:  # cleanup must not mask the original failure
            print(f"  ROLLBACK FAILED for {server['name']}: {error}", file=sys.stderr)


def main():
    deployment, pubkey_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    # An optional directory of per-operator cloud-init payloads. Without it the
    # hosts come up bare, which is only useful for connectivity checks.
    cloud_init_dir = sys.argv[4] if len(sys.argv) > 4 else None
    # Addresses reserved by reserve-ips.py, so the signed topology baked into
    # the cloud-init names the address the host will actually answer on. Without
    # it each server takes whatever dynamic address its zone hands out, which is
    # only knowable after boot -- too late to appear in the payload.
    reserved_path = sys.argv[5] if len(sys.argv) > 5 else None
    reserved = {}
    if reserved_path:
        reserved = {entry["operator"]: entry for entry in json.load(open(reserved_path))}
    pubkey = open(pubkey_path).read().strip()
    project = os.environ["SCW_DEFAULT_PROJECT_ID"]
    bare_cloud_init = (
        "#cloud-config\n"
        "users:\n  - name: root\n    ssh_authorized_keys:\n      - " + pubkey + "\n"
        "ssh_pwauth: false\n"
        "package_update: true\npackages:\n  - tcpdump\n"
    )

    created = []
    try:
        for zone, operator in ZONES.items():
            name = f"{deployment}-{operator}"
            image = resolve_image(zone)
            print(f"provisioning {name} in {zone}", file=sys.stderr)
            body = {
                "name": name,
                "commercial_type": TYPE,
                "image": image,
                "project": project,
                "tags": [deployment, "nomad-wan-campaign"],
            }
            if operator in reserved:
                body["public_ips"] = [reserved[operator]["id"]]
                body["dynamic_ip_required"] = False
            else:
                body["dynamic_ip_required"] = True
            server = api("POST", zone, "/servers", body)["server"]
            created.append({"zone": zone, "operator": operator, "id": server["id"],
                            "name": name, "image": image})
            if cloud_init_dir:
                payload = open(f"{cloud_init_dir}/cloud-init-{operator}.yaml").read()
            else:
                payload = bare_cloud_init
            api("PATCH", zone, f"/servers/{server['id']}/user_data/cloud-init",
                raw=payload.encode(), content_type="text/plain")
            api("POST", zone, f"/servers/{server['id']}/action", {"action": "poweron"})

        # Public addresses appear once the server leaves 'starting'.
        deadline = time.time() + 300
        while time.time() < deadline:
            pending = []
            for server in created:
                detail = api("GET", server["zone"], f"/servers/{server['id']}")["server"]
                address = (detail.get("public_ip") or {}).get("address")
                server["state"] = detail.get("state")
                if address:
                    server["ip"] = address
                else:
                    pending.append(server["name"])
            if not pending:
                break
            time.sleep(10)
        missing = [s["name"] for s in created if not s.get("ip")]
        if missing:
            raise RuntimeError(f"no public address for {missing}")
        # A host that answers on an address the signed topology does not name is
        # invisible to its peers, and the campaign would record silence rather
        # than a fault, so the mismatch is fatal here rather than puzzling later.
        for server in created:
            expected = reserved.get(server["operator"], {}).get("address")
            if expected and server["ip"] != expected:
                raise RuntimeError(
                    f"{server['name']} came up on {server['ip']}, not the "
                    f"reserved {expected} named in the topology")
    except Exception:
        print("provisioning failed; rolling back", file=sys.stderr)
        destroy(created)
        raise

    json.dump(created, open(out_path, "w"), indent=2)
    for server in created:
        print(f"  {server['operator']:12s} {server['zone']:10s} {server['ip']}", file=sys.stderr)


if __name__ == "__main__":
    main()
