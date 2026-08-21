#!/usr/bin/env python3
"""Wait for a WAN campaign's hosts to publish their results, then fetch them.

Polls the campaign bucket rather than the hosts, because the hosts are not
reachable on any port but 443 from every environment this runs in. Exits
non-zero if the campaign did not complete within the deadline, so a caller can
tear down and report rather than hang.
"""

import os
import sys
import time

import boto3


def main():
    if len(sys.argv) != 4:
        print("usage: collect.py BUCKET OUT_DIR DEADLINE_SECONDS", file=sys.stderr)
        return 2
    bucket, out_dir, deadline_seconds = sys.argv[1], sys.argv[2], int(sys.argv[3])
    os.makedirs(out_dir, exist_ok=True)

    s3 = boto3.client(
        "s3", region_name="fr-par", endpoint_url="https://s3.fr-par.scw.cloud",
        aws_access_key_id=os.environ["SCW_ACCESS_KEY"],
        aws_secret_access_key=os.environ["SCW_SECRET_KEY"])

    expected = {f"results/{operator}-{world}.pcap"
                for operator in ("operator-a", "operator-b", "operator-c")
                for world in ("idle1", "idle2", "active")}

    deadline = time.time() + deadline_seconds
    seen = set()
    while time.time() < deadline:
        listing = s3.list_objects_v2(Bucket=bucket, Prefix="results/")
        current = {item["Key"]: item["Size"] for item in listing.get("Contents", [])}
        for key, size in sorted(current.items()):
            if key not in seen:
                seen.add(key)
                print(f"  published {key} ({size} bytes)", file=sys.stderr)
        if expected <= set(current):
            break
        time.sleep(15)

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="results/")
    fetched = 0
    for item in listing.get("Contents", []):
        name = item["Key"].split("/", 1)[1]
        s3.download_file(bucket, item["Key"], os.path.join(out_dir, name))
        fetched += 1
    missing = sorted(expected - {i["Key"] for i in listing.get("Contents", [])})
    print(f"fetched {fetched} result files", file=sys.stderr)
    if missing:
        print(f"MISSING: {missing}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
