#!/usr/bin/env python3
"""Stage a WAN campaign's payload in Scaleway Object Storage.

Hosts receive only per-object presigned URLs. Both egress implementations are
staged from the same commit so an A/B campaign changes only the process
boundary, not the wire implementation or analysis.
"""

import json
import os
import sys

import boto3

ENDPOINT = "https://s3.fr-par.scw.cloud"
REGION = "fr-par"
OPERATORS = ("operator-a", "operator-b", "operator-c")
WORLDS = ("idle1", "idle2", "active")
EXPIRY_SECONDS = 7200


def client():
    return boto3.client(
        "s3",
        region_name=REGION,
        endpoint_url=ENDPOINT,
        aws_access_key_id=os.environ["SCW_ACCESS_KEY"],
        aws_secret_access_key=os.environ["SCW_SECRET_KEY"],
    )


def main():
    if len(sys.argv) != 4:
        print("usage: stage-payload.py BUCKET RUNTIME_DIR OUT_URLS_JSON", file=sys.stderr)
        return 2
    bucket, runtime, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    binary_dir = os.path.join(os.path.dirname(runtime), "bin")

    uploads = {
        "nomad-node": os.path.join(binary_dir, "nomad-node"),
        "nomad-shaper": os.path.join(binary_dir, "nomad-shaper"),
        "topology.json": f"{runtime}/public/topology.json",
        "authority.pub": f"{runtime}/public/authority.pub",
        "seed.json": f"{runtime}/public/seed.json",
    }
    for operator in OPERATORS:
        uploads[f"{operator}/node-secrets.json"] = f"{runtime}/operators/{operator}/node-secrets.json"

    for key, path in uploads.items():
        if not os.path.isfile(path):
            raise SystemExit(f"missing staged input {key}: {path}")

    s3 = client()
    for key, path in uploads.items():
        s3.upload_file(path, bucket, key)
    print(f"uploaded {len(uploads)} objects", file=sys.stderr)

    urls = {"get": {}, "put": {}}
    for key in uploads:
        urls["get"][key] = s3.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=EXPIRY_SECONDS)
    for operator in OPERATORS:
        for world in WORLDS:
            key = f"results/{operator}-{world}.pcap"
            urls["put"][key] = s3.generate_presigned_url(
                "put_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=EXPIRY_SECONDS)
        for extra in ("health.json", "log.txt", "shaper-stats.json"):
            key = f"results/{operator}-{extra}"
            urls["put"][key] = s3.generate_presigned_url(
                "put_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=EXPIRY_SECONDS)

    with open(out_path, "w") as handle:
        json.dump(urls, handle)
    os.chmod(out_path, 0o600)
    print(f"presigned {len(urls['get'])} GET and {len(urls['put'])} PUT, "
          f"expiring in {EXPIRY_SECONDS // 3600}h", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
