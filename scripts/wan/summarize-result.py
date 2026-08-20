#!/usr/bin/env python3
"""Render a successful Nomad WAN evidence directory as a human-readable result.

This script is intentionally conservative: it only reports PASS for gates that
have already failed closed earlier in the WAN harness. It never upgrades the
result into an anonymity, independence, publication, or production claim.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def die(message: str) -> None:
    raise SystemExit(message)


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        if not raw or raw.lstrip().startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def fmt(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def main() -> int:
    if len(sys.argv) != 2:
        die("usage: summarize-result.py EVIDENCE_DIRECTORY")
    root = Path(sys.argv[1])
    cadence_path = root / "cadence.json"
    nodes_path = root / "nodes.json"
    cert_path = root / "dkg" / "CERTIFICATE_SHA256"
    boundary_path = root / "CLAIM_BOUNDARY.txt"
    if not cadence_path.is_file() or not nodes_path.is_file() or not cert_path.is_file():
        die("WAN evidence is incomplete; refusing to render a PASS result")

    cadence = json.loads(cadence_path.read_text())
    nodes = json.loads(nodes_path.read_text())
    env = read_env(root / "deployment.env")
    operators = cadence.get("operators")
    if not isinstance(operators, dict) or len(operators) != 3:
        die("cadence evidence must contain exactly three operators")
    if cadence.get("production_independence") is not False:
        die("unexpected independence claim in WAN evidence")

    cert_digest = cert_path.read_text().strip().split()[0]
    capture_seconds = env.get("CAPTURE_SECONDS")
    if not capture_seconds and boundary_path.is_file():
        for line in boundary_path.read_text().splitlines():
            if line.startswith("capture_seconds="):
                capture_seconds = line.split("=", 1)[1]
                break
    capture_seconds = capture_seconds or "recorded in raw evidence"

    lines = [
        "# Nomad real-WAN test result",
        "",
        "**Status: PASS for the gates exercised by this run.**",
        "",
        "This run completed Nomad's distributed DKG and then observed the fixed-cadence",
        "reader-side fabric across three real Scaleway regions. The harness fails before",
        "this file is generated if DKG certificates disagree, a captured Nomad UDP payload",
        "is not 1200 bytes, the sender catches up with a burst, the sender changes its signed",
        "destination, or the no-fault WAN path falls outside the registered cadence bounds.",
        "",
        "## What ran",
        "",
        f"- Deployment: `{cadence.get('profile', 'unknown')}`",
        f"- Capture duration: **{capture_seconds} seconds**",
        f"- Signed cell interval: **{fmt(cadence.get('expected_interval_ms'))} ms**",
        "- Administrative domains: **1** (all three VPSs are controlled from this project)",
        f"- Public DKG certificate SHA-256: `{cert_digest}`",
        "",
        "## Observed network behavior",
        "",
        "| Operator | Region | Emission mean | Emission min–max | Arrival mean | Arrival min–max | Delivery ratio |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]

    for operator in sorted(operators):
        item = operators[operator]
        if not isinstance(item, dict):
            die(f"invalid operator evidence for {operator}")
        node = nodes.get(operator, {})
        emission = item.get("emission", {})
        arrival = item.get("arrival", {})
        lines.append(
            "| {op} | `{zone}` | {em_mean} ms | {em_min}–{em_max} ms | "
            "{ar_mean} ms | {ar_min}–{ar_max} ms | {ratio:.2%} |".format(
                op=operator,
                zone=node.get("zone", "unknown"),
                em_mean=fmt(emission.get("mean_interval_ms")),
                em_min=fmt(emission.get("minimum_interval_ms")),
                em_max=fmt(emission.get("maximum_interval_ms")),
                ar_mean=fmt(arrival.get("mean_interval_ms")),
                ar_min=fmt(arrival.get("minimum_interval_ms")),
                ar_max=fmt(arrival.get("maximum_interval_ms")),
                ratio=float(item.get("delivery_ratio_vs_local_emission", 0.0)),
            )
        )

    lines += [
        "",
        "## What this result means",
        "",
        "It is evidence that the current checked-out Nomad implementation can run its",
        "distributed key ceremony and maintain its configured fixed-size/fixed-cadence",
        "reader-side traffic over the public internet between three regions for this",
        "recorded interval. That is stronger evidence than the one-host Docker test.",
        "",
        "## What this result does **not** mean",
        "",
        "This run does **not** prove production anonymity. It does not prove independent",
        "operator governance, anonymous publication, resistance to long-horizon traffic",
        "analysis, behavior under a global passive observer, 72-hour durability, or an",
        "external security assessment. Three regions under one Scaleway/GitHub administrator",
        "remain one administrative trust domain.",
        "",
        "## Continue from here",
        "",
        "1. **Repeatability:** run the same baseline again and compare distributions.",
        "2. **Longer baseline:** extend the clean WAN capture before changing tolerances.",
        "3. **Two-world test:** run blinded idle/private-activity worlds over this same WAN",
        "   substrate and ask the classifier to distinguish them.",
        "4. **Fault campaign:** add registered loss, jitter, delay, clock and node-failure",
        "   scenarios and verify privacy fails closed rather than producing catch-up traffic.",
        "5. **72-hour soak:** only after the short campaign is boring and reproducible.",
        "6. **Independent operators:** finally move operator custody to different humans/",
        "   organizations; do not count more VPSs under this account as independence.",
        "",
        "The raw pcaps, topology/DKG public artifacts, health output, logs and hashes in this",
        "artifact remain the authoritative evidence. This Markdown file is only the readable",
        "index into them.",
        "",
    ]

    (root / "RESULT.md").write_text("\n".join(lines))
    print(root / "RESULT.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
