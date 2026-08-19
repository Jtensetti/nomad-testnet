#!/usr/bin/env python3
"""Fail closed unless a capture shows stable exact-size UDP cadence per sender."""

import collections
import re
import subprocess
import sys


LINE = re.compile(
    r"^(?P<time>\d+\.\d+)\s+IP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):\s+UDP, length (?P<size>\d+)$"
)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-pcap.py CAPTURE.pcap", file=sys.stderr)
        return 2
    result = subprocess.run(
        ["tcpdump", "-tt", "-nn", "-r", sys.argv[1], "udp", "port", "4200"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    flows: dict[str, list[float]] = collections.defaultdict(list)
    destinations: dict[str, set[str]] = collections.defaultdict(set)
    for raw in result.stdout.splitlines():
        match = LINE.match(raw.strip())
        if not match:
            continue
        if int(match.group("size")) != 1200:
            raise SystemExit(f"non-1200-byte UDP payload: {raw}")
        source = match.group("src")
        flows[source].append(float(match.group("time")))
        destinations[source].add(match.group("dst"))
    if len(flows) < 3:
        raise SystemExit(f"capture has {len(flows)} senders, want at least 3")
    evidence = {}
    for source, timestamps in sorted(flows.items()):
        if len(timestamps) < 20:
            raise SystemExit(f"sender {source} has only {len(timestamps)} cells")
        intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
        minimum = min(intervals)
        maximum = max(intervals)
        # The demo profile is 50 ms. Linux scheduling and capture timestamps
        # may jitter, but a 5 ms lower bound detects a catch-up burst.
        if minimum < 0.005:
            raise SystemExit(f"sender {source} emitted a burst: {minimum:.6f}s")
        if len(destinations[source]) != 1:
            raise SystemExit(f"sender {source} changed its signed peer plan")
        evidence[source] = {
            "cells": len(timestamps),
            "minimum_interval_ms": round(minimum * 1000, 3),
            "maximum_interval_ms": round(maximum * 1000, 3),
            "destinations": sorted(destinations[source]),
        }
    import json

    print(json.dumps({"cell_size": 1200, "senders": evidence}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
