#!/usr/bin/env python3
"""Fail closed unless a capture shows stable exact-size UDP cadence per sender."""

import collections
import json
import statistics
import sys

from capture import CaptureError, read_capture


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: verify-pcap.py CAPTURE.pcap EXPECTED_INTERVAL_MS", file=sys.stderr)
        return 2
    try:
        expected_interval = float(sys.argv[2]) / 1000.0
    except ValueError:
        raise SystemExit("expected interval must be numeric")
    if expected_interval <= 0:
        raise SystemExit("expected interval must be positive")
    try:
        times, sizes, packet_destinations, sources = read_capture(
            sys.argv[1], "udp port 4200"
        )
    except CaptureError as error:
        raise SystemExit(f"capture could not be read in full: {error}")
    flows: dict[str, list[float]] = collections.defaultdict(list)
    destinations: dict[str, set[str]] = collections.defaultdict(set)
    for time, size, destination, source in zip(times, sizes, packet_destinations, sources):
        if size != 1200:
            raise SystemExit(f"non-1200-byte UDP payload from {source}: {size}")
        flows[source].append(time)
        destinations[source].add(destination)
    if len(flows) < 3:
        raise SystemExit(f"capture has {len(flows)} senders, want at least 3")
    evidence = {}
    for source, timestamps in sorted(flows.items()):
        if len(timestamps) < 20:
            raise SystemExit(f"sender {source} has only {len(timestamps)} cells")
        intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
        minimum = min(intervals)
        maximum = max(intervals)
        mean = statistics.fmean(intervals)
        median = statistics.median(intervals)
        # Hosted runners add jitter, but a tenth-interval lower bound rejects
        # catch-up bursts and a five-interval ceiling rejects long gaps.
        if minimum < expected_interval / 10:
            raise SystemExit(f"sender {source} emitted a burst: {minimum:.6f}s")
        if maximum > expected_interval * 5:
            raise SystemExit(f"sender {source} paused for {maximum:.6f}s")
        if mean < expected_interval * 0.8 or mean > expected_interval * 1.2:
            raise SystemExit(f"sender {source} mean cadence is {mean:.6f}s")
        if len(destinations[source]) != 1:
            raise SystemExit(f"sender {source} changed its signed peer plan")
        evidence[source] = {
            "cells": len(timestamps),
            "mean_interval_ms": round(mean * 1000, 3),
            "median_interval_ms": round(median * 1000, 3),
            "minimum_interval_ms": round(minimum * 1000, 3),
            "maximum_interval_ms": round(maximum * 1000, 3),
            "destinations": sorted(destinations[source]),
        }
    print(
        json.dumps(
            {
                "cell_size": 1200,
                "expected_interval_ms": expected_interval * 1000,
                "senders": evidence,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
