#!/usr/bin/env python3
"""Analyze one egress-only Nomad pcap per WAN operator.

The capture is deliberately taken on the host boundary rather than inside the
Nomad process/container. Every packet must parse, every UDP payload must be
exactly 1200 bytes, each sender must keep one signed destination, and cadence
must remain bounded without catch-up bursts.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture import CaptureError, read_capture  # noqa: E402


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> int:
    if len(sys.argv) != 3:
        fail("usage: analyze-captures.py PCAP_DIRECTORY EXPECTED_INTERVAL_MS")
    directory = Path(sys.argv[1])
    if not directory.is_dir():
        fail(f"capture directory does not exist: {directory}")
    try:
        expected = float(sys.argv[2]) / 1000.0
    except ValueError:
        fail("expected interval must be numeric")
    if expected <= 0:
        fail("expected interval must be positive")

    pcaps = sorted(directory.glob("*.pcap"))
    if len(pcaps) != 3:
        fail(f"expected exactly three operator pcaps, found {len(pcaps)}")

    evidence: dict[str, dict[str, object]] = {}
    all_sources: set[str] = set()
    for pcap in pcaps:
        try:
            times, sizes, destinations, sources = read_capture(pcap, "udp port 4200")
        except (CaptureError, Exception) as error:
            fail(f"{pcap.name}: capture could not be read in full: {error}")
        if len(times) < 20:
            fail(f"{pcap.name}: only {len(times)} cells; need at least 20")
        unique_sources = sorted(set(sources))
        if len(unique_sources) != 1:
            fail(f"{pcap.name}: egress-only capture has {len(unique_sources)} senders: {unique_sources}")
        source = unique_sources[0]
        if source in all_sources:
            fail(f"duplicate sender across captures: {source}")
        all_sources.add(source)
        if any(size != 1200 for size in sizes):
            bad = sorted(set(size for size in sizes if size != 1200))
            fail(f"{pcap.name}: non-1200-byte UDP payload(s): {bad}")
        unique_destinations = sorted(set(destinations))
        if len(unique_destinations) != 1:
            fail(f"{pcap.name}: sender changed destination: {unique_destinations}")

        intervals = [right - left for left, right in zip(times, times[1:])]
        minimum = min(intervals)
        maximum = max(intervals)
        mean = statistics.fmean(intervals)
        median = statistics.median(intervals)
        # These are intentionally the same broad hosted-environment bounds as
        # the existing Compose verifier. Long-horizon campaigns preregister
        # tighter distributions rather than silently weakening this gate.
        if minimum < expected / 10:
            fail(f"{pcap.name}: catch-up/burst interval {minimum:.6f}s")
        if maximum > expected * 5:
            fail(f"{pcap.name}: long cadence gap {maximum:.6f}s")
        if not expected * 0.8 <= mean <= expected * 1.2:
            fail(f"{pcap.name}: mean cadence {mean:.6f}s outside tolerance")

        evidence[pcap.stem] = {
            "source": source,
            "destination": unique_destinations[0],
            "cells": len(times),
            "mean_interval_ms": round(mean * 1000, 3),
            "median_interval_ms": round(median * 1000, 3),
            "minimum_interval_ms": round(minimum * 1000, 3),
            "maximum_interval_ms": round(maximum * 1000, 3),
            "payload_bytes": 1200,
        }

    print(
        json.dumps(
            {
                "profile": "single-admin-three-region-scaleway-wan",
                "production_independence": False,
                "expected_interval_ms": expected * 1000,
                "operators": evidence,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
