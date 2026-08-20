#!/usr/bin/env python3
"""Analyze one host-boundary Nomad pcap per WAN operator.

Each host capture contains the cells it emits and the cells that actually
arrive from its signed predecessor over the public WAN. The parser fails on
unknown packet lines, all Nomad UDP payloads must be exactly 1200 bytes, and
emission cadence retains the no-catch-up gate. Arrival cadence is reported
separately so WAN jitter is evidence rather than accidentally attributed to
the sender scheduler.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture import read_capture  # noqa: E402


def fail(message: str) -> None:
    raise SystemExit(message)


def ipv4_host(endpoint: str) -> str:
    """Extract an IPv4 host from tcpdump's address.port representation."""
    parts = endpoint.rsplit(".", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        fail(f"unexpected IPv4 endpoint in capture: {endpoint}")
    host = parts[0]
    octets = host.split(".")
    if len(octets) != 4:
        fail(f"unexpected IPv4 endpoint in capture: {endpoint}")
    try:
        values = [int(value) for value in octets]
    except ValueError:
        fail(f"unexpected IPv4 endpoint in capture: {endpoint}")
    if any(value < 0 or value > 255 for value in values):
        fail(f"invalid IPv4 endpoint in capture: {endpoint}")
    return host


def cadence(timestamps: list[float], expected: float, *, arrival: bool) -> dict[str, float | int]:
    if len(timestamps) < 20:
        fail(f"only {len(timestamps)} cells; need at least 20")
    intervals = [right - left for left, right in zip(timestamps, timestamps[1:])]
    minimum = min(intervals)
    maximum = max(intervals)
    mean = statistics.fmean(intervals)
    median = statistics.median(intervals)

    if arrival:
        # Public-WAN queues can compress and reorder arrivals. Do not turn that
        # into a false scheduler failure, but reject a path whose average rate
        # or gaps no longer resemble the signed traffic class at all.
        if maximum > expected * 20:
            fail(f"arrival cadence contains a gap of {maximum:.6f}s")
        if not expected * 0.7 <= mean <= expected * 1.3:
            fail(f"arrival mean cadence {mean:.6f}s outside broad WAN tolerance")
    else:
        # Sender-boundary evidence checks the privacy-critical scheduler rule:
        # a missed slot must never be repaid with a catch-up burst.
        if minimum < expected / 10:
            fail(f"emission catch-up/burst interval {minimum:.6f}s")
        if maximum > expected * 5:
            fail(f"emission cadence contains a gap of {maximum:.6f}s")
        if not expected * 0.8 <= mean <= expected * 1.2:
            fail(f"emission mean cadence {mean:.6f}s outside tolerance")

    return {
        "cells": len(timestamps),
        "mean_interval_ms": round(mean * 1000, 3),
        "median_interval_ms": round(median * 1000, 3),
        "minimum_interval_ms": round(minimum * 1000, 3),
        "maximum_interval_ms": round(maximum * 1000, 3),
    }


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: analyze-captures.py PCAP_DIRECTORY NODES_JSON EXPECTED_INTERVAL_MS")
    directory = Path(sys.argv[1])
    nodes_path = Path(sys.argv[2])
    if not directory.is_dir():
        fail(f"capture directory does not exist: {directory}")
    if not nodes_path.is_file():
        fail(f"nodes JSON does not exist: {nodes_path}")
    try:
        expected = float(sys.argv[3]) / 1000.0
    except ValueError:
        fail("expected interval must be numeric")
    if expected <= 0:
        fail("expected interval must be positive")

    nodes = json.loads(nodes_path.read_text())
    if not isinstance(nodes, dict) or len(nodes) != 3:
        fail("nodes JSON must contain exactly three operators")
    pcaps = sorted(directory.glob("*.pcap"))
    if len(pcaps) != 3:
        fail(f"expected exactly three operator pcaps, found {len(pcaps)}")

    evidence: dict[str, dict[str, object]] = {}
    for pcap in pcaps:
        operator = pcap.stem
        if operator not in nodes:
            fail(f"capture has no matching node entry: {operator}")
        local_ip = nodes[operator].get("ipv4")
        if not isinstance(local_ip, str):
            fail(f"node {operator} has no IPv4 address")

        try:
            times, sizes, destinations, sources = read_capture(pcap, "udp port 4200")
        except Exception as error:
            fail(f"{pcap.name}: capture could not be read in full: {error}")
        if not times:
            fail(f"{pcap.name}: no Nomad UDP cells captured")
        if any(size != 1200 for size in sizes):
            bad = sorted(set(size for size in sizes if size != 1200))
            fail(f"{pcap.name}: non-1200-byte UDP payload(s): {bad}")

        outgoing_times: list[float] = []
        incoming_times: list[float] = []
        outgoing_destinations: set[str] = set()
        incoming_sources: set[str] = set()
        for timestamp, source, destination in zip(times, sources, destinations):
            source_host = ipv4_host(source)
            destination_host = ipv4_host(destination)
            if source_host == local_ip:
                outgoing_times.append(timestamp)
                outgoing_destinations.add(destination_host)
            elif destination_host == local_ip:
                incoming_times.append(timestamp)
                incoming_sources.add(source_host)
            else:
                fail(
                    f"{pcap.name}: packet belongs to neither local ingress nor egress: "
                    f"{source} > {destination}"
                )

        if len(outgoing_destinations) != 1:
            fail(f"{pcap.name}: local sender changed destination: {sorted(outgoing_destinations)}")
        if len(incoming_sources) != 1:
            fail(f"{pcap.name}: local receiver saw unexpected senders: {sorted(incoming_sources)}")

        emission = cadence(outgoing_times, expected, arrival=False)
        arrival = cadence(incoming_times, expected, arrival=True)
        delivery_ratio = len(incoming_times) / len(outgoing_times)
        # Counts come from different ring legs, so small startup skew is normal.
        # Large divergence means the baseline path is dropping too much traffic
        # to be a useful no-fault WAN reference run.
        if delivery_ratio < 0.90 or delivery_ratio > 1.10:
            fail(f"{pcap.name}: ingress/egress cell ratio {delivery_ratio:.3f} is implausible")

        evidence[operator] = {
            "local_ipv4": local_ip,
            "emission_destination": next(iter(outgoing_destinations)),
            "arrival_source": next(iter(incoming_sources)),
            "delivery_ratio_vs_local_emission": round(delivery_ratio, 4),
            "payload_bytes": 1200,
            "emission": emission,
            "arrival": arrival,
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
