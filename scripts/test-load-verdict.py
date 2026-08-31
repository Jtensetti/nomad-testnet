#!/usr/bin/env python3
"""Self-test for verify-load.py.

The load gate's verdict is the only thing standing between "the fabric held
its cadence under a flood" and "nothing was flooding and nothing changed".
Those two produce identical output from a rule that does not check, so the
rule is checked here, against captures built byte by byte rather than against
whatever a live run happened to produce.

The captures are real libpcap files, so the flood count goes through tcpdump
and the same filter expression the gate uses. A rule whose filter matched
nothing would pass every case in a text-based harness and fail closed on the
first real run, which is a slow way to find a typo.
"""

import json
import pathlib
import struct
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent
VERIFY = REPO / "verify-load.py"


def ipv4(value: str) -> bytes:
    return bytes(int(part) for part in value.split("."))


def packet(source: str, destination: str, payload_bytes: int,
           source_port: int = 4200, destination_port: int = 4200) -> bytes:
    payload = b"\x00" * payload_bytes
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    header = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0)
    ip = header + ipv4(source) + ipv4(destination) + udp
    ethernet = b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x0800)
    return ethernet + ip


def write_pcap(path: pathlib.Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for when, frame in packets:
            seconds = int(when)
            microseconds = int(round((when - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
            handle.write(frame)


def evidence(senders: dict) -> dict:
    return {"cell_size": 1200, "expected_interval_ms": 50.0, "senders": senders}


def sender(mean: float, cells: int = 100, destinations=("10.0.0.9",)) -> dict:
    return {
        "cells": cells,
        "mean_interval_ms": mean,
        "median_interval_ms": mean,
        "minimum_interval_ms": mean * 0.9,
        "maximum_interval_ms": mean * 1.1,
        "destinations": list(destinations),
    }


def run(directory: pathlib.Path, baseline: dict, loaded: dict,
        flood_packets: int, flood_source: str = "10.0.0.99") -> subprocess.CompletedProcess:
    baseline_path = directory / "baseline.json"
    loaded_path = directory / "loaded.json"
    baseline_path.write_text(json.dumps(baseline))
    loaded_path.write_text(json.dumps(loaded))

    packets = []
    when = 1000.0
    # Fabric cells from two operators, and the flood from a third address.
    for index in range(200):
        packets.append((when + index * 0.05, packet("10.0.0.1", "10.0.0.9", 1200)))
        packets.append((when + index * 0.05, packet("10.0.0.2", "10.0.0.9", 1200)))
    for index in range(flood_packets):
        packets.append((when + index * 0.0001, packet(flood_source, "10.0.0.1", 1200)))
    packets.sort(key=lambda item: item[0])
    capture = directory / "loaded.pcap"
    write_pcap(capture, packets)

    return subprocess.run(
        [sys.executable, str(VERIFY), str(baseline_path), str(loaded_path),
         str(capture), flood_source, "--minimum-flood-packets", "2000"],
        capture_output=True, text=True,
    )


def main() -> int:
    quiet = evidence({"10.0.0.1": sender(50.0), "10.0.0.2": sender(50.2)})
    failures = 0

    with tempfile.TemporaryDirectory() as raw:
        directory = pathlib.Path(raw)

        cases = [
            ("a loaded window that matches the quiet one is accepted",
             quiet, evidence({"10.0.0.1": sender(50.4), "10.0.0.2": sender(50.1)}), 3000, True, ""),
            ("a flood that never reached the wire is refused",
             quiet, evidence({"10.0.0.1": sender(50.4), "10.0.0.2": sender(50.1)}), 10, False,
             "was not loaded"),
            ("a sender that goes silent under load is refused",
             quiet, evidence({"10.0.0.1": sender(50.4)}), 3000, False, "goes silent"),
            ("a cadence that moves beyond tolerance is refused",
             quiet, evidence({"10.0.0.1": sender(75.0), "10.0.0.2": sender(50.1)}), 3000, False,
             "changed what the fabric emitted"),
            ("a changed peer plan is refused",
             quiet,
             evidence({"10.0.0.1": sender(50.4, destinations=("10.0.0.8",)),
                       "10.0.0.2": sender(50.1)}), 3000, False, "peer plan"),
        ]
        for name, baseline, loaded, flood, want_pass, want_text in cases:
            result = run(directory, baseline, loaded, flood)
            passed = result.returncode == 0
            output = result.stdout + result.stderr
            if passed != want_pass:
                print(f"FAIL {name}: exit {result.returncode}\n{output}")
                failures += 1
                continue
            if want_text and want_text not in output:
                print(f"FAIL {name}: refused for the wrong reason, "
                      f"{want_text!r} not in output\n{output}")
                failures += 1
                continue
            print(f"ok   {name}")

    if failures:
        print(f"{failures} failed")
        return 1
    print("the load verdict behaves as specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
