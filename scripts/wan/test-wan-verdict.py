#!/usr/bin/env python3
"""Self-tests for the three-world campaign verdict.

The verdict decides what a campaign concluded, so the ways it can be wrong are
the ways a campaign can be misreported: calling a noisy host a leak, calling a
leak a noisy host, or reporting either when a capture is missing.
"""

import pathlib
import subprocess
import sys
import tempfile

VERDICT = str(pathlib.Path(__file__).with_name("wan-verdict.py"))
OPERATORS = ("operator-a", "operator-b", "operator-c")
failures = []


def check(name, condition):
    print(f"{'ok  ' if condition else 'FAIL'} {name}")
    if not condition:
        failures.append(name)


def write_capture(path, jitter=0.0, cells=400):
    """A one-directional fixed-cadence capture, in tcpdump's rendered form."""
    lines = ["reading from file capture.pcap, link-type EN10MB (Ethernet)"]
    for index in range(cells):
        stamp = 1712345678.0 + 0.05 * index + (jitter if index % 2 else 0.0)
        lines.append(f"{stamp:.6f} IP 10.0.0.2.4200 > 10.0.0.3.4200: UDP, length 1200")
    path.write_text("\n".join(lines) + "\n")


def campaign(root, worlds, skip=()):
    """Lay out one results directory: worlds maps world name to jitter."""
    for operator in OPERATORS:
        for world, jitter in worlds.items():
            if (operator, world) in skip:
                continue
            write_capture(root / f"{operator}-{world}.pcap", jitter=jitter)
    return subprocess.run([sys.executable, VERDICT, str(root), "1200", "50"],
                          capture_output=True, text=True)


with tempfile.TemporaryDirectory() as workspace:
    root = pathlib.Path(workspace)

    quiet = campaign(root, {"idle1": 0.0, "idle2": 0.0, "active": 0.0})
    check("three identical worlds pass", quiet.returncode == 0)
    check("a passing campaign says so", '"campaign_verdict": "PASS"' in quiet.stdout)
    check("a pass is not reported as proof",
          "not proof of indistinguishability" in quiet.stderr)

    # The active world differs from two identical idle worlds. Control passes,
    # both treatments are rejected: that is what a finding looks like.
    leak = campaign(root, {"idle1": 0.0, "idle2": 0.0, "active": 0.004})
    check("a leak against a clean control is a finding", leak.returncode == 1)
    check("a finding says so", '"campaign_verdict": "FINDING"' in leak.stdout)
    check("a finding is not averaged away",
          "not averaged away" in leak.stderr)

    # One idle world differs from the other. The host has no usable noise
    # floor, so nothing can be concluded there -- reporting the rejected
    # treatment pair as a leak would be reporting the noise floor as one.
    noisy = campaign(root, {"idle1": 0.0, "idle2": 0.004, "active": 0.0})
    check("a rejected control is inconclusive, not a finding", noisy.returncode == 2)
    check("an inconclusive campaign says so",
          '"campaign_verdict": "INCONCLUSIVE"' in noisy.stdout)
    check("an inconclusive host names its control as the reason",
          "no usable noise floor" in noisy.stderr)

    # A campaign missing a capture has not passed.
    for path in root.glob("*.pcap"):
        path.unlink()
    missing = campaign(root, {"idle1": 0.0, "idle2": 0.0, "active": 0.0},
                       skip={("operator-b", "active")})
    check("a missing capture is not a pass", missing.returncode != 0)
    check("a missing capture is inconclusive", missing.returncode == 2)

    # Too little data is not a pass either.
    for path in root.glob("*.pcap"):
        path.unlink()
    for operator in OPERATORS:
        for world in ("idle1", "idle2", "active"):
            write_capture(root / f"{operator}-{world}.pcap", cells=8)
    short = subprocess.run([sys.executable, VERDICT, str(root), "1200", "50"],
                           capture_output=True, text=True)
    check("too few cells is inconclusive", short.returncode == 2)

print()
if failures:
    print(f"{len(failures)} self-test(s) failed")
    raise SystemExit(1)
print("all campaign verdict self-tests passed")
