#!/usr/bin/env python3
"""Decide a three-world WAN campaign: control pair first, then the treatments.

The preregistered rule judges one pair of captures. A campaign needs more than
that, because a rejection only means something relative to what two identical
worlds do on the same host: if idle and idle already differ by the rule's
standards, the host is too noisy to say anything about idle versus active, and
reporting a rejection there would be reporting the noise floor as a leak.

So per host: reject the control pair and the host is INCONCLUSIVE, whatever the
treatments did. Control passes and a treatment is rejected, and that is a
FINDING. Everything passes and the host PASSES, at this sample size.

The rule itself is not reimplemented here. Each pair goes through
two-world-analysis.py as a subprocess, so the campaign and CI decide by the
same code and the same exit statuses.
"""

import json
import os
import subprocess
import sys

OPERATORS = ("operator-a", "operator-b", "operator-c")
ANALYSIS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "two-world-analysis.py")
# (label, world a, world b)
PAIRS = (("control", "idle1", "idle2"),
         ("treatment-1", "idle1", "active"),
         ("treatment-2", "idle2", "active"))


def analyse(results, operator, left, right, cell_size, interval_ms):
    paths = [os.path.join(results, f"{operator}-{world}.pcap") for world in (left, right)]
    for path in paths:
        if not os.path.exists(path):
            return None, f"missing capture {os.path.basename(path)}"
    finished = subprocess.run(
        [sys.executable, ANALYSIS, *paths, str(cell_size), str(interval_ms)],
        capture_output=True, text=True)
    try:
        report = json.loads(finished.stdout)
    except json.JSONDecodeError:
        return finished.returncode, (finished.stderr.strip().splitlines() or ["no output"])[0]
    return finished.returncode, report


def main():
    if len(sys.argv) != 4:
        print("usage: wan-verdict.py RESULTS_DIR CELL_SIZE INTERVAL_MS", file=sys.stderr)
        return 2
    results, cell_size, interval_ms = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])

    summary = {}
    for operator in OPERATORS:
        outcomes = {}
        for label, left, right in PAIRS:
            status, report = analyse(results, operator, left, right, cell_size, interval_ms)
            if status is None or isinstance(report, str):
                outcomes[label] = {"status": status, "error": report}
                continue
            flow = next(iter(report.get("emission_flows", {}).values()), {})
            outcomes[label] = {
                "status": status,
                "verdict": report.get("verdict"),
                "cells": flow.get("count"),
                "ks_p": flow.get("interarrival_ks", {}).get("p"),
                "drift": flow.get("mean_interarrival", {}).get("drift_fraction"),
                "emission_failures": report.get("failures", []),
                "path_failures": report.get("path_failures", []),
            }

        control = outcomes["control"]
        treatments = [outcomes[label] for label, _, _ in PAIRS if label != "control"]
        if control.get("status") not in (0, 3):
            verdict = "INCONCLUSIVE"
            because = "the control pair did not pass, so this host has no usable noise floor"
        elif any(t.get("status") == 1 for t in treatments):
            verdict = "FINDING"
            because = "the control pair passed and a treatment pair was rejected"
        elif any(t.get("status") not in (0, 3) for t in treatments):
            verdict = "INCONCLUSIVE"
            because = "a treatment pair could not be evaluated"
        else:
            verdict = "PASS"
            because = "the control pair and both treatment pairs passed"
        summary[operator] = {"verdict": verdict, "because": because, "pairs": outcomes}

    verdicts = [entry["verdict"] for entry in summary.values()]
    overall = ("FINDING" if "FINDING" in verdicts
               else "INCONCLUSIVE" if "INCONCLUSIVE" in verdicts else "PASS")
    report = {"campaign_verdict": overall, "hosts": summary}
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")

    for operator, entry in sorted(summary.items()):
        print(f"{operator}: {entry['verdict']} -- {entry['because']}", file=sys.stderr)
        for label, _, _ in PAIRS:
            outcome = entry["pairs"][label]
            ks = outcome.get("ks_p")
            cells = outcome.get("cells") or {}
            print(f"    {label:12s} exit={outcome.get('status')} "
                  f"cells={cells.get('a')}/{cells.get('b')} "
                  f"KS_p={ks if ks is None else format(ks, '.4g')}"
                  + (f" {outcome['error']}" if outcome.get("error") else ""),
                  file=sys.stderr)
    print(f"\ncampaign verdict: {overall}", file=sys.stderr)
    if overall == "FINDING":
        print("A single failing run is a finding. It is investigated and explained, "
              "not averaged away across runs.", file=sys.stderr)
        return 1
    if overall == "INCONCLUSIVE":
        return 2
    print("A pass bounds an attacker at this sample size; it is not proof of "
          "indistinguishability, and one administrator running all three hosts is "
          "not evidence of independent operation.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
