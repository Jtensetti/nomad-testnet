#!/usr/bin/env python3
"""Fail closed unless a loaded capture shows the same cadence as a quiet one.

PROD-14 claims a resource limit does not change what a node emits. Every
measurement behind that claim was in-process. This rule judges the composed
Compose stack on a real bridge interface, across two capture windows that
differ by one thing: whether an unrecognised sender is flooding an operator's
fabric port.

Two failures this is built to avoid, both of which look like success:

  - a flood that never arrived, which makes the loaded window a second quiet
    one that matches trivially. So the flood must be visible ON THE WIRE, in
    the capture the cadence is read from -- not taken from the generator's own
    report, and not only from a counter inside the process under test.
  - a cadence comparison loose enough to accept anything. Per-sender means must
    agree within a stated tolerance, and every sender present in the quiet
    window must still be emitting in the loaded one; a comparison over whoever
    happens to be present would miss a node that fell silent.
"""

import argparse
import json
import pathlib
import sys

from capture import CaptureError, read_capture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline_evidence", help="verify-pcap.py JSON from the quiet window")
    parser.add_argument("loaded_evidence", help="verify-pcap.py JSON from the loaded window")
    parser.add_argument("loaded_capture", help="the loaded window's pcap")
    parser.add_argument("flood_source", help="source address of the load generator")
    parser.add_argument("--minimum-flood-packets", type=int, default=2000,
                        help="fewest flood datagrams the capture must show")
    parser.add_argument("--tolerance", type=float, default=0.15,
                        help="allowed fractional change in a sender's mean interval")
    arguments = parser.parse_args()

    baseline = json.loads(pathlib.Path(arguments.baseline_evidence).read_text())
    loaded = json.loads(pathlib.Path(arguments.loaded_evidence).read_text())

    # The flood, read off the wire it was supposed to be on.
    try:
        times, _, destinations, _ = read_capture(
            arguments.loaded_capture, f"udp and src host {arguments.flood_source}"
        )
    except CaptureError as error:
        raise SystemExit(f"loaded capture could not be read: {error}")
    if len(times) < arguments.minimum_flood_packets:
        raise SystemExit(
            f"the capture shows {len(times)} datagrams from {arguments.flood_source}, "
            f"want at least {arguments.minimum_flood_packets}. The load window was not "
            "loaded, so its agreement with the quiet window means nothing"
        )

    baseline_senders = baseline["senders"]
    loaded_senders = loaded["senders"]
    missing = sorted(set(baseline_senders) - set(loaded_senders))
    if missing:
        raise SystemExit(
            f"{', '.join(missing)} emitted in the quiet window and not under load; "
            "a node that goes silent under a flood is the failure this gate exists for"
        )

    comparison = {}
    findings = []
    for sender, quiet in sorted(baseline_senders.items()):
        under_load = loaded_senders[sender]
        before = quiet["mean_interval_ms"]
        after = under_load["mean_interval_ms"]
        change = (after - before) / before if before else 0.0
        comparison[sender] = {
            "quiet_mean_interval_ms": before,
            "loaded_mean_interval_ms": after,
            "fractional_change": round(change, 4),
            "quiet_cells": quiet["cells"],
            "loaded_cells": under_load["cells"],
        }
        if abs(change) > arguments.tolerance:
            findings.append(
                f"{sender} emitted every {before} ms quiet and every {after} ms under "
                f"load, a change of {change:+.1%} against a {arguments.tolerance:.0%} "
                "tolerance"
            )
        if under_load["destinations"] != quiet["destinations"]:
            findings.append(
                f"{sender} sent to {under_load['destinations']} under load and "
                f"{quiet['destinations']} quiet; load changed its signed peer plan"
            )

    print(json.dumps({
        "flood_source": arguments.flood_source,
        "flood_datagrams_on_the_wire": len(times),
        "flood_destinations": sorted(set(destinations)),
        "tolerance": arguments.tolerance,
        "senders": comparison,
    }, sort_keys=True))

    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        raise SystemExit("load changed what the fabric emitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
