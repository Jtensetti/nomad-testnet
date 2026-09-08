#!/usr/bin/env python3
"""Run the classifier-based two-world distinguisher over capture files.

    traffic-lab.py [--rounds N] WORLD_A.pcap ... -- WORLD_B.pcap ...

Exit codes match two-world-analysis.py so the campaign can treat both the same
way: 0 the classifier could not beat chance, 1 it could and that is a finding,
2 the test could not run at all and the run is broken rather than clean.

This is a second instrument, not a replacement. The preregistered rule compares
marginal distributions and this asks whether an adversary can label a trace.
Two worlds with the same inter-arrival distribution in a different order are
identical to the first question and trivially separable under the second.
"""

import json
import sys

from capture import CaptureError, read_capture
from trafficlab import distinguish


def load(paths):
    world = []
    for path in paths:
        times, sizes, _destinations, _sources = read_capture(path)
        if len(times) < 2:
            raise CaptureError(f"{path} holds fewer than two packets")
        world.append((times, sizes))
    return world


def main():
    arguments = sys.argv[1:]
    if "--" not in arguments:
        print("usage: traffic-lab.py [--rounds N] WORLD_A... -- WORLD_B...",
              file=sys.stderr)
        return 2
    # The permutation null is sampled, so rounds set the floor on the p-value
    # this run can produce. Lowering it is a way to trade resolution for time,
    # and distinguish() refuses a value too low to reach alpha rather than
    # returning a PASS the run could not have avoided.
    rounds = 200
    if "--rounds" in arguments[:arguments.index("--")]:
        at = arguments.index("--rounds")
        if at + 1 >= len(arguments):
            print("--rounds needs a value", file=sys.stderr)
            return 2
        try:
            rounds = int(arguments[at + 1])
        except ValueError:
            print(f"--rounds needs a number, not {arguments[at + 1]!r}", file=sys.stderr)
            return 2
        arguments = arguments[:at] + arguments[at + 2:]
    split = arguments.index("--")
    left, right = arguments[:split], arguments[split + 1:]
    if not left or not right:
        print("both worlds need at least one capture", file=sys.stderr)
        return 2
    try:
        world_a, world_b = load(left), load(right)
    except (CaptureError, OSError, ValueError) as error:
        print(f"the lab could not read its input: {error}", file=sys.stderr)
        return 2

    result = distinguish(world_a, world_b, rounds=rounds)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["verdict"] == "INCONCLUSIVE":
        return 2
    return 1 if result["verdict"] == "FINDING" else 0


if __name__ == "__main__":
    sys.exit(main())
