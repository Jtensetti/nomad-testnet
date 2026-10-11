#!/usr/bin/env python3
"""Check the published renderer-URL decisions against a second implementation.

PROD-16 asks for cross-platform and parser-differential evidence for the
renderer boundary. The decision corpus exists and, until this, was consumed
only by the Go tests that produced it -- a self-consistency check wearing an
interoperability claim.

This reads the same corpus with an implementation in another language that
shares no code with the first, and requires the decisions to agree case for
case. A disagreement is reported with the URL, both verdicts and the corpus's
own stated reason, because the interesting output is not "N passed" but which
URL two parsers read differently.

Usage:
    crosscheck_egress.py <url-decisions.json>
"""

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import nomadegress  # noqa: E402

CORPUS_VERSION = "nomad-browser-url-decisions-v1"


class Failure(Exception):
    pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus")
    arguments = parser.parse_args()

    corpus = json.loads(pathlib.Path(arguments.corpus).read_text())
    if corpus.get("version") != CORPUS_VERSION:
        print(f"CROSS-IMPLEMENTATION FAILURE: unrecognised corpus version "
              f"{corpus.get('version')!r}", file=sys.stderr)
        return 1

    cases = corpus.get("cases") or []
    if len(cases) < 20:
        print(f"CROSS-IMPLEMENTATION FAILURE: the corpus has {len(cases)} cases, "
              f"which is too few to establish anything", file=sys.stderr)
        return 1

    allowed = 0
    denied = 0
    disagreements = []
    for case in cases:
        url = case["url"]
        expected = bool(case["allow"])
        actual = nomadegress.allows(url)
        if actual != expected:
            reason = ""
            try:
                nomadegress.check_renderer_url(url)
            except nomadegress.Denied as failure:
                reason = str(failure)
            disagreements.append(
                f"  {url!r}\n"
                f"    corpus says {'allow' if expected else 'deny'} because "
                f"{case.get('why', '(no reason given)')}\n"
                f"    this implementation says {'allow' if actual else 'deny'}"
                + (f" because {reason}" if reason else "")
            )
        if expected:
            allowed += 1
        else:
            denied += 1

    if disagreements:
        print("CROSS-IMPLEMENTATION FAILURE: two implementations read these URLs "
              "differently:\n" + "\n".join(disagreements), file=sys.stderr)
        return 1

    # A corpus that only denied things would be satisfied by an implementation
    # that denies everything, and one that only allowed things by the reverse.
    if allowed < 3 or denied < 3:
        print(f"CROSS-IMPLEMENTATION FAILURE: the corpus has {allowed} allows and "
              f"{denied} denies; a one-sided corpus is satisfied by a one-sided "
              f"implementation", file=sys.stderr)
        return 1

    print(f"URL decisions: {len(cases)} cases agree ({allowed} allowed, "
          f"{denied} denied), checked by a second implementation in another "
          f"language sharing no code with the first")
    return 0


if __name__ == "__main__":
    sys.exit(main())
