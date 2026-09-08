#!/usr/bin/env python3
"""Apply the preregistered two-world decision rule to a pair of captures.

The thresholds live in nomad-protocol/production/PREREGISTRATION.md and are
mirrored here as constants. They are deliberately not command-line options: a
threshold that can be passed in at analysis time is a threshold that can be
chosen after seeing the answer.

The registration extracts features "per capture, per direction, per peer".
That is what a flow key of (source, destination) is, and the tests below run
per flow. Pooling every packet in a capture into one series instead -- which
this script did until 2026-08-21 -- compares a host's own emissions merged
with its peers' independently-phased ones, so restarting the node between
worlds re-randomises the relative phase and the merged distribution shifts on
its own. That reports a large difference whatever the node does, and it does
so in the direction of a false alarm rather than a false pass.

Exit status: 0 when every registered test passes, 1 when the rule ran and
found a difference, 2 when the rule could not run at all. Those last two are
kept apart deliberately -- a crash reported as a rejection is a crash
recorded as a verdict, and a caller cannot tell the difference from the exit
status alone.
"""

import collections
import json
import math
import statistics
import sys

from capture import CaptureError, read_capture

PREREGISTRATION_VERSION = 2

# --- Preregistered thresholds. Do not edit without amending the document. ---
MAX_MEAN_INTERVAL_DRIFT_FRACTION = 0.02
KS_ALPHA = 0.01
CHI_SQUARE_ALPHA = 0.01
BURST_WINDOW_SECONDS = 1.0
MIN_PACKETS_PER_FLOW = 20


def interarrivals(times):
    ordered = sorted(times)
    return [b - a for a, b in zip(ordered, ordered[1:])]


def kolmogorov_survival(lam):
    """Q(lam), the asymptotic Kolmogorov distribution survival function.

    The alternating series only converges for lam bounded away from zero. At
    lam = 0 -- which is exactly what two identical samples produce, and the
    expected shape for two honest fixed-cadence captures -- truncating it
    yields 1-1+1-1..., i.e. 0 for an even term count. Reporting p=0 for
    identical inputs would turn this harness into a permanent false alarm, so
    the sum is accumulated with an explicit convergence test and a
    non-converging sum returns 1.0 (no evidence of a difference).
    """
    if lam <= 0.0:
        return 1.0
    term_scale = 2.0
    total = 0.0
    previous = 0.0
    exponent = -2.0 * lam * lam
    for k in range(1, 101):
        term = term_scale * math.exp(exponent * k * k)
        total += term
        if abs(term) <= 1e-6 * previous or abs(term) <= 1e-16 * abs(total):
            return max(0.0, min(1.0, total))
        term_scale = -term_scale
        previous = abs(term)
    return 1.0


def ks_two_sample(left, right):
    """Two-sample Kolmogorov-Smirnov statistic and asymptotic p-value."""
    if not left or not right:
        return 1.0, 0.0
    left, right = sorted(left), sorted(right)
    n, m = len(left), len(right)
    i = j = 0
    statistic = 0.0
    # Both empirical CDFs must be advanced past every observation equal to the
    # current value before the gap between them is measured. Inter-arrivals
    # from a fixed-cadence capture are heavily tied -- a 50 ms cadence yields a
    # handful of distinct float gaps across thousands of packets -- and a
    # per-observation walk would charge every tie run as a gap, reporting a
    # large statistic for a sample against itself.
    while i < n and j < m:
        value = left[i] if left[i] < right[j] else right[j]
        while i < n and left[i] == value:
            i += 1
        while j < m and right[j] == value:
            j += 1
        statistic = max(statistic, abs(i / n - j / m))
    if statistic <= 0.0:
        return 0.0, 1.0
    effective = math.sqrt(n * m / (n + m))
    lam = (effective + 0.12 + 0.11 / effective) * statistic
    return statistic, kolmogorov_survival(lam)


def chi_square_counts(left_counts, right_counts):
    """Chi-square over two labelled count distributions; returns (stat, p)."""
    keys = sorted(set(left_counts) | set(right_counts))
    if len(keys) < 2:
        return 0.0, 1.0
    total_left = sum(left_counts.values())
    total_right = sum(right_counts.values())
    if total_left == 0 or total_right == 0:
        return 0.0, 0.0
    statistic = 0.0
    for key in keys:
        observed_left, observed_right = left_counts.get(key, 0), right_counts.get(key, 0)
        combined = observed_left + observed_right
        expected_left = combined * total_left / (total_left + total_right)
        expected_right = combined * total_right / (total_left + total_right)
        if expected_left > 0:
            statistic += (observed_left - expected_left) ** 2 / expected_left
        if expected_right > 0:
            statistic += (observed_right - expected_right) ** 2 / expected_right
    degrees = len(keys) - 1
    # Survival function of chi-square via the regularized upper incomplete
    # gamma, adequate for the small degree counts used here.
    return statistic, upper_gamma_regularized(degrees / 2.0, statistic / 2.0)


def upper_gamma_regularized(shape, value):
    if value <= 0:
        return 1.0
    if value < shape + 1.0:
        # Series expansion for the lower regularized gamma.
        term = 1.0 / shape
        total = term
        for index in range(1, 200):
            term *= value / (shape + index)
            total += term
            if abs(term) < abs(total) * 1e-12:
                break
        return max(0.0, 1.0 - total * math.exp(-value + shape * math.log(value) - math.lgamma(shape)))
    # Continued fraction for the upper regularized gamma.
    tiny = 1e-300
    b = value + 1.0 - shape
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for index in range(1, 200):
        an = -index * (index - shape)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return max(0.0, min(1.0, math.exp(-value + shape * math.log(value) - math.lgamma(shape)) * h))


def max_burst(times, window=BURST_WINDOW_SECONDS):
    ordered = sorted(times)
    best = 0
    start = 0
    for end in range(len(ordered)):
        while ordered[end] - ordered[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def flows_of(packets):
    """Group a capture into (source, destination) flows: direction and peer."""
    times, sizes, destinations, sources = packets
    grouped = collections.defaultdict(list)
    for time, destination, source in zip(times, destinations, sources):
        grouped[(source, destination)].append(time)
    return {key: sorted(values) for key, values in grouped.items()}


def equal_windows(left, right, interval):
    """Trim two flows to equal-length windows anchored at each one's first cell.

    The registered count test compares packet counts "for equal-length
    windows". A capture starts before the node and stops after it, so the raw
    files cover slightly different spans and differ by a handful of cells for
    reasons that have nothing to do with the world. The window is an integer
    number of nominal cell intervals so that an honest fixed-cadence sender
    emits exactly the same number of cells in both, and it is anchored at a
    real cell so no boundary lands within jitter of an expected emission.
    """
    if not left or not right:
        return [], [], 0.0
    span = min(left[-1] - left[0], right[-1] - right[0])
    periods = int(span / interval)
    if periods < 1:
        return [], [], 0.0
    width = periods * interval
    # Each window opens half an interval before its first cell. A boundary
    # placed on a cell decides by jitter whether that cell is inside, so two
    # honest worlds differ by one and the count test reports a leak that is
    # really the ruler's edge. Half an interval is the furthest any boundary
    # can sit from an expected emission, so gaining or losing a cell now takes
    # jitter of half an interval, which the inter-arrival tests reject on
    # their own.
    start_left, start_right = left[0] - interval / 2, right[0] - interval / 2
    trimmed_left = [t for t in left if start_left <= t < start_left + width]
    trimmed_right = [t for t in right if start_right <= t < start_right + width]
    return trimmed_left, trimmed_right, width


def measured_host(flows_a, flows_b):
    """Infer which address the capture was taken at, if it was taken at one.

    A participating host sees its own emissions leave and its peers' arrive,
    so its address is the one appearing as both a source and a destination; a
    pure upstream peer only ever appears as a source and a pure downstream peer
    only as a destination.

    An empty result is not a failure. It means no address does both, which is
    what a capture taken at an observation point rather than at a participant
    looks like -- every flow in it is some sender's emission, and all of them
    carry the verdict. More than one candidate is a real ambiguity: the caller
    must say, because guessing would silently decide which flows the verdict
    rests on, and guessing wrong would file a leak under the path.
    """
    candidates = set()
    for flows in (flows_a, flows_b):
        sources = {source for source, _ in flows}
        destinations = {destination for _, destination in flows}
        candidates |= sources & destinations
    return candidates


def main():
    if len(sys.argv) not in (5, 6):
        print("usage: two-world-analysis.py WORLD_A.pcap WORLD_B.pcap CELL_SIZE INTERVAL_MS "
              "[MEASURED_HOST]", file=sys.stderr)
        return 2
    path_a, path_b = sys.argv[1], sys.argv[2]
    cell_size = int(sys.argv[3])
    interval = float(sys.argv[4]) / 1000.0
    declared_host = sys.argv[5] if len(sys.argv) == 6 else None

    try:
        capture_a = read_capture(path_a)
        capture_b = read_capture(path_b)
    except CaptureError as error:
        # Exit 2, not 1. A rejection means the rule ran and found a
        # difference; this means the rule never ran, and reporting the two the
        # same way is how a crash gets recorded as a verdict.
        print(f"capture could not be read in full: {error}", file=sys.stderr)
        return 2

    failures = []
    path_failures = []
    report = {"preregistration_version": PREREGISTRATION_VERSION,
              "world_a": path_a, "world_b": path_b}

    sizes_a, sizes_b = capture_a[1], capture_b[1]
    report["packet_count"] = {"a": len(capture_a[0]), "b": len(capture_b[0])}
    offenders = sorted({size for size in sizes_a + sizes_b if size != cell_size})
    report["unexpected_sizes"] = offenders
    if offenders:
        failures.append(f"packet sizes other than {cell_size}: {offenders}")

    flows_a, flows_b = flows_of(capture_a), flows_of(capture_b)
    if not flows_a or not flows_b:
        print("a capture contained no UDP packets, so no test could be evaluated",
              file=sys.stderr)
        return 2

    host = declared_host
    if host is None:
        candidates = measured_host(flows_a, flows_b)
        if len(candidates) > 1:
            print(f"cannot tell which host this capture was taken at "
                  f"(candidates: {sorted(candidates)}); pass it explicitly",
                  file=sys.stderr)
            return 2
        host = candidates.pop() if candidates else None
    report["measured_host"] = host
    report["vantage"] = "participant" if host else "observation point"

    # Flows the measured host emits, and flows it merely receives. The claim
    # under test is that private activity does not modulate the events this
    # node creates, so the verdict rests on the flows it sources. A received
    # count is a function of the sender and of the path between them, and
    # charging a lossy hour on someone else's backbone to this node's
    # scheduler would be a category error -- so those flows are tested too,
    # reported in full, and returned under their own non-zero exit status
    # rather than folded into this node's verdict or quietly dropped.
    shared = set(flows_a) & set(flows_b)
    if host is None:
        emission_keys, path_keys = sorted(shared), []
    else:
        emission_keys = sorted(key for key in shared if key[0] == host)
        path_keys = sorted(key for key in shared if key[0] != host)
    if not emission_keys:
        print(f"no flow common to both worlds is sourced at {host}; nothing to judge",
              file=sys.stderr)
        return 2

    # A flow that exists in one world and not the other is the strongest form
    # of the difference this experiment looks for, so it is named before any
    # statistic is computed on the flows they share.
    only_a = sorted(f"{s} > {d}" for s, d in set(flows_a) - set(flows_b))
    only_b = sorted(f"{s} > {d}" for s, d in set(flows_b) - set(flows_a))
    report["flows_only_in_a"], report["flows_only_in_b"] = only_a, only_b
    for name in only_a:
        sink = failures if host is None or name.startswith(host) else path_failures
        sink.append(f"flow present only in world A: {name}")
    for name in only_b:
        sink = failures if host is None or name.startswith(host) else path_failures
        sink.append(f"flow present only in world B: {name}")

    def evaluate(keys, sink, label, inconclusive):
        results = {}
        for key in keys:
            name = f"{key[0]} > {key[1]}"
            left, right, width = equal_windows(flows_a[key], flows_b[key], interval)
            entry = {"window_seconds": width, "count": {"a": len(left), "b": len(right)}}
            results[name] = entry
            if width <= 0.0 or min(len(left), len(right)) < MIN_PACKETS_PER_FLOW:
                # Not a difference: the rule had too little to run on. Recorded
                # apart from the findings for the same reason exit 2 exists at
                # all -- a comparison that could not be made is not a
                # comparison that rejected.
                inconclusive.append(f"{name}: too few cells to evaluate "
                                    f"({len(left)} vs {len(right)}, "
                                    f"minimum {MIN_PACKETS_PER_FLOW})")
                continue
            if len(left) != len(right):
                sink.append(f"{name}: packet count differs over a "
                            f"{width:.3f}s window: {len(left)} vs {len(right)}")

            gaps_left, gaps_right = interarrivals(left), interarrivals(right)
            statistic, p = ks_two_sample(gaps_left, gaps_right)
            entry["interarrival_ks"] = {"statistic": statistic, "p": p}
            if p < KS_ALPHA:
                sink.append(f"{name}: inter-arrival distributions differ (KS p={p:.4g})")

            mean_left, mean_right = statistics.fmean(gaps_left), statistics.fmean(gaps_right)
            drift = abs(mean_left - mean_right) / interval
            entry["mean_interarrival"] = {"a": mean_left, "b": mean_right,
                                          "drift_fraction": drift}
            if drift > MAX_MEAN_INTERVAL_DRIFT_FRACTION:
                sink.append(f"{name}: mean inter-arrival drift {drift:.4f} exceeds "
                            f"{MAX_MEAN_INTERVAL_DRIFT_FRACTION}")

            burst_left, burst_right = max_burst(left), max_burst(right)
            entry["max_burst"] = {"a": burst_left, "b": burst_right}
            if burst_left != burst_right:
                sink.append(f"{name}: maximum 1s burst differs: "
                            f"{burst_left} vs {burst_right}")
        report[label] = results

    inconclusive = []
    evaluate(emission_keys, failures, "emission_flows", inconclusive)
    evaluate(path_keys, path_failures, "path_flows", inconclusive)
    report["inconclusive"] = inconclusive

    # Destination sequence per sender: which peer slots a source used and in
    # what proportion. Pooling senders here would let one sender's shift hide
    # behind another's steadiness.
    report["destination_chi_square"] = {}
    for source in sorted({key[0] for key in emission_keys}):
        left_counts = {d: len(t) for (s, d), t in flows_a.items() if s == source}
        right_counts = {d: len(t) for (s, d), t in flows_b.items() if s == source}
        statistic, p = chi_square_counts(left_counts, right_counts)
        report["destination_chi_square"][source] = {"statistic": statistic, "p": p}
        if p < CHI_SQUARE_ALPHA:
            failures.append(f"{source}: destination distributions differ "
                            f"(chi-square p={p:.4g})")

    report["failures"] = failures
    report["path_failures"] = path_failures
    report["verdict"] = ("FAIL" if failures
                         else "INCONCLUSIVE" if inconclusive else "PASS")
    report["path_verdict"] = "PASS" if not path_failures else "FAIL"
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    if failures:
        emitter = f"traffic {host} emits" if host else "emitted traffic"
        print(f"\n{len(failures)} preregistered test(s) failed on {emitter}. "
              f"A single failure is a finding.", file=sys.stderr)
        return 1
    if inconclusive:
        # A finding outranks this, because a rejection stands whatever else
        # was short of data. With no finding, too little data is exit 2: the
        # rule did not run on those flows, and reporting that as a pass would
        # turn an empty capture into evidence of indistinguishability.
        for line in inconclusive:
            print(f"  {line}", file=sys.stderr)
        print(f"\n{len(inconclusive)} flow(s) had too few cells for the rule to run.",
              file=sys.stderr)
        return 2
    if path_failures:
        print(f"\n{len(path_failures)} preregistered test(s) failed on traffic {host} "
              f"receives. That is a finding about the sender or the path between them, "
              f"not about this node's scheduler: check it against the sender's own "
              f"capture of the same link before attributing it.", file=sys.stderr)
        return 3
    print("\nAll preregistered tests passed. This bounds an attacker at this sample size; "
          "it is not proof of indistinguishability.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
