#!/usr/bin/env python3
"""Apply the preregistered two-world decision rule to a pair of captures.

The thresholds live in nomad-protocol/production/PREREGISTRATION.md v1 and
are mirrored here as constants. They are deliberately not command-line
options: a threshold that can be passed in at analysis time is a threshold
that can be chosen after seeing the answer.

Exit status is 0 only when every registered test passes. Any failure, and
any inability to evaluate a test, is a non-zero exit: a test that could not
run has not passed.
"""

import collections
import json
import math
import statistics
import sys

from capture import CaptureError, read_capture

PREREGISTRATION_VERSION = 1

# --- Preregistered thresholds. Do not edit without amending the document. ---
MAX_MEAN_INTERVAL_DRIFT_FRACTION = 0.02
KS_ALPHA = 0.01
CHI_SQUARE_ALPHA = 0.01
BURST_WINDOW_SECONDS = 1.0

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


def chi_square_destinations(left, right):
    """Chi-square over the destination distributions; returns (stat, p)."""
    keys = sorted(set(left) | set(right))
    if len(keys) < 2:
        return 0.0, 1.0
    left_counts = collections.Counter(left)
    right_counts = collections.Counter(right)
    total_left, total_right = sum(left_counts.values()), sum(right_counts.values())
    if total_left == 0 or total_right == 0:
        return 0.0, 0.0
    statistic = 0.0
    for key in keys:
        observed_left, observed_right = left_counts[key], right_counts[key]
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
    p = upper_gamma_regularized(degrees / 2.0, statistic / 2.0)
    return statistic, p


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


def main():
    if len(sys.argv) != 5:
        print("usage: two-world-analysis.py WORLD_A.pcap WORLD_B.pcap CELL_SIZE INTERVAL_MS",
              file=sys.stderr)
        return 2
    path_a, path_b = sys.argv[1], sys.argv[2]
    cell_size = int(sys.argv[3])
    interval = float(sys.argv[4]) / 1000.0

    try:
        times_a, sizes_a, destinations_a, _ = read_capture(path_a)
        times_b, sizes_b, destinations_b, _ = read_capture(path_b)
    except CaptureError as error:
        print(f"capture could not be read in full: {error}", file=sys.stderr)
        return 1

    failures = []
    report = {"preregistration_version": PREREGISTRATION_VERSION,
              "world_a": path_a, "world_b": path_b}

    report["packet_count"] = {"a": len(times_a), "b": len(times_b)}
    if not times_a or not times_b:
        failures.append("a capture contained no UDP packets, so no test could be evaluated")
    if len(times_a) != len(times_b):
        failures.append(f"packet count differs: {len(times_a)} vs {len(times_b)}")

    offenders = sorted({size for size in sizes_a + sizes_b if size != cell_size})
    report["unexpected_sizes"] = offenders
    if offenders:
        failures.append(f"packet sizes other than {cell_size}: {offenders}")

    gaps_a, gaps_b = interarrivals(times_a), interarrivals(times_b)
    if gaps_a and gaps_b:
        statistic, p = ks_two_sample(gaps_a, gaps_b)
        report["interarrival_ks"] = {"statistic": statistic, "p": p}
        if p < KS_ALPHA:
            failures.append(f"inter-arrival distributions differ (KS p={p:.4g})")
        mean_a, mean_b = statistics.fmean(gaps_a), statistics.fmean(gaps_b)
        drift = abs(mean_a - mean_b) / interval
        report["mean_interarrival"] = {"a": mean_a, "b": mean_b, "drift_fraction": drift}
        if drift > MAX_MEAN_INTERVAL_DRIFT_FRACTION:
            failures.append(f"mean inter-arrival drift {drift:.4f} exceeds "
                            f"{MAX_MEAN_INTERVAL_DRIFT_FRACTION}")
    else:
        failures.append("insufficient packets to evaluate inter-arrival tests")

    burst_a, burst_b = max_burst(times_a), max_burst(times_b)
    report["max_burst"] = {"a": burst_a, "b": burst_b}
    if burst_a != burst_b:
        failures.append(f"maximum 1s burst differs: {burst_a} vs {burst_b}")

    statistic, p = chi_square_destinations(destinations_a, destinations_b)
    report["destination_chi_square"] = {"statistic": statistic, "p": p}
    if p < CHI_SQUARE_ALPHA:
        failures.append(f"destination distributions differ (chi-square p={p:.4g})")

    report["failures"] = failures
    report["verdict"] = "PASS" if not failures else "FAIL"
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    if failures:
        print(f"\n{len(failures)} preregistered test(s) failed. A single failure is a finding.",
              file=sys.stderr)
        return 1
    print("\nAll preregistered tests passed. This bounds an attacker at this sample size; "
          "it is not proof of indistinguishability.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
