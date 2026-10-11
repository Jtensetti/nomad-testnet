#!/usr/bin/env python3
"""Self-tests for the classifier-based two-world distinguisher.

The reason this file exists is the same reason test-two-world-analysis.py
exists, only sharper. The traffic lab's job is to *fail* a defence, so every
way it can quietly stop failing things is a way it turns into a rubber stamp:
a feature extractor that loses the order features, a classifier that stops
converging, a permutation null with too few rounds, a world too small to
reject. Each of those returns PASS, and PASS is the answer everybody wants.

So the checks below are two-sided. The control worlds must pass, and the
fixture the lab was built for -- two worlds with *provably identical*
inter-arrival distributions that differ only in the order of those
inter-arrivals -- must produce a finding, while the preregistered marginal
rule on the same bytes reports nothing at all. If that pair ever stops
separating, the lab has gone blind and this test says so.

This takes a few minutes. Every verdict below is an exact permutation test
over all 252 labelings rather than a sampled one, which is what makes the
results facts about the fixtures instead of facts about a seed; the cost is
252 cross-validations per verdict. That is the right trade for a gate.
"""

import importlib.util
import math
import pathlib
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))

spec = importlib.util.spec_from_file_location(
    "twa", pathlib.Path(__file__).with_name("two-world-analysis.py")
)
twa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(twa)

import trafficlab

failures = []


def check(name, condition):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}")
        failures.append(name)


# --------------------------------------------------------------------------
# Fixtures.
#
# Gaps are whole multiples of 1/1024 of a second. That is not decoration: a
# cumulative sum of dyadic rationals is exact in binary floating point, and so
# is the subtraction that recovers the gaps. Decimal gaps drift by an ulp or
# two, and the whole point of the headline fixture is that the two worlds have
# gap multisets that are equal *exactly* -- a drifting fixture would make the
# marginal test report a difference and the demonstration would be worthless.
TICK = 1.0 / 1024.0
MULTISET = [count * TICK for count in [8, 12, 17, 23, 30, 38, 47, 57] * 8]


def trace(gaps):
    times, now = [0.0], 0.0
    for gap in gaps:
        now += gap
        times.append(now)
    return times, [1200] * len(times)


def ordered_world(size):
    """Gaps in sorted order, rotated per trace: strongly autocorrelated."""
    base = sorted(MULTISET)
    return [trace(base[at:] + base[:at]) for at in range(size)]


def shuffled_world(size, seed):
    """The same gaps in a random order: autocorrelation near zero."""
    world = []
    for index in range(size):
        gaps = MULTISET[:]
        random.Random(seed + index).shuffle(gaps)
        world.append(trace(gaps))
    return world


def gap_multiset(world):
    pooled = []
    for times, _sizes in world:
        pooled.extend(twa.interarrivals(times))
    return sorted(pooled)


# Five per world is the smallest that can reject at all: C(10,5) = 252
# labelings, of which the true one and its complement always tie, so the floor
# is 2/252 = 0.0079. Four per world gives 2/70 = 0.0286 and cannot reach alpha
# however separable the worlds are. 252 is inside ENUMERATION_LIMIT, so every
# verdict below is an exact permutation test with no seed in it.
TRACES = 5

ORDERED = ordered_world(TRACES)
SHUFFLED = shuffled_world(TRACES, 1000)
CONTROL_A = shuffled_world(TRACES, 2000)
CONTROL_B = shuffled_world(TRACES, 3000)

# --------------------------------------------------------------------------
# The fixture has to be what it claims before any verdict on it means
# anything. A pair that merely looks similar would let the headline check pass
# for the ordinary reason -- the worlds differ -- rather than for the reason
# being demonstrated.
check("the two worlds have exactly equal gap multisets",
      gap_multiset(ORDERED) == gap_multiset(SHUFFLED))
check("...and equal packet counts and durations",
      [len(t) for t, _ in ORDERED] == [len(t) for t, _ in SHUFFLED]
      and [round(t[-1], 9) for t, _ in ORDERED] == [round(t[-1], 9) for t, _ in SHUFFLED])
check("...but different orderings",
      [t for t, _ in ORDERED] != [t for t, _ in SHUFFLED])

_, marginal_p = twa.ks_two_sample(gap_multiset(ORDERED), gap_multiset(SHUFFLED))
check("the preregistered marginal rule sees nothing in that pair",
      marginal_p > twa.KS_ALPHA)
check("...and sees nothing because the samples are identical, not by luck",
      marginal_p == 1.0)

# --------------------------------------------------------------------------
# Unit checks on the features that make the difference.
_scrambled = MULTISET[:]
random.Random(4242).shuffle(_scrambled)
check("autocorrelation is sensitive to order",
      abs(trafficlab.autocorrelation(sorted(MULTISET), 1)
          - trafficlab.autocorrelation(_scrambled, 1)) > 0.5)
# Regression. A stream of identical gaps is what a fixed-cadence fabric emits,
# and its computed variance is around 1e-33 rather than 0, so a guard written
# against zero does not fire. This returned 0.95 -- a strong order signal
# invented out of floating-point residue, on the honest case.
check("a constant series has no autocorrelation to report",
      trafficlab.autocorrelation([0.05] * 20, 1) == 0.0)
check("...while a real periodic pattern in the same range still shows one",
      abs(trafficlab.autocorrelation([0.05, 0.06] * 10, 1)) > 0.5)
check("autocorrelation of a series shorter than the lag is defined",
      trafficlab.autocorrelation([0.05, 0.06], 4) == 0.0)

check("quantile at the ends returns the ends",
      trafficlab.quantile([1.0, 2.0, 3.0, 4.0], 0.0) == 1.0
      and trafficlab.quantile([1.0, 2.0, 3.0, 4.0], 1.0) == 4.0)
check("quantile interpolates", trafficlab.quantile([0.0, 10.0], 0.5) == 5.0)
check("quantile of an empty sample is not an exception", trafficlab.quantile([], 0.9) == 0.0)

check("bursts counts runs below the threshold",
      trafficlab.bursts([0.1, 0.01, 0.01, 0.1, 0.01], 0.05) == [2, 1])
check("bursts closes a run that reaches the end",
      trafficlab.bursts([0.1, 0.01, 0.01], 0.05) == [2])
check("bursts finds nothing in a steady stream",
      trafficlab.bursts([0.05] * 10, 0.05) == [])

try:
    trafficlab.features([1.0], [1200])
    check("a one-packet trace is refused", False)
except ValueError:
    check("a one-packet trace is refused", True)

check("the feature vector is the length the names claim",
      len(trafficlab.features(*ORDERED[0])) == len(trafficlab.FEATURE_NAMES))

# Standardisation must survive a feature that is constant across the whole set
# -- mean_size is exactly that in a fixed-cell fabric, so a zero-variance
# column is the normal case here and not an edge case.
constant = trafficlab.standardise([[1.0, 5.0], [2.0, 5.0]])
check("a zero-variance feature standardises to zero rather than to a NaN",
      constant[0][1] == 0.0 and constant[1][1] == 0.0)

# --------------------------------------------------------------------------
# The power guard. Both ceilings on the p-value have to fail closed, because
# both of them produce a PASS that says nothing about the traffic.
# These fire before any classification, so they cost nothing and can use
# placeholder traces.
STUB = ([0.0, 0.05], [1200, 1200])

too_few = trafficlab.distinguish([STUB] * 4, [STUB] * 4)
check("four traces per world is inconclusive, not a pass",
      too_few["verdict"] == "INCONCLUSIVE")
check("...and the reason names the labelings ceiling and the number needed",
      "labelings" in too_few["reason"] and "5 traces per world" in too_few["reason"])
check("...and the ceiling counts the complement labeling, which always ties",
      abs(too_few["smallest_attainable_p"] - 2 / math.comb(8, 4)) < 1e-12)

# Past the enumeration limit the null is sampled, and then the number of
# rounds is a second ceiling on the p-value with nothing to do with the traffic.
too_coarse = trafficlab.distinguish([STUB] * 7, [STUB] * 7, rounds=50)
check("fifty permutation rounds is inconclusive, not a pass",
      too_coarse["verdict"] == "INCONCLUSIVE")
check("...and the reason names the rounds ceiling and the number needed",
      "rounds" in too_coarse["reason"] and "100 rounds" in too_coarse["reason"])
check("...and the guard costs nothing to reach: it precedes the classifier",
      "accuracy" not in too_coarse)


# --------------------------------------------------------------------------
# The headline. This is the claim the lab is for.
finding = trafficlab.distinguish(ORDERED, SHUFFLED)
check("the classifier separates worlds the marginal rule cannot",
      finding["verdict"] == "FINDING")
check("...decisively", finding["accuracy"] == 1.0 and finding["p_value"] < 0.01)
check("...and the null it is measured against is not trivially low",
      finding["null_max"] > finding["null_mean"])
# At this size the null is enumerated rather than sampled, which is what makes
# the verdict a fact about the traffic instead of a fact about the seed. With
# the sampled null this same fixture -- separated perfectly, exact p 0.0079 --
# came back FINDING for two seeds out of eight and PASS for the other six.
check("...from every labeling, not a sample of them", finding["null"] == "exhaustive")
check("...so no seed took part in it", "seed" not in finding)
check("a perfect separation lands exactly on the attainable floor",
      finding["p_value"] == finding["smallest_attainable_p"])

# The floor is 2/L rather than 1/L because flipping every label makes this
# classifier learn the negated rule and score identically. If that ever stops
# being true the guard is miscalibrated, in the direction of claiming power it
# does not have.
_vectors = trafficlab.standardise(
    [trafficlab.features(*t) for t in ORDERED + SHUFFLED])
_labels = [0] * TRACES + [1] * TRACES
check("the complement labeling ties with the truth",
      trafficlab.leave_one_out_accuracy(_vectors, _labels)
      == trafficlab.leave_one_out_accuracy(_vectors, [1 - l for l in _labels]))

# The order features have to be load-bearing, not decoration. The headline
# fixture above separates on burst structure as well, so blinding
# autocorrelation entirely leaves it separating at accuracy 1.0 -- which means
# the three gap_autocorr features could be deleted without any check noticing.
#
# This pair isolates them. The positions of the short gaps are identical in
# both worlds, so burst structure is identical; the long and medium gaps are
# blocked in one world and alternating in the other, so every marginal is
# identical too. Every feature but gap_autocorr_1/2/4 is the same number on
# both sides, and the classifier still has to reach a verdict.
GRAIN = 1.0 / 1024.0
GAP_SIZES = {"t": 4 * GRAIN, "d": 40 * GRAIN, "L": 80 * GRAIN}


def from_pattern(pattern):
    return trace([GAP_SIZES[symbol] for symbol in pattern])


def rotations(unit, count):
    cell = ("tt" + unit) * 6
    return [from_pattern(cell[at:] + cell[:at]) for at in range(count)]


BLOCKED = rotations("ddddLLLL", TRACES)
ALTERNATING = rotations("dLdLdLdL", TRACES)
blocked_features = [trafficlab.features(*t) for t in BLOCKED]
alternating_features = [trafficlab.features(*t) for t in ALTERNATING]
order_only = [index for index, name in enumerate(trafficlab.FEATURE_NAMES)
              if name.startswith("gap_autocorr_")]
check("the order-only pair differs in nothing but the autocorrelations",
      all({vector[index] for vector in blocked_features}
          == {vector[index] for vector in alternating_features}
          for index in range(len(trafficlab.FEATURE_NAMES))
          if index not in order_only))
check("...and does differ in those",
      all({vector[index] for vector in blocked_features}
          != {vector[index] for vector in alternating_features}
          for index in order_only))
order = trafficlab.distinguish(BLOCKED, ALTERNATING)
check("gap ordering alone is enough to separate two worlds",
      order["verdict"] == "FINDING" and order["accuracy"] == 1.0)
_, order_marginal = twa.ks_two_sample(gap_multiset(BLOCKED), gap_multiset(ALTERNATING))
check("...and the marginal rule sees nothing there either", order_marginal == 1.0)

# The control. Same generator, different seeds: nothing to find, and the
# classifier must say so. A lab that reports a finding here is unusable, and
# it is the easy failure mode -- ten traces and seventeen features will fit
# noise perfectly if the null is not doing its job.
control = trafficlab.distinguish(CONTROL_A, CONTROL_B)
check("two draws from one process do not separate", control["verdict"] == "PASS")
check("...and the null explains why: shuffled labels reach the same accuracy",
      control["null_max"] >= control["accuracy"])

# Restart behaviour: the invariant names restart explicitly, and a node that
# emits a catch-up burst after coming back has the same gap *values* as one
# that does not if the burst is built from gaps already in the multiset. Here
# the burst is put at a fixed position, so the marginals move very little and
# the order moves a lot -- the shape of a real restart signature.
restarted = []
for index in range(TRACES):
    gaps = MULTISET[:]
    random.Random(2000 + index).shuffle(gaps)
    small = sorted(gaps)[:12]
    rest = sorted(gaps)[12:]
    random.Random(9000 + index).shuffle(rest)
    restarted.append(trace(small + rest))
restart = trafficlab.distinguish(CONTROL_A, restarted)
check("a restart catch-up burst is a finding", restart["verdict"] == "FINDING")

# --------------------------------------------------------------------------
# An honest fixed-cadence fabric must not separate from itself. This is the
# case Nomad actually emits, so a false finding here is not a curiosity: it
# would send someone hunting a leak in traffic that has none.
#
# Regression, and the reason RESOLUTION exists. Every gap below is nominally
# 0.05 s with no jitter whatsoever, and this classifier separated the two
# worlds at accuracy 1.0 -- reading the floating-point residue in mean_gap,
# duration and the gap quantiles, which standardisation had scaled up to unit
# size. It returned PASS only because the null happened to be generous that
# run; with a few more traces it reports a leak on a clean node.
def steady(count, start):
    times, now = [start], start
    for _ in range(count):
        now += 0.05
        times.append(now)
    return times, [1200] * (count + 1)


HONEST_A = [steady(300 + index, 100.0 + index) for index in range(TRACES)]
HONEST_B = [steady(300 + index, 900.0 + 7 * index) for index in range(TRACES)]
# Traces of equal length differing only in when the capture started must be
# one and the same feature vector. Any difference at all is residue, because
# every feature is computed from gaps and from spans, and neither depends on
# the offset.
same_length = [steady(300, 100.0 + index) for index in range(TRACES)]
same_vectors = [trafficlab.features(*t) for t in same_length]
check("a jitter-free cadence yields one feature vector, not five",
      all(vector == same_vectors[0] for vector in same_vectors))

# Unequal trace lengths make count and duration genuinely differ -- that is
# data and it must survive standardisation at full scale. Every feature
# describing the *shape* of the cadence is identical in truth and differs only
# by accumulated rounding, and standardisation is where that rounding used to
# become a unit-scale feature. It has to arrive at approximately zero instead.
honest_columns = list(zip(*trafficlab.standardise(
    [trafficlab.features(*t) for t in HONEST_A + HONEST_B])))
carried, suppressed = {}, {}
for index, name in enumerate(trafficlab.FEATURE_NAMES):
    reach = max(abs(value) for value in honest_columns[index])
    (carried if name in ("count", "duration") else suppressed)[name] = reach
check("...and a real difference in length survives standardisation",
      all(reach > 0.5 for reach in carried.values()))
check("...while the rounding in every cadence feature does not",
      all(reach < 1e-6 for reach in suppressed.values()))
honest = trafficlab.distinguish(HONEST_A, HONEST_B)
check("an honest fixed-cadence fabric does not separate from itself",
      honest["verdict"] == "PASS")

# ...and the floor must not buy that by going blind. A microsecond of drift on
# a 50 ms cadence is four orders of magnitude above RESOLUTION, and captures
# carry microsecond timestamps, so it is the smallest difference the input can
# even hold. It has to survive.
drifted = []
for index in range(TRACES):
    times, now = [0.0], 0.0
    for step in range(300 + index):
        now += 0.05 + (0.000001 if step % 2 else 0.0)
        times.append(now)
    drifted.append((times, [1200] * len(times)))
check("a microsecond of periodic drift is not rounded away",
      trafficlab.features(*drifted[0])[trafficlab.FEATURE_NAMES.index("stdev_gap")] > 0)
check("...and is visible to the order features too",
      trafficlab.features(*drifted[0])[trafficlab.FEATURE_NAMES.index("gap_autocorr_1")]
      != 0.0)

# --------------------------------------------------------------------------
# Determinism. A gate whose verdict moves between runs cannot be a gate, and
# the null is only a null if training is a function of its input alone.
check("feature extraction is reproducible",
      trafficlab.features(*ORDERED[0]) == trafficlab.features(*ORDERED[0]))
check("training is reproducible",
      trafficlab.train(_vectors, _labels) == trafficlab.train(_vectors, _labels))
check("cross-validation is reproducible",
      trafficlab.leave_one_out_accuracy(_vectors, _labels)
      == trafficlab.leave_one_out_accuracy(_vectors, _labels))
_null_once = trafficlab.exhaustive_null(_vectors, _labels)
check("the enumerated null is reproducible",
      _null_once == trafficlab.exhaustive_null(_vectors, _labels))
check("...and enumerates every labeling exactly once",
      len(_null_once) == math.comb(2 * TRACES, TRACES))

# --------------------------------------------------------------------------
# End to end through the CLI, because the campaign keys on the exit status and
# nothing else. The capture is written in the rendered tcpdump form the Go wire
# campaign produces, so this also pins that the lab and the preregistered rule
# read the same files.
def write_capture(path, times):
    lines = ["reading from file capture.pcap, link-type EN10MB (Ethernet)"]
    for stamp in times:
        lines.append(
            f"{1712345678.0 + stamp:.6f} IP 10.0.0.2.4200 > 10.0.0.3.4200: "
            f"UDP, length 1200"
        )
    path.write_text("\n".join(lines) + "\n")


with tempfile.TemporaryDirectory() as workspace:
    root = pathlib.Path(workspace)
    laboratory = str(pathlib.Path(__file__).with_name("traffic-lab.py"))

    def paths(prefix, world):
        written = []
        for index, (times, _sizes) in enumerate(world):
            target = root / f"{prefix}-{index}"
            write_capture(target, times)
            written.append(str(target))
        return written

    ordered_paths = paths("ordered", ORDERED)
    shuffled_paths = paths("shuffled", SHUFFLED)
    control_paths = paths("control", CONTROL_B)

    def run(left, right, *extra):
        return subprocess.run(
            [sys.executable, laboratory, *extra, *left, "--", *right],
            capture_output=True, text=True,
        )

    separable = run(ordered_paths, shuffled_paths)
    check("end to end: a separable pair exits 1", separable.returncode == 1)
    check("end to end: the report is on stdout for the campaign to keep",
          '"verdict": "FINDING"' in separable.stdout)

    check("end to end: an inseparable pair exits 0",
          run(paths("a", CONTROL_A), control_paths).returncode == 0)

    # Underpowered and unreadable both mean "this run did not test anything",
    # and neither may be reported as clean.
    check("end to end: too few traces exits 2, not 0",
          run(ordered_paths[:3], shuffled_paths[:3]).returncode == 2)

    (root / "unreadable").write_text("this is not a capture at all\n")
    check("end to end: an unreadable capture exits 2, not 1",
          run(ordered_paths, [str(root / "unreadable")]).returncode == 2)

    check("end to end: a missing world separator exits 2",
          subprocess.run([sys.executable, laboratory, ordered_paths[0]],
                         capture_output=True, text=True).returncode == 2)
    check("end to end: a non-numeric rounds value exits 2",
          run(ordered_paths, shuffled_paths, "--rounds", "many").returncode == 2)

if failures:
    print(f"\n{len(failures)} traffic-lab self-test(s) failed", file=sys.stderr)
    sys.exit(1)
print("\nall traffic-lab self-tests passed")
