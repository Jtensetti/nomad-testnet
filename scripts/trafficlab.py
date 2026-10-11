"""Traffic-analysis features and a classifier-based two-world distinguisher.

The preregistered rule in two-world-analysis.py compares *marginal*
distributions: a Kolmogorov-Smirnov test over inter-arrivals, a chi-square over
per-destination counts. Those are the right first questions and they are not
the adversary's question.

A traffic-analysis adversary trains a classifier. That is what the website
fingerprinting literature Maybenot is built against actually does, and a
classifier sees structure a marginal test cannot: two worlds can have the same
inter-arrival distribution and differ completely in the *order* of those
inter-arrivals, in how bursts are shaped, or in where in the trace the
variation sits. A defence that passes KS and loses to a classifier is a defence
that passes the test and fails the threat.

So this is the adversary's side of the instrument, and it is deliberately
aggressive: it is trying to distinguish the worlds, and a run where it fails to
is the result worth having.

Nothing here is a replacement for the preregistered rule. It is a second
instrument answering a strictly stronger question, reported separately.

No third-party modules, for the same reason the rest of this directory has
none: the statistics are short enough to write and reading them is part of
trusting the verdict.
"""

import itertools
import math
import random

# Below this, relative to the level of the quantity, a spread is rounding and
# not signal.
#
# A fixed-cadence fabric is the normal input to this lab, and its gaps are equal
# only up to floating point: summing 0.05 three hundred times and dividing
# leaves a mean that misses by an ulp, so a genuinely constant series has a
# computed variance around 1e-33 rather than 0. Anything that tests against
# zero does not fire, and anything that divides by the spread then amplifies
# that residue to unit scale.
#
# That is not a rounding nuisance, it is a false-finding generator pointed at
# exactly the honest traffic Nomad emits: two worlds of pure 0.05 s cadence,
# no jitter anywhere, were separated by this classifier at accuracy 1.0 on the
# residue in mean_gap, duration and the gap quantiles alone.
#
# Captures carry microsecond timestamps, so the smallest timing difference the
# input can even express is around one part in 1e5 of a 50 ms cadence. A floor
# four orders of magnitude below that discards residue and keeps every
# difference the data is capable of holding.
RESOLUTION = 1e-9


# The feature vector, and why each entry is here.
#
# Every feature is computed from packet timestamps and sizes only -- what an
# observer at a link sees. None of them reads anything private; if one did, the
# lab would be measuring its own instrumentation rather than the wire.
FEATURE_NAMES = [
    "count",              # how many packets, the crudest signal there is
    "duration",           # wall-clock span of the trace
    "mean_gap",           # first moment of inter-arrival
    "stdev_gap",          # second moment: jitter
    "median_gap",
    "p90_gap",            # tail: a defence that mostly holds cadence but
    "p99_gap",            # occasionally does not shows up here and not in the mean
    "max_gap",
    "gap_autocorr_1",     # ORDER. The marginal tests are blind to this: shuffle
    "gap_autocorr_2",     # a trace's gaps and every KS statistic is unchanged.
    "gap_autocorr_4",
    "burst_count",        # runs of packets closer together than the cadence
    "mean_burst_len",
    "max_burst_len",
    "mean_size",          # constant in a fixed-cell fabric; a non-zero variance
    "stdev_size",         # here is itself a finding
    "unique_sizes",
]


def quantile(sorted_values, fraction):
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = fraction * (len(sorted_values) - 1)
    lower = int(math.floor(position))
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def autocorrelation(values, lag):
    """Lag-k autocorrelation of the inter-arrival series.

    This is the feature the marginal tests structurally cannot have. KS over
    inter-arrivals is invariant to any permutation of them, so a world whose
    gaps are the same numbers in a different order is, to KS, the same world.
    """
    if len(values) <= lag + 1:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values)
    # A constant series has no correlation to report. Tested against zero this
    # returned 0.95 for a stream of identical gaps -- a strong order signal
    # invented out of floating-point residue.
    if variance <= 0 or math.sqrt(variance / len(values)) <= abs(mean) * RESOLUTION:
        return 0.0
    covariance = sum(
        (values[index] - mean) * (values[index + lag] - mean)
        for index in range(len(values) - lag)
    )
    return covariance / variance


def bursts(gaps, threshold):
    """Runs of consecutive gaps below the threshold, and their lengths."""
    lengths, run = [], 0
    for gap in gaps:
        if gap < threshold:
            run += 1
        elif run:
            lengths.append(run)
            run = 0
    if run:
        lengths.append(run)
    return lengths


def features(times, sizes):
    """Turn one capture into the feature vector above."""
    if len(times) < 2:
        raise ValueError("a trace needs at least two packets to have an inter-arrival")
    ordered = sorted(times)
    gaps = [ordered[index] - ordered[index - 1] for index in range(1, len(ordered))]
    ranked = sorted(gaps)
    mean_gap = sum(gaps) / len(gaps)
    variance = sum((gap - mean_gap) ** 2 for gap in gaps) / len(gaps)
    # A burst is packets arriving closer together than half the typical gap,
    # which is scale-free: it does not need the configured cadence passed in.
    burst_lengths = bursts(gaps, mean_gap * 0.5)
    mean_size = sum(sizes) / len(sizes) if sizes else 0.0
    size_variance = (
        sum((size - mean_size) ** 2 for size in sizes) / len(sizes) if sizes else 0.0
    )
    return [
        float(len(ordered)),
        ordered[-1] - ordered[0],
        mean_gap,
        math.sqrt(variance),
        quantile(ranked, 0.5),
        quantile(ranked, 0.9),
        quantile(ranked, 0.99),
        ranked[-1],
        autocorrelation(gaps, 1),
        autocorrelation(gaps, 2),
        autocorrelation(gaps, 4),
        float(len(burst_lengths)),
        (sum(burst_lengths) / len(burst_lengths)) if burst_lengths else 0.0,
        float(max(burst_lengths)) if burst_lengths else 0.0,
        mean_size,
        math.sqrt(size_variance),
        float(len(set(sizes))),
    ]


def standardise(vectors):
    """Zero mean and unit variance per feature, computed over the whole set.

    A feature measured in seconds and one measured in packet counts differ by
    orders of magnitude, and an unstandardised gradient step is then dominated
    by whichever happens to be large. That is not a modelling nicety: it would
    make the classifier weaker, and a weak adversary reporting "cannot
    distinguish" is exactly the result this file must not produce by accident.
    """
    if not vectors:
        return []
    width = len(vectors[0])
    means, deviations = [], []
    for index in range(width):
        column = [vector[index] for vector in vectors]
        mean = sum(column) / len(column)
        variance = sum((value - mean) ** 2 for value in column) / len(column)
        means.append(mean)
        deviation = math.sqrt(variance)
        # A column whose spread is below the resolution of its own level holds
        # no information, and dividing by that spread is what turns rounding
        # into a feature. Mapping it to 1.0 sends every entry to about zero,
        # which is what a constant column should contribute.
        scale = max(abs(mean), max(abs(value) for value in column))
        deviations.append(deviation if deviation > scale * RESOLUTION else 1.0)
    return [
        [(vector[index] - means[index]) / deviations[index] for index in range(width)]
        for vector in vectors
    ]


def train(vectors, labels, passes=400, rate=0.1):
    """Logistic regression by gradient descent.

    Deterministic on purpose: fixed initialisation, fixed iteration count, no
    shuffling. A verdict that moved between runs would be unusable as a gate,
    and the permutation null below depends on the training being a function of
    its input alone.
    """
    width = len(vectors[0])
    weights = [0.0] * width
    bias = 0.0
    for _ in range(passes):
        gradient = [0.0] * width
        bias_gradient = 0.0
        for vector, label in zip(vectors, labels):
            score = bias + sum(weights[i] * vector[i] for i in range(width))
            # Clamped to keep exp from overflowing on a confidently wrong point.
            prediction = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, score))))
            error = prediction - label
            for i in range(width):
                gradient[i] += error * vector[i]
            bias_gradient += error
        count = len(vectors)
        for i in range(width):
            weights[i] -= rate * gradient[i] / count
        bias -= rate * bias_gradient / count
    return weights, bias


def predict(weights, bias, vector):
    score = bias + sum(weights[i] * vector[i] for i in range(len(vector)))
    return 1 if score > 0 else 0


def leave_one_out_accuracy(vectors, labels):
    """Accuracy under leave-one-out cross-validation.

    Leave-one-out rather than a train/test split because these campaigns
    produce a handful of traces per world, and a split would leave a test set
    too small to mean anything. Every point is predicted by a model that never
    saw it.
    """
    correct = 0
    for held in range(len(vectors)):
        rest = [vectors[i] for i in range(len(vectors)) if i != held]
        rest_labels = [labels[i] for i in range(len(labels)) if i != held]
        if len(set(rest_labels)) < 2:
            # Holding this one out leaves one class. Predicting it is
            # meaningless, so count it as a coin flip rather than as a success.
            correct += 0
            continue
        weights, bias = train(rest, rest_labels)
        if predict(weights, bias, vectors[held]) == labels[held]:
            correct += 1
    return correct / len(vectors)


# Enumerating every labeling is exact and seed-free, and costs one
# cross-validation per labeling. Up to this many that is no more work than the
# sampled null it replaces, so it is simply the better test; past it, sampling.
ENUMERATION_LIMIT = 400


def exhaustive_null(vectors, labels):
    """Every possible labeling, not a sample of them.

    Preferred wherever it is affordable. The sampled null below estimates the
    tail from a few hundred draws, and in the regime these campaigns run in --
    five or six traces per world -- that estimate is too coarse for the answer
    it is asked to give. Measured on a synthetic pair the classifier separates
    perfectly, whose exact permutation p is 0.0079, the sampled null returned a
    finding for two of eight seeds and PASS for the other six. The verdict was
    being decided by the seed rather than by the traffic.
    """
    positives = sum(1 for label in labels if label == 0)
    scores = []
    for chosen in itertools.combinations(range(len(labels)), positives):
        permuted = [1] * len(labels)
        for index in chosen:
            permuted[index] = 0
        scores.append(leave_one_out_accuracy(vectors, permuted))
    return scores


def permutation_null(vectors, labels, rounds, seed):
    """The accuracy distribution when the labels mean nothing, sampled.

    This is what makes the accuracy interpretable. With ten traces and
    seventeen features a classifier can reach high accuracy on noise alone, so
    "80% accurate" says nothing until you know what shuffled labels achieve on
    the same data. The null is computed by the same code path as the real
    number, so any optimism in the classifier is present in both.
    """
    generator = random.Random(seed)
    shuffled_scores = []
    for _ in range(rounds):
        permuted = labels[:]
        generator.shuffle(permuted)
        shuffled_scores.append(leave_one_out_accuracy(vectors, permuted))
    return shuffled_scores


def distinguish(world_a, world_b, rounds=200, seed=20260903):
    """Can a classifier tell these two sets of traces apart?

    world_a and world_b are lists of (times, sizes). Returns the verdict, the
    cross-validated accuracy, and the p-value against the permutation null.
    """
    alpha = 0.01
    # Before measuring anything: can this run reject at all?
    #
    # Two separate things cap how small a p-value can come out, and neither of
    # them has anything to do with the traffic.
    #
    # A permutation test cannot go below 1/L, where L is the number of distinct
    # labelings -- C(n, |a|). With four traces per world that is C(8,4) = 70, so
    # the smallest attainable p is 0.014 and alpha 0.01 is unreachable however
    # separable the two worlds are.
    #
    # And the null here is sampled rather than enumerated, so it cannot go below
    # 1/(rounds + 1) either: 50 rounds bottom out at p = 0.0196.
    #
    # Either ceiling at or above alpha makes this a gate that cannot fail, so
    # the run says so instead of returning PASS. The first version of this file
    # had neither guard, and a synthetic pair the classifier separated perfectly
    # came back PASS at p = 0.033 -- the instrument reporting the size of the
    # experiment as a property of the network.
    total = len(world_a) + len(world_b)
    labelings = math.comb(total, len(world_a)) if total else 0
    exact = 0 < labelings <= ENUMERATION_LIMIT
    # Two labelings always tie with the truth, not one: flipping every label
    # makes this classifier learn the negated rule and score identically, which
    # was confirmed on a perfectly separated pair -- 2 of 252 labelings reached
    # the observed accuracy, for an exact p of 0.0079. A floor of 1/L would
    # have claimed twice the power this test has.
    from_labelings = (2.0 / labelings) if labelings else float("inf")
    from_rounds = 0.0 if exact else 1.0 / (rounds + 1)
    smallest = max(from_labelings, from_rounds)
    if len(world_a) < 3 or len(world_b) < 3 or smallest >= alpha:
        needed = 3
        while 2.0 / math.comb(2 * needed, needed) >= alpha:
            needed += 1
        rounds_needed = 1
        while 1.0 / (rounds_needed + 1) >= alpha:
            rounds_needed += 1
        limits = []
        if len(world_a) < 3 or len(world_b) < 3 or from_labelings >= alpha:
            limits.append(
                f"{len(world_a)} and {len(world_b)} traces give {labelings} "
                f"distinct labelings, of which the true one and its complement "
                f"always tie, bottoming out at p {from_labelings:.4f}, so collect "
                f"at least {needed} traces per world"
            )
        if from_rounds >= alpha:
            limits.append(
                f"{rounds} sampled permutation rounds bottom out at p "
                f"{from_rounds:.4f}, so use at least {rounds_needed} rounds"
            )
        return {
            "verdict": "INCONCLUSIVE",
            "reason": (
                f"the smallest p-value this run could produce is {smallest:.4f}, "
                f"so alpha {alpha} is unreachable and the verdict would say "
                f"nothing about the traffic: " + "; ".join(limits) + "."
            ),
            "traces": {"a": len(world_a), "b": len(world_b)},
            "rounds": rounds,
            "smallest_attainable_p": smallest,
        }
    traces = [features(*trace) for trace in world_a] + [
        features(*trace) for trace in world_b
    ]
    labels = [0] * len(world_a) + [1] * len(world_b)
    vectors = standardise(traces)
    accuracy = leave_one_out_accuracy(vectors, labels)
    if exact:
        null = exhaustive_null(vectors, labels)
    else:
        null = permutation_null(vectors, labels, rounds, seed)
    # One-sided: how often does meaningless labelling do at least this well?
    at_least = sum(1 for score in null if score >= accuracy)
    # The exhaustive null already contains the true labeling, so its tail
    # fraction is the p-value outright. The sampled one does not, and the
    # add-one keeps it from ever reporting an impossible zero.
    p_value = (at_least / len(null)) if exact else (at_least + 1) / (len(null) + 1)
    result = {
        "verdict": "FINDING" if p_value < alpha else "PASS",
        "accuracy": accuracy,
        "null": "exhaustive" if exact else "sampled",
        "null_mean": sum(null) / len(null),
        "null_max": max(null),
        "p_value": p_value,
        "traces": {"a": len(world_a), "b": len(world_b)},
        "smallest_attainable_p": smallest,
    }
    if not exact:
        result["rounds"] = rounds
        result["seed"] = seed
    return result
