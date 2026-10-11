# Traffic-analysis preregistration

This document fixes the features, metrics, tolerances and decision rule for
Nomad's two-world traffic-analysis experiments **before** any result is
examined. Its purpose is to make the experiments falsifiable: a threshold
chosen after seeing the answer proves nothing.

**Amendment rule.** Any change to this document after captures exist must be
recorded in the amendment log at the bottom, with the reason, and invalidates
every result gathered under the previous version. Results are re-gathered,
not reinterpreted.

Version: 2. Registered: 2026-08-21. Version 1 was registered 2026-08-20; the
results gathered under it are void, for the reason given in the amendment log.

## Hypotheses

For each experiment, the null hypothesis is that the observable traffic is
independent of the private state, and the alternative is that it is not. The
project's claim is the null; the experiment exists to try to reject it.

| ID | World A | World B | Claim under test |
|---|---|---|---|
| TA-1 | client idle | client running local search | reader non-interference |
| TA-2 | search for object X | search for object Y | reader non-interference across queries |
| TA-3 | reading a cached object | reconstructing an uncached one | reconstruction non-interference |
| TA-4 | publisher idle | publisher submitting one object | publication non-interference |
| TA-5 | publisher submitting one object | publisher submitting many | publication volume non-interference |
| TA-6 | publication succeeds | publication fails and retries | failure non-interference |
| TA-7 | node steady | node restarted mid-window | restart non-interference |

TA-4 through TA-7 cannot run until the airlock's deposit path exists. They
are registered now so that the tolerances are fixed before the implementation
that will be judged against them.

## Observable features

Extracted from packet captures taken on a real interface with kernel
timestamps. Per capture, per direction, per peer:

1. packet count;
2. packet size distribution (Nomad's profile is fixed-size, so any variance
   is itself a finding);
3. inter-arrival times: mean, median, standard deviation, and the full
   empirical distribution;
4. burst structure: maximum packets in any 1 s window, and the distribution
   of gaps exceeding 1.5x the nominal cell interval;
5. destination sequence: the ordered series of peer slots used;
6. connection lifecycle events: sockets opened or closed during the window;
7. total bytes;
8. any non-Nomad traffic from the measured process, including DNS.

## Sample definition

The features above are extracted **per flow**, where a flow is one (source
address, destination address) pair. That is what "per direction, per peer"
means operationally, and it is the unit every test below is applied to.

Pooling a capture's packets into a single series instead is not a weaker
version of this; it measures something else. A capture taken on a host holds
that host's emissions and its peers' arrivals interleaved, and the two streams
have independent phase. Restarting the node between worlds re-randomises that
phase, which shifts the pooled inter-arrival distribution regardless of what
the node did.

**Windows.** The count test compares equal-length windows. Each world's window
is an integer number of nominal cell intervals, and opens half an interval
before that flow's first cell in that world. Anchoring on a cell instead would
let jitter decide whether the closing cell falls inside, so two honest worlds
would differ by one cell and the count test would report the ruler's edge as a
leak. At half an interval, gaining or losing a cell requires jitter of half an
interval, which the inter-arrival tests reject on their own.

**Which flows carry the verdict.** The claim under test is that private
activity does not modulate the observable events a node *creates*. That claim
is evaluated on the flows sourced at the measured host.

Flows the host receives are also tested and reported in full, but they are a
joint function of the sender and of the path between them, and a lossy hour on
a third party's backbone is not evidence about this node's scheduler. They are
therefore reported under a separate verdict and a distinct non-zero exit
status: visible, never silently dropped, and never folded into the measured
node's result.

A finding on a received flow is attributed, not excused. Every campaign
captures at both ends of every link, so a difference in what B received is
checked against B's sender's own capture of the same cells. If the sender
emitted the same count in both worlds and the receiver saw different counts,
the difference is in the path; if the sender's own emissions differ, that is a
finding against the sender, at the sender.

## Decision rule

A world pair **fails** — the claim is rejected — if any of the following
holds. These are fixed now:

| Test | Threshold |
|---|---|
| Packet count differs | any difference at all, for equal-length windows |
| Any packet size differs from the profile constant | any occurrence |
| Two-sample Kolmogorov-Smirnov on inter-arrival times | p < 0.01 |
| Difference in mean inter-arrival | > 2% of the nominal cell interval |
| Maximum 1 s burst count differs | any difference |
| Destination-sequence distributions differ (chi-square) | p < 0.01 |
| Socket lifecycle events differ | any difference |
| Any DNS or non-Nomad packet from the measured process | any occurrence |
| Blind classifier accuracy over >= 100 labelled captures per world | > 55% (95% CI lower bound above 50%) |

The classifier threshold is deliberately close to chance: at 100 captures
per world, 55% is roughly the point at which a binomial test rejects a fair
coin at p < 0.05. A classifier that beats chance at all is a finding.

**A single failing run is a finding.** It is investigated and explained, not
averaged away across runs.

**Passing is not proof.** "The classifier failed" bounds an attacker of the
modelled strength with the sample size used; it does not establish
indistinguishability. Every report states its sample size and the power that
sample gives.

## Blinding

Captures are labelled by an index only. The mapping from index to world is
withheld until after the analyst has committed classifications, and the
committed classifications are hashed and recorded before the mapping is
revealed. An analysis run whose labels were visible is not a blind run and
must be reported as such.

## Environment matrix

Each experiment is repeated across:

- loss: 0%, 0.1%, 1%, 5%, 20%; random and burst;
- latency: nominal, +50 ms, +200 ms, asymmetric;
- jitter: 0, 10 ms, 50 ms;
- reordering and duplication: 0%, 1%;
- host: steady, suspend/resume (30 s and 5 min), clock jump +/-30 s, CPU
  starvation;
- network: IPv4-only, IPv6-only, dual-stack, behind NAT with rebinding.

## Sample size and duration

Screening runs: 30 captures per world, 5 minutes each. Confirmatory runs:
100 captures per world, 30 minutes each. The production requirement of
72-hour per-platform captures is separate and is not satisfied by any number
of shorter runs.

## Amendment log

| Version | Date | Change | Results invalidated |
|---|---|---|---|
| 1 | 2026-08-20 | Initial registration | none (no results existed) |
| 2 | 2026-08-21 | Added the sample definition above: per-flow extraction, window placement, and which flows carry the verdict. No threshold changed. | WAN campaign nomad-wan-20260821-123801 (all three hosts) |

Version 2 is a clarification of what the analysis is applied to, not of what
counts as a failure; every threshold in the decision rule is unchanged from
version 1. It was written because the first multi-region WAN campaign returned
FAIL on all three hosts and the cause was the instrument: the analysis script
pooled each capture's flows into one series, which version 1 did not ask for
and which the "per direction, per peer" wording excluded. The campaign's
results are void rather than reinterpreted, per the amendment rule, and the
measurement was re-run under this version.

Re-analysing void captures is diagnosis, and is reported as diagnosis. It does
not become a result by having been recomputed with a correct instrument.
