# Timing finding root-cause investigation

The original baseline privacy timing gate reported an idle-vs-active cadence difference of about 3.2-3.3% against a fixed 2.0% tolerance. The tolerance has not been changed.

A decomposition experiment (`TestTimingShiftDiagnosis`) separated the original active treatment into five worlds while keeping the same production `Node`, scheduler, UDP sink, observer and decision metric.

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.002854 | 0.000158 | no |
| queue-only (concurrent enqueue) | 0.000505 | 0.039547 | **yes** |
| compute-only, same Go runtime | 0.000313 | 0.022179 | **yes** |
| disk-only | 0.000389 | 0.005667 | no |
| full-active | 0.001903 | 0.029507 | **yes** |

Evidence artifact: GitHub Actions run `32377363558`, `wire-campaign-captures`, `TIMING_DIAGNOSIS.json`.

## Interpretation

1. Merely sending work instead of cover is not the cause: a statically full work queue is comfortably below the gate.
2. Concurrent mutation of `fabric.QueueSource` is the strongest isolated cause. The current queue uses one mutex and shifts the entire slice on every dequeue, putting producer activity directly on the scheduler critical path.
3. Private compute in the same Go runtime also crosses the 2% threshold by itself, although less strongly. This means dependency separation alone is not sufficient: same-runtime resource contention can modulate wake-up/emission timing.
4. Private local file persistence by itself did not cross the gate in this experiment.

## Required fix

- Make the public work queue bounded O(1), with no slice compaction on the scheduler path.
- Re-run the unchanged 2% gate and the decomposition experiment.
- Keep reader/private computation outside the network process/runtime in production-boundary tests. A separate package is not a scheduling boundary.
- Retain an intentionally leaky positive control so a green result cannot come from a blind harness.

This document records evidence and a hypothesis-to-fix chain. It does not claim production anonymity or close issue #6 by itself.
