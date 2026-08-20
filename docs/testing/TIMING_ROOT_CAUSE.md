# Timing finding root-cause investigation

The original baseline timing gate reported an idle-vs-active cadence difference of about **3.2-3.3%** against a fixed **2.0%** tolerance. The tolerance has not been changed.

This document records hypotheses that were later falsified as well as fixes that survived further testing. A green intermediate run is not treated as a final conclusion.

## Initial decomposition

`TestTimingShiftDiagnosis` separated the original active treatment into five worlds while keeping the same production `Node`, scheduler, UDP sink, observer and decision metric.

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.285% | 0.016% | no |
| queue-only (concurrent enqueue) | 0.050% | **3.955%** | **yes** |
| compute-only, same Go runtime | 0.031% | **2.218%** | **yes** |
| disk-only | 0.039% | 0.567% | no |
| full-active | 0.190% | **2.951%** | **yes** |

Evidence: Actions run `32377363558`, `wire-campaign-captures/TIMING_DIAGNOSIS.json`.

The static queue result ruled out work-vs-cover encoding as the main timing mechanism. Concurrent producer activity was the strongest isolated treatment.

## Hypothesis 1: slice compaction

The original `fabric.QueueSource.NextCell` used one producer/consumer mutex and, while holding it, removed the first cell by copying every remaining 1200-byte cell one position left. This made scheduler-path work proportional to queue depth.

A preallocated O(1) ring buffer initially appeared to fix the problem: one run measured `queue-only` at 0.251%. A later run with the same ring buffer reproduced approximately **3.87%**.

That falsified slice compaction as a complete explanation. It was an amplifier, but producer and scheduler still shared the same mutex.

## Queue architecture fix

`QueueSource` was changed to a bounded non-blocking producer/consumer queue with no producer-held mutex on the scheduler path:

1. a producer atomically reserves a FIFO position;
2. it copies the complete fixed-size cell;
3. it atomically publishes the slot as ready;
4. the single scheduler consumer reads only the oldest position when already published;
5. if the queue is empty or the oldest reservation is not yet published, `NextCell` returns `ErrNoWork` immediately;
6. `CoverSource` supplies cover for the already-public emission slot.

The consumer does not spin, sleep, wait on the producer, retry, or skip ahead. A stalled producer can reduce useful throughput but cannot deliberately hold the scheduler waiting for useful work.

Component regressions cover FIFO order, bounded capacity, concurrent producers/consumer and a deliberately stalled reserved slot. Component race/unit CI passes.

## Early lock-free evidence

Two independent diagnosis executions after the lock-free change measured the isolated concurrent-queue signal at:

- **0.434%**, control 0.042%;
- **0.323%**, control 0.041%.

Both were far below the unchanged 2.0% threshold. In the same executions, unrelated same-runtime CPU/disk treatments sometimes still exceeded 2%, showing that removing a queue lock does not provide general host/runtime resource isolation.

A first permanent relay regression also passed at approximately 0.437% signal with about 0.025% control spread.

Those observations supported closing issue #6 for the queue/scheduler channel at that time.

## Reopening: later falsifying run

A later independent shared runner falsified the claim that the relay-producer gate was already stable across executions:

- permanent relay-producer signal: **2.47%**;
- relay control spread: **0.29%**;
- composite baseline signal: **2.43%**;
- composite baseline control spread: **0.07%**;
- threshold: **2.00%**, unchanged.

Because the controls were below the decision threshold, this was not classified as UNDECIDABLE. Issue #6 was reopened rather than explaining the run away.

Review of the permanent regression then found an experimental confound: every round always ran `control A -> control B -> control C -> treatment`. The treatment therefore always occupied the fourth wall-clock position. A monotonic runner drift over the experiment could alias execution position into a treatment effect while leaving the three controls relatively close to one another.

## Balanced-order relay experiment

The relay regression now uses four rounds and rotates the four series:

```text
round 0: A B C T
round 1: B C T A
round 2: C T A B
round 3: T A B C
```

Each control and the treatment therefore occupies every execution position exactly once. This changes neither the treatment nor the **2.0%** decision threshold; it removes wall-clock position as a confound.

First balanced execution, Actions run `32391362393`, artifact `9415043124`:

| Measure | Result |
|---|---:|
| relay control spread | **0.052%** |
| relay producer signal | **0.150%** |
| threshold | **2.000%** |
| decision | **PASS** |

The same artifact's unbalanced diagnostic treatments remained informative:

| Treatment | control spread | signal | finding? |
|---|---:|---:|---|
| queue-static | 0.066% | 0.004% | no |
| queue-only | 0.095% | 0.368% | no |
| compute-only | 0.031% | **3.969%** | **yes** |
| disk-only | 0.180% | **2.622%** | **yes** |
| full-active | 0.071% | 1.739% | no |

This is the desired experimental separation: the balanced relay-producer treatment is far below the gate while same-runtime CPU/disk sensitivity remains visible rather than being hidden by the queue fix.

**Issue #6 remains open until the balanced relay result is reproduced on another independent runner.** If a balanced, resolvable run again exceeds 2%, the operator shaper/relay architecture must be isolated further rather than changing the threshold.

## Why the CPU/disk findings remain open

Unrelated CPU or disk activity in the same Go runtime/host can perturb wall-clock scheduling. Package/dependency separation is therefore not a resource-isolation boundary.

For the reader product, private query/selection belongs in the network-incapable native browser process. Current macOS boundary work uses two Team-scoped App Groups:

```text
network/fetch domain -> <TeamID>.nomad.fabric-cache
                           |
                           v
                    networkless materializer
                           |
                           v
Nomad Browser       <- <TeamID>.nomad.browser-cache
```

Browser and network/fetch processes never share one App Group directly. The materializer is the only bridge and has no network entitlement. This is tracked in issue #7 and still needs a host/kernel packet-capture campaign using release-shaped separate processes under CPU/disk/UI/search pressure.

The future publisher fixed-rate uplink needs the equivalent process/resource boundary.

## Shared-runner measurement boundary

The complete preregistered packet-analysis rule is preserved, but a GitHub shared runner can sometimes make even idle-vs-idle worlds fail. A run whose control spread itself reaches the target resolution is evidence that the host cannot decide that comparison, not a privacy pass or failure.

The intentionally distinguishing analyzer fixtures remain in CI so a green result cannot be produced by a disabled detector or blind parser.

## CI placement correction

Wall-clock privacy campaigns are no longer run repeatedly inside parallel Docker BuildKit image builds. Image builds use deterministic `go test -short ./live/...`; dedicated privacy CI retains the unchanged 2% timing decision rule and uploads the captures.

## Current claim boundary

The shared-mutex QueueSource mechanism has been removed and multiple measurements show a large reduction in concurrent queue signal. The later 2.47% run also exposed a treatment-order confound, and the first balanced execution measured 0.150%.

This is **not yet a closed production claim**. Issue #6 stays open pending another balanced execution. Issue #7 separately tracks OS/process resource isolation. WAN indistinguishability, independent operators, publication anonymity and production anonymity remain unproven.