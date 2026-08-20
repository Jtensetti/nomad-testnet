# Timing finding root-cause investigation

The original baseline timing gate reported an idle-vs-active cadence difference of about **3.2-3.3%** against a fixed **2.0%** tolerance. The tolerance has not been changed.

A decomposition experiment (`TestTimingShiftDiagnosis`) separated the original active treatment into five worlds while keeping the same production `Node`, scheduler, UDP sink, observer and decision metric.

## Before any queue fix

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.285% | 0.016% | no |
| queue-only (concurrent enqueue) | 0.050% | **3.955%** | **yes** |
| compute-only, same Go runtime | 0.031% | **2.218%** | **yes** |
| disk-only | 0.039% | 0.567% | no |
| full-active | 0.190% | **2.951%** | **yes** |

Evidence: Actions run `32377363558`, artifact `wire-campaign-captures/TIMING_DIAGNOSIS.json`.

## Hypothesis 1: slice compaction

The original `fabric.QueueSource.NextCell` used one producer/consumer mutex and, while holding it, removed the first cell by copying every remaining 1200-byte cell one position left. This made scheduler-path work proportional to queue depth.

A preallocated O(1) ring buffer initially appeared to fix the problem: one run measured `queue-only` at 0.251%. A later run with the same ring buffer reproduced approximately **3.87%**.

That falsified the first hypothesis as a complete explanation. Slice compaction was an amplifier, not the fundamental coupling. The producer and scheduler still shared the same mutex, so producer scheduling could still delay the scheduler's work-source path.

## Root cause and architectural fix

The scheduler must not wait for useful work. `QueueSource` therefore no longer has a producer/consumer mutex.

The current bounded non-blocking queue works as follows:

1. a producer atomically reserves a FIFO position;
2. it copies the complete fixed-size cell outside the scheduler path;
3. it atomically publishes that slot as ready;
4. the single scheduler-side consumer reads only the oldest position when it is already published;
5. if the queue is empty, or the oldest reserved producer has not published yet, `NextCell` returns `ErrNoWork` immediately;
6. `CoverSource` then supplies cover for the already-public emission slot.

The consumer does not spin, sleep, acquire a producer-held lock, retry, or skip ahead. A stalled producer may reduce useful throughput, but it cannot hold a scheduled slot waiting for work. This is the intended failure direction: availability yields to the fixed observable schedule.

Component regressions cover FIFO order, bounded capacity, concurrent producers/consumer and a deliberately stalled reserved slot. The component passes race/unit CI.

## Lock-free post-fix evidence

The exact lock-free implementation was copied into the pinned testnet snapshot and exercised by the normal integration path.

### Execution 1

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.073% | 0.018% | no |
| queue-only | 0.042% | **0.434%** | no |
| compute-only | 0.021% | 0.598% | no |
| disk-only | 0.015% | **3.183%** | **yes** |
| full-active | 0.042% | **2.492%** | **yes** |

Evidence: Actions run `32379491322`, artifact `9410486105`.

### Independent rerun

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | — | 0.005% | no |
| queue-only | 0.041% | **0.323%** | no |
| compute-only | 0.046% | **3.346%** | **yes** |
| disk-only | 0.034% | **2.541%** | **yes** |
| full-active | 0.080% | **2.014%** | **yes** |

Evidence: rerun of Actions run `32379491322`, artifact `9411954174`.

The directly isolated concurrent-queue signal is therefore reproducibly about **0.3-0.4%** after the lock-free change, compared with about **3.9%** before it, with the threshold still fixed at **2.0%**.

The same testnet snapshot also passed `go test -race ./...`, the traffic-analysis harness self-tests, operator ceremony, `go vet ./...`, and the isolated multi-process Compose fabric-to-cache path.

Issue #6 was closed for this specific QueueSource/scheduler channel after those results were recorded.

## Why the CPU/disk findings are not erased

The decomposition also exposed a different class of effect: unrelated CPU or disk activity running in the **same Go process/runtime and host** can perturb wall-clock scheduling on some shared runners. Its magnitude varies substantially between executions, which is consistent with host/runtime resource contention rather than the now-removed QueueSource lock path.

That finding remains security-relevant. Package/dependency separation is not process or resource isolation.

It is also a different production boundary. The native Nomad reader keeps private query/selection state in a network-incapable browser sandbox and intentionally contains no fabric transport. A separate materializer/network domain is intended to populate the verified cache. The future publisher fixed-rate uplink must likewise remain outside the private authoring/work process.

Therefore the remaining same-host resource channel is tracked separately as issue #7. It must be tested using release-shaped **separate processes**, the actual IPC/storage boundary, and host/kernel packet capture under CPU, disk and memory pressure. A deliberately colocated same-runtime case remains useful as a positive control.

We do not convert that observation into a pass by widening the timing tolerance or by claiming that package separation is sufficient.

## Shared-runner measurement boundary

The complete preregistered packet-analysis rule is preserved, but a GitHub shared runner can sometimes make even idle-vs-idle worlds fail its timing statistics. For example, one lock-free run measured an idle-vs-idle baseline drift of about 3.39%, already above the 2% resolution target.

Such a run is evidence that the host cannot resolve that comparison, not evidence for or against anonymity. The local campaign therefore measures its own idle-control spread and reports a statistic as undecidable when the noise floor itself reaches the threshold. The stricter sustained rule belongs on controlled hosts and the real WAN campaign.

The intentionally distinguishing analyzer fixtures remain in CI so a green result cannot be produced by a blind parser or disabled detector.

## CI placement correction

The Dockerfile previously ran the wall-clock campaign during every parallel BuildKit image build. That caused the timing experiment to execute repeatedly while the host was simultaneously compiling multiple images. Image builds now run deterministic `go test -short ./live/...`; the wall-clock campaign still runs with the unchanged 2% threshold in the dedicated CI privacy job.

This is test placement, not a relaxed criterion.

## Claim boundary

This work explains and removes the reproducible scheduler-visible QueueSource contention mechanism behind issue #6. It does **not** prove general OS-level timing isolation, client process isolation, WAN indistinguishability, independent-operator security, publication anonymity, or production anonymity. Those remain separate evidence gates.