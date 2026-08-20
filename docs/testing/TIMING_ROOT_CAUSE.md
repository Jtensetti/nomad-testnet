# Timing finding root-cause investigation

The original baseline timing gate reported an idle-vs-active cadence difference of about **3.2-3.3%** against a fixed **2.0%** tolerance. The tolerance has not been changed.

A decomposition experiment (`TestTimingShiftDiagnosis`) separated the original active treatment into five worlds while keeping the same production `Node`, scheduler, UDP sink, observer and decision metric.

## Before the queue fix

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.285% | 0.016% | no |
| queue-only (concurrent enqueue) | 0.050% | **3.955%** | **yes** |
| compute-only, same Go runtime | 0.031% | **2.218%** | **yes** |
| disk-only | 0.039% | 0.567% | no |
| full-active | 0.190% | **2.951%** | **yes** |

Evidence: Actions run `32377363558`, artifact `wire-campaign-captures/TIMING_DIAGNOSIS.json`.

## Root cause found

`fabric.QueueSource.NextCell` used a single producer/consumer mutex and, while holding it, removed the first cell by copying every remaining 1200-byte cell one position left. That made scheduler-path work proportional to queue depth and made concurrent producer activity extend the scheduler critical section.

The result above distinguishes this from a work-vs-cover encoding effect: a queue filled once and then left alone changed cadence by only 0.016%, while concurrent enqueue changed it by 3.955%.

## Fix

`QueueSource` is now a fixed-capacity preallocated ring buffer. Enqueue and dequeue are bounded O(1); dequeue no longer compacts the backing array. FIFO order, capacity, wraparound and concurrent producer/consumer behavior are covered by component tests. The same change is tested both in `nomad-constant-rate-fabric` and in the pinned testnet component snapshot.

The component PR's own CI passed without changing any timing threshold.

## After the queue fix

On Actions run `32378102023`:

| Treatment | control spread | signal | 2% finding? |
|---|---:|---:|---|
| queue-static | 0.093% | 0.009% | no |
| queue-only (concurrent enqueue) | 0.076% | **0.251%** | no |
| compute-only, same Go runtime | 0.043% | **3.937%** | **yes** |
| disk-only, same process | 0.054% | **2.511%** | **yes** |
| full-active | 0.064% | **1.598%** | no |

The directly isolated queue signal therefore fell from **3.955% to 0.251%** (about a 94% reduction), and the original combined treatment fell below the unchanged 2% cadence gate in that run. The normal `go test -race ./...`, analysis positive controls, operator ceremony and `go vet ./...` all passed in the dedicated CI job.

## What the remaining same-process findings mean

The compute-only and disk-only treatments deliberately run unrelated private-style work inside the **same Go process/runtime** as the network `Node`. Their variation demonstrates an important boundary fact: package/dependency separation is not CPU/I/O scheduling isolation.

That treatment is not the deployed reader boundary. `live/node` is the operator network domain; reader selection/reconstruction and the browser are excluded from its dependency graph, and the publication airlock persists locally without network capability. Publisher ingress has a separate fixed-rate `uplink` profile. Therefore a same-runtime private workload must not be used as a substitute for a production-boundary privacy claim.

It remains valuable as a sensitivity diagnostic: if a future deployment colocates private computation with a constant-rate sender, process/resource isolation must itself be tested. We do not convert that observation into a pass by widening the tolerance.

## CI placement correction

The Dockerfile previously ran the wall-clock campaign during every parallel BuildKit image build. That can create an intentionally hostile and uncontrolled timing environment unrelated to the image's correctness. Image builds now run deterministic `go test -short ./live/...`; the timing campaign still runs, unchanged, in the dedicated CI privacy job with its control worlds and evidence. This is test placement, not a relaxed criterion.

## Claim boundary

This work explains and removes the reproducible queue-contention mechanism behind the original ~3.3% shift. It does **not** prove production anonymity, general OS-level timing isolation, independent-operator security, or WAN indistinguishability. Those remain separate evidence gates.
