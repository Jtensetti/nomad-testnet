# Service level objectives

Published targets for a Nomad operator, and — more usefully — what has and has
not been measured against them. A target with no measurement behind it is a
wish, and is marked as one.

Every figure here is traceable to a named test or gate. Where a number came
from a single run on a shared container, it says so, because that is not the
same kind of number as one from a preregistered campaign.

## What Nomad promises, and to whom

Nomad's reliability targets are unusual in one way that has to be stated first:
**availability is subordinate to the privacy invariant.** Where the two
conflict, the protocol loses work rather than emit a private-dependent signal.
So these objectives describe what an operator should expect from correctly
functioning infrastructure, not a guarantee to a user that their publication
will succeed.

## Emission

| Objective | Target | Measured | Where |
|---|---|---|---|
| Cell size on the wire | exactly 1200 bytes, no exceptions | yes | Compose pcap gate; `wire.Capture.Sizes` in every node campaign |
| Emission cadence | one cell per configured interval | yes, with a known finding | wire timing campaign; the private-activity timing row is **CONTRADICTED**, see CLAIM_TEST_MATRIX |
| Catch-up bursts after loss | never | yes | `fabric` scheduler tests; one-second burst ceiling asserted on every captured world |
| Emission survives a transient local failure | cell lost, schedule kept | yes | `TestATransientSendFailureCostsOneCellAndNotTheNode`: 29 drops over 30 ticks, cadence held |
| Emission stops on a permanent local failure | node exits, naming the cause | yes | `TestAPermanentlyRefusedDestinationStopsTheNode`, `TestAnUnusableHopSequenceStopsTheNode` |

## Resources

| Objective | Target | Measured | Where |
|---|---|---|---|
| Memory under sustained flood | bounded; no per-datagram retention | yes | `TestASustainedFloodCannotGrowTheHeapWithoutBound`: 234,978 datagrams moved the live heap 347 KiB → 747 KiB |
| Raw cache growth | bounded by the configured stream limit | yes | `TestTheCacheAndQueueBoundsAreReachedRatherThanGrown` |
| Relay queue depth | bounded by the traffic class | yes | same |
| Amplification under flood | well below 1 | yes | 0.0003–0.0008 outbound/inbound across four flood types |
| Disk growth | **not measured** | no | the raw cache is bounded by stream count, not by bytes; no test bounds bytes on disk |

## Availability

| Objective | Target | Measured | Where |
|---|---|---|---|
| Recovery from a lost raw cache | node returns, refills from peers | yes | `TestANodeRecoversOrRefusesForEachPieceOfLostState` |
| Recovery from a lost state directory | node returns; epoch rotation required for peers to accept it | yes | same, plus `TestASequenceRollbackIsInvisibleToTheSenderAndFatalToItsTraffic` |
| Rollback protection across a restart | older or equivocating topology refused | yes | `TestARolledBackTopologyIsRefusedAcrossARestart` |
| Uptime target | **not set** | no | setting one before a 30-day soak would be a number with nothing behind it |
| Availability under sustained loss | **not claimed** | no | see ADMISSION_AND_RATE_CONTROL.md; a sufficiently resourced flood can push a small node past its lateness budget |
| Regional failure | **not measured** | no | needs multi-region infrastructure (EB-3) |

## Detection

The objective that matters most operationally, because the change that keeps a
node running through a local failure removed the crudest alarm there was — the
process exiting.

| Objective | Target | Measured | Where |
|---|---|---|---|
| A node that is up but emitting nothing is detected | within `--max-silence` | yes | `nomad-node --check-health`; `TestTheLivenessTimestampFollowsWhatActuallyWentOut` runs a healthy, a totally failing and a partly failing node |
| The healthcheck fails closed on an unreadable status file | always | yes | `cmd/nomad-node` table over missing, empty and unparseable files |
| A node whose traffic peers silently discard is detected | **only from a peer** | yes, and this is a gap | `TestASequenceRollbackIsInvisibleToTheSenderAndFatalToItsTraffic`: the sender reports healthy while 17 of 18 cells are refused. See RECOVERY.md |

Alert on, at minimum:

- `nomad-node --check-health` non-zero — the node is not emitting;
- `send_dropped` rising — a local condition is costing cells;
- `health_deferred` rising — the status file cannot be written, so every other
  alarm here is degraded;
- a peer's `replay_rejected` rising against you — your sequence state went
  backwards, and nothing on your own node can tell you.

## What is not here

**No 30-day soak.** PROD-28 requires one and none has run. Every number above
comes from tests measured in seconds, in a container, alongside other work.
They establish that a bound exists and is enforced; they say nothing about
drift, leaks or degradation over weeks, which is exactly what a soak is for.

**No capacity target.** Cells per second per operator, objects per epoch,
concurrent publishers: none of these has a number, because none has been
measured at a scale where the number would mean anything.

**No incident history.** These objectives have never been tested by a real
incident, only by exercises that this project designed and ran.
