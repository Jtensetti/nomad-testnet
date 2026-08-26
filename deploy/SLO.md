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

## Capacity

PROD-28 asked for cells per second per operator, objects per epoch and
concurrent publishers. Two of those three are not measurements.

A fixed-cadence fabric has no throughput in the usual sense. An operator emits
exactly one cell per interval per link whether it has work or not, so **cells
per second per operator is a fact about the signed topology**, not about the
hardware. What the hardware decides is whether the node finishes the per-cell
work inside the interval, and by what margin. That margin is the number worth
having, because when it reaches one the node starts missing its cadence, and a
node whose emissions drift with load is a node whose timing carries load rather
than schedule.

### The envelope, from the deployed configuration

At `deploy/compose.yaml`'s 50 ms cadence with three operators, each having two
links, and `cmd/nomad-node`'s default of 64 raw-cache streams. `live/capacity`
holds the derivation and `TestTheReportedDeploymentIsTheDeployedOne` fails if
these stop matching what is deployed.

| Figure | Value | Kind |
|---|---|---|
| Cells per second per link | 20 | configuration |
| Cells per second per operator, one direction | 40 | configuration |
| Cells per epoch per operator, quoting a 24-hour epoch | 3,456,000 | configuration |
| Publication payload per cell | 504 bytes of a 1200-byte cell | protocol |
| Payload ceiling per epoch per operator | 1.74 GB | arithmetic |
| Objects per epoch at 1 MiB | 1,660 | arithmetic |

The last two are ceilings and no deployment reaches them. They assume every
cell carries work, and cover traffic is the mechanism rather than waste, so the
work fraction is a privacy parameter a deployment chooses; the coding rate is
not applied either, and RLNC emits more coded fragments than an object has
source fragments. Divide by both.

### The measured margins

Measured by `TestCapacityReport`; the full artifact including the environment
is `deploy/capacity-report.json`.

| Operation | Cost | Per second | Headroom vs the 50 ms interval |
|---|---|---|---|
| hop seal (operator, per emitted cell) | 26.6 us | 37,602 | 1,880x |
| hop open (operator, per received cell) | 26.9 us | 37,114 | 1,856x |
| hop relay (open then seal) | 52.2 us | 19,150 | 958x |
| raw cache put (operator, per received cell) | 459.8 us | 2,175 | 109x |
| uplink seal (publisher, per emitted cell) | 9.47 ms | 106 | 5x |
| uplink handshake (publisher side) **(not on any deployed path)** | 95.8 us | 10,444 | 522x |

Three things in that table are worth saying out loud.

**The raw-cache write is the operator's expensive step**, several times the
whole cryptographic relay path. It is still 109x inside
the interval, so it is not a problem; it is the number to watch, because it is
the one that touches a disk and therefore the one that behaves differently on
an operator's hardware than in a container.

**The publisher's seal is the tight one.** At 9.5 ms it fits a 50 ms
cadence 5.3x over, which is real headroom, but the topology permits
intervals as short as 5 ms and at that cadence a publisher cannot keep up at
all. This is not a new finding -- it is PROD-18's open blocker -- and this
measurement is the current number for it.

**Concurrent publishers has no deployed value**, because no deployed command
constructs an uplink responder: `live/deposit` accepts an already-established
session, and the session limit is a parameter of `uplink.NewResponder` that
nothing in `cmd/` sets. The handshake cost is reported above so the figure is
available when the entry-operator role is wired up, and it is marked as off the
path because a cost measured for something nothing runs is a fact about the
code rather than about a deployment.

### What these numbers are not

- Not a soak. Nothing here runs longer than a few seconds, so none of it speaks
  to drift, leaks or degradation over weeks.
- Not deployment hardware. Every figure comes from a shared container doing
  other work concurrently. As upper bounds on a quiet machine they are useful;
  as predictions for a small operator's box they are not.
- Not a composed system. Each cost is measured in isolation, not with the
  scheduler, the socket and the cache contending for the same core.
- Not a capacity *target*. These are what the implementation costs today. An
  operator-facing target needs the soak and the hardware, both of which are
  EB-3 and time.

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
