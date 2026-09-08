# States, errors and timeouts

Normative. PROD-01 asks for state transitions, errors and timeouts in one
document rather than distributed across subsystem prose, because an
implementer building from a specification needs to know not only what the
bytes are but what a participant does when something does not arrive.

Every numeric value here is pinned by `live/spec/spec_test.go` in
nomad-testnet, which fails if the code and this document disagree. A
specification nobody checks is a specification that drifts, and this project
has already found two formats that were described wrongly (`PROTOCOL.md`, the
hop header and the topology). Values that come from the signed topology are
marked *policy*: they are chosen per deployment, and the document constrains
their range rather than their value.

## The rule every state machine here obeys

No transition may be taken because of private user activity, and no transition
may be taken *sooner* or *later* because of it. Where a subsystem must choose
between losing work and taking a private-dependent transition, it loses the
work. Where it must choose between stopping and taking one, it stops.

## Emission (operator)

One cell leaves per public interval. The interval and the lateness budget are
policy, from the signed topology's traffic class.

| From | Event | To | Note |
|---|---|---|---|
| Idle | interval elapses | Sealing | deadline is absolute, never `now + interval` |
| Sealing | cell sealed | Sent | |
| Sealing | transient local failure | Idle | cell lost, counted, **never** retried or deferred |
| Sealing | permanent local failure | Stopped | names the cause |
| Sealing | 4096 consecutive losses | Stopped | a condition that does not clear is not weather |
| Idle | emission ran past the lateness budget | Stopped | a catch-up burst would measure the stall |

**Transient** is an allowlist, not a denylist: `ENOBUFS`, `ENOMEM`, `EAGAIN`,
`EINTR`, `ENETUNREACH`, `EHOSTUNREACH`, `ENETDOWN`, a passed write deadline,
and a hop-sequence reservation that could not be written. Everything else is
permanent, including `EPERM` (a firewall verdict) and `EINVAL` (a destination
the kernel will never accept). An unrecognised error is permanent.

A lost cell returns its hop sequence number. The sequence is in the clear in
every header, so a number issued and discarded leaves a gap that counts local
failures for anyone watching the link.

The destination advances with the tick index, not with success: a failing peer
does not shift the rotation onto the working one.

## Reception (operator)

A datagram is refused at the first gate it fails, and each refusal is counted
under its own name. Nothing is stored before authentication.

1. wrong size → `wrong_size`
2. source is not a signed peer → `unknown_peer`
3. hop tag does not verify → `auth_rejected`
4. sequence outside the replay window → `replay_rejected`
5. not a work cell → dropped silently, no counter (cover is not an event)
6. cache refuses → `cache_rejected`
7. already held → `duplicate`
8. relay queue full → `queue_dropped`

The replay window holds the highest sequence seen and a 64-bit bitmap below
it. Above the highest advances the window; within 64 below is accepted once;
64 or more below is refused. Gaps are ordinary — sequences are allocated per
sender across all its peers.

## Hop and uplink sequences

Both are authenticated-nonce spaces and both behave identically. A range of
2^20 is reserved durably before any number in it is used, so a crash skips the
unused remainder rather than replaying it.

| Failure | Kind | Response |
|---|---|---|
| reservation could not be written | transient | lose the cell, keep the schedule |
| space exhausted | fatal | stop; rotate the epoch (hop) or establish a new session (uplink) |
| state unreadable or malformed | fatal | stop; **never** restart from zero |

Restarting from zero is the failure that looks like a fresh participant and
behaves like a replay, which is why the state is fail-closed rather than
self-healing. Restoring the state from a backup moves it backwards and is
worse than losing it; see `deploy/RECOVERY.md` in nomad-testnet.

## Publication (publisher)

| From | Event | To |
|---|---|---|
| Idle | object submitted | Queued (local only, no network) |
| Queued | queue full | Refused locally, no wire effect |
| Emitting | interval elapses, work available | work cell |
| Emitting | interval elapses, no work | cover cell, identical path and distribution |

The queue is drained by a separate clock into a one-slot buffer and the tick
does a non-blocking receive. The tick never asks the queue anything, so what
is emitted is a function of the clock and what it carries is a function of the
queue.

## Airlock epoch (entry operator)

| From | Event | To |
|---|---|---|
| Open | deposit arrives, slot free, session under quota | Open, slot filled |
| Open | batch full, or session quota reached | Open, deposit dropped **silently** |
| Open | cutoff reached | Closed |
| Closed | release boundary | Released: full batch shuffled and decrypted |

A dropped deposit returns success to the depositor. Telling it otherwise turns
the airlock's occupancy into something a depositor can probe. The batch is a
fixed size, real deposits and cover together, and the cover is built at a
public time so the release instant does not read out publication volume.

Period, cutoff, batch size and per-session quota are policy.

## Distributed key generation

Four phases of equal, policy-set duration, on a schedule in the signed
topology, so every participant changes phase at the same instant rather than
on receipt of a message.

| Phase | Ends when |
|---|---|
| Deal | phase duration elapses |
| Respond | phase duration elapses |
| Justify | phase duration elapses |
| Finalize | phase duration elapses |

A participant that has not received what it needs when a phase ends proceeds
without it. Waiting would make the schedule depend on message arrival, which
is an adversary's input.

Board transport: 3 s dial, 5 s request, 30 s idle, 100 ms poll.

## Epoch rotation

Preparation begins 6 h before the boundary, with retries at 1 h and 2 h after
a failure, escalating after 3 h. An epoch that has not been prepared by its
boundary does not roll: continuing on the current epoch is safe, and rolling
into an unprepared one is not.

## Topology acceptance

| Offered | Held | Result |
|---|---|---|
| epoch > watermark | any | accepted, watermark advances |
| epoch = watermark, same digest | same | accepted, an ordinary restart |
| epoch = watermark, different digest | same | **refused: equivocation** |
| epoch < watermark | any | **refused: rollback** |

Signature and validity alone do not make a topology current: an older one
inside its own window verifies perfectly, and replaying it is how a removed
operator or a rotated-away key returns. The watermark is durable, so the
refusal survives a restart.

## Release installation

The same shape, over versions: an offered release at or below the installed
version is a rollback and refused; two different artifacts claiming one
version are equivocation and refused rather than resolved. A release needs
approvals from at least two distinct trusted keys before any of this is
reached.

## Timeouts that are not policy

| Value | Where | Why fixed |
|---|---|---|
| 1 s | node socket read deadline | bounds shutdown latency, not a protocol event |
| 1 s | node health file interval | local observability |
| 4096 | consecutive-loss ceiling | a local condition that never clears |
| 2^20 | sequence reservation range | crash skips rather than replays |
| 64 | replay window width | bounded reordering |
| 2 s / 5 s / 5 s / 10 s | share service header, read, write, idle | HTTP server hygiene |
| 3 s / 5 s / 30 s / 100 ms | DKG board dial, request, idle, poll | as above |
| 3 s, 2 s | share and DKG shutdown grace | bounded shutdown |

## What this document does not specify

Session establishment for the publisher uplink. The shared secret is out of
band today because a publisher's ephemeral key does not fit in the cell, and
an in-band handshake is a wire-format change. See `DECISIONS.md` DEC-015.
