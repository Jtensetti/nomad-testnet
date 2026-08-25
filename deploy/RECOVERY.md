# Recovering a Nomad operator

Written from an exercise that runs, not from what recovery ought to look like.
`live/node/recovery_test.go` destroys each piece of a node's durable state in
turn and records what the code actually does; every claim below is what that
exercise measured.

A node has four pieces of durable state, and they do **not** recover the same
way. Two of them are unsafe to restore from a backup, which is the opposite of
the instinct an operator brings from every other service.

| State | Path in the runbook | Losing it | Restoring an old copy |
|---|---|---|---|
| Raw cache | `--cache` | Safe. Rebuilt from peers. | Safe. |
| Hop sequence | `--state` | Safe but noisy: the node restarts from zero and its peers refuse its traffic until the epoch rotates. | **Unsafe and silent.** See below. |
| Topology watermark | alongside `--state` | Loses rollback protection, nothing else. | **Unsafe.** Re-admits a removed operator or a rotated-away key. |
| Operator secrets | `--secrets` | The operator cannot participate. | Safe if the topology has not rotated past them. |

## A hung node does not resume, and that is correct

If a node is stopped and later continued — SIGSTOP/SIGCONT, a paused VM, a
host that froze — it does not carry on where it left off. While it was stopped
it missed its lateness budget by however long that was, and a fixed-cadence
sender that wakes up behind refuses to emit a catch-up burst. It exits.

`scripts/incident-drill.sh` exercises exactly this and confirms both halves:
the liveness gate detects the stopped node ("health file is 7.1s old: the node
stopped reporting"), and on resume the process exits rather than catching up.

**So recovery from a hang is a restart, not a resume.** Supervision has to
restart the unit; continuing the process leaves you where you were a moment
later. This is the privacy invariant costing you availability on purpose: a
burst that made up for lost time would be a measurement of how long the host
was frozen, emitted onto the wire.

## The one that will catch you: a restored hop sequence file

The hop sequence is a per-sender counter that peers use to refuse replays. It
is reserved ahead in blocks and persisted, so a crash *skips* numbers rather
than reusing them. That is correct and deliberate.

Restoring the file from a backup moves it **backwards**, and then the node
reissues numbers its peers have already seen. What the exercise measured:

> After restoring an older hop sequence file, the sender emitted 18 cells and
> reported 0 local drops — it cannot tell. The receiver counted 17 replays
> rejected over the same window.

Read that twice. The sending node's own health file says it is healthy:
`sent` climbs, `send_dropped` stays at zero, `last_sent_at` is current,
`nomad-node --check-health` passes. Every one of its cells is discarded by
every peer. **An operator watching only their own node cannot see this.**

Refusing the replays is right — that is the anti-replay control doing its job.
The gap is that the sender has no way to learn it, because nothing on the wire
comes back.

**So the signal lives on the receiving side.** Alert on a peer's
`replay_rejected` climbing steadily against one sender. A handful is ordinary
reordering; a sustained rise from a single peer means that peer's sequence
state went backwards.

**The remedy is to rotate the epoch, not to fix the file.** New pairwise keys
and a new epoch make old sequence numbers unusable, which is the only thing
that restores the sender's traffic. Do not attempt to hand-edit the counter
forward: you cannot know how far the peers have already seen.

**Prevention.** Exclude `--state` from ordinary filesystem backups, or restore
it only as part of a full epoch rotation. Losing the file outright is *safer*
than restoring an old one, because a node starting from zero is refused
immediately and consistently rather than intermittently.

**Why this hides.** The reservation on disk only moves when the node opens it,
so a backup and a restore either side of a single restart are the same bytes
and the restore does nothing at all. The damage needs a backup that is old
enough for the node to have restarted since — which is to say, every backup you
would actually restore from. A test that skips that detail concludes the
problem does not exist; `scripts/incident-drill.sh` made that mistake once
before it was fixed to restart in between.

The drill's measured result, with the shipped binaries on loopback:

> operator-a: sent=99 send_dropped=0 — and it passes `--check-health`.
> operator-b: replay_rejected 0 → 80.

## Restoring an old topology

`topology.AcceptMonotonic` refuses a topology whose epoch is below the highest
this node has served, and refuses two different topologies at the same epoch
rather than choosing between them. Both refusals survive a restart, because
the watermark is on disk.

That matters because an older topology is *perfectly signed* and inside its own
validity window: nothing about verification rejects it. Replaying one is how a
removed operator, or a peer whose key was rotated away, gets put back — by
restoring a stale directory rather than by forging anything.

Losing the watermark loses that protection without stopping the node. If you
have restored a state directory from backup and cannot account for the
watermark, rotate the epoch.

## Losing the raw cache

Unremarkable, which is worth stating so it is not treated as an incident. The
cache holds public replicated content, it is immutable and content-addressed,
and it refills from peers. Losing it costs the availability of what it held and
nothing else. The exercise restarts a node with the cache deleted and it comes
back emitting normally.

## Order of operations for a full rebuild

1. Stop the node.
2. Keep `--secrets`. Everything else can be rebuilt.
3. Delete the state directory rather than restoring it — see above.
4. Coordinate an epoch rotation with the other operators. This is the step
   that makes the node's traffic acceptable again; skipping it leaves a node
   that looks healthy and is ignored by every peer.
5. Start the node and confirm with
   `nomad-node --check-health=<health file> --max-silence=30s`.
6. Ask a peer operator to confirm their `replay_rejected` against you is flat.
   Your own health file cannot answer this.

Step 6 is not a formality. It is the only check that distinguishes a recovered
node from one that is emitting into a void.

## Running the drill

```
scripts/incident-drill.sh
```

It builds the real binaries, bootstraps a three-operator network on loopback,
and works both scenarios above with a pass or fail for each. No container
runtime, so it runs anywhere the tests do. Run it after changing anything in
the emission path, the health file, or this document — a runbook whose drill
has not been run since the code moved is a document about an older system.
