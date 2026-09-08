# Admission and rate control (v1)

Status: NORMATIVE for the release candidate. Feeds PROD-20 and Workstream G.

This states how Nomad bounds Sybil, eclipse, amplification, resource
exhaustion and abusive peers, and — equally important — where those bounds
stop. Several are architectural rather than statistical, which makes them
strong; the ones that are not are named as gaps rather than described
optimistically.

## The admission rule

**There is no peer discovery.** A node's outgoing peers are its own entry's
`PeerPlan` in the signed topology document; its incoming peers are exactly the
operators whose signed plans name it. Nothing at runtime — no message, flood,
restart or elapsed time — introduces a peer.

Membership therefore changes only by publishing a new signed topology inside
an epoch descriptor, and that requires the previous committee's approval
quorum: `max(previous.threshold, floor(members/2)+1)` distinct previous-epoch
operators, each signature bound to the approver's own key and to both the
previous and new descriptor digests.

## Admission on the publication uplink

The rule above is about *relay* peers, which are named. The publication uplink
is the other direction and the opposite case: an entry operator accepts
handshakes from parties it has never heard of and must never learn who they
are, so nothing there can be bounded per identity. Everything is bounded per
session and per source address instead.

**A session costs an ephemeral key and buys nothing but a session.** The
handshake is one-sided: the publisher authenticates the operator from the
`kex_key` in the signed topology and proves nothing about itself. What that
leaves to bound is state, and there are three bounds.

1. **A session budget, spent and never returned.** An operator establishes at
   most `SessionLimit` sessions for as long as it runs. The bound cannot be an
   occupancy: the responder has to remember every ephemeral key it has ever
   accepted, because a replayed handshake would otherwise establish a second
   session under the same key and therefore reuse that key's AEAD nonces. A
   structure that forgets in order to free a slot would trade nonce reuse for
   availability, so nothing frees a slot. An operator sizes the budget for the
   publishers an epoch is expected to carry; a service is restarted at each
   topology epoch, because the uplink context it was built with names one.
2. **A per-address session list, capped, refusing rather than evicting.** A
   data cell carries no session identifier -- one would be a linkable tag on
   every cell a publisher sends -- so a cell is attributed to a session by its
   source address, which is unauthenticated. A cell is tried against each
   session bound to its address, and offered to the responder as a handshake
   only if none of them open it. The list is capped, and a full one refuses:
   evicting the oldest would let anyone who can put a datagram on the wire with
   a victim's source address take that victim's session away. The cap is also
   what keeps the trial-open cost bounded, so a forged cell costs a fixed small
   number of AEAD opens rather than the whole table.
3. **A per-session slot quota in the airlock**, which is the bound on what a
   session can do once it has one, described under resource exhaustion below.

**A refusal is silent and fail-closed.** An exhausted budget, a full address
list, a cell that opens under no session: each ends in the same nothing. The
operator's counters separate a refused cell from a refused handshake because an
operator watching for an attack needs to tell them apart, but neither is
reported back to whoever sent the datagram, and no refusal changes what the
operator emits or when.

## What that buys, per threat

**Eclipse.** The usual route is out-populating a victim's neighbourhood so that
every peer it finds is yours. Nomad has no "finds": the peer set is a function
of a signed document. An attacker cannot become a peer by arriving, only by
being approved into a topology. Evidenced by
`TestNoRuntimeEventCanAddAPeer`, which floods a node from unnamed addresses and
with correctly sealed cells from the wrong socket, and requires the peer set to
be byte-identical afterwards.

**Sybil.** Identities are free, so the bound must come from what an identity
buys. Here it buys nothing: the node consults the signed document, never a
population. Sixty-four fresh identities change nothing
(`TestUnsignedIdentitiesGainNothingByExisting`). Sybil pressure is redirected
onto the governance process, where it belongs, and the cost of an identity
becomes the cost of persuading an approval quorum.

**Amplification.** A fixed-cadence sender emits on a public schedule, so the
harder an attacker pushes the lower the ratio goes. Measured outbound-over-
inbound bytes under four flood types: **0.00079, 0.00072, 0.00030, 0.00038**,
across floods of 124k–330k datagrams (up to 396 MB in for 118 KB out). The
test fails at 1.0, where a flood would have paid for itself.

**Resource exhaustion.** Every accumulator has an explicit, enforced bound:
per-generation symbol, byte, rank-attempt, work-unit, memory and lifetime
budgets in the decoder; a bounded relay queue; bounded immutable caches; a
fixed airlock batch with a per-session slot quota. Exceeding a budget ends the
generation rather than throttling it, because dropping work is preferable to
letting an attacker set the cost.

**Abusive peers.** Malformed, unauthenticated, misdirected, cross-epoch and
replayed datagrams are each rejected for their own reason and store nothing
(`TestHostileDatagramsAreRejectedForTheRightReason`). Rejection is cheap and
constant: authentication precedes any allocation.

## Rate control

Emission is not rate-*limited*, it is rate-*fixed*: one cell per public
interval, scheduled from a clock and never from load. There is no token bucket
to drain and no backpressure signal to observe, because a rate that responds to
conditions is a rate that carries information about them.

One qualification, stated here rather than only in the subsection below,
because it is the difference between a schedule and a claim about output: the
*schedule* is unconditional, but a scheduled emission can still fail to reach
the wire when the host cannot send it. What the sender must never do is let
that failure change the schedule -- no retry, no deferral, no catch-up, no
change to which peer the next tick addresses. A lost cell is a hole in the
output, not a shift in the cadence.

### What a local failure costs

"Whatever the load" has to survive the load actually breaking something. A
send can fail for reasons that have nothing to do with the protocol: socket
buffers exhausted (ENOBUFS), a local rate limiter refusing the datagram
(EPERM), a route withdrawn (ENETUNREACH), a full disk under the hop sequence
reservation. Every one of those used to return from the scheduler, and in the
live node that closed the socket: the node stopped emitting, permanently. The
loudest event a passive observer can see, from the quietest local cause.

A local failure now costs the cell it interrupted and nothing else. The cell
is lost -- never retried, never deferred and re-emitted, never followed by a
catch-up -- and the next emission lands on the absolute deadline it would have
had anyway. Which peer that deadline is addressed to also stays a function of
the tick index and the signed plan, so a failing peer does not shift the
rotation. Only a closed socket still ends the schedule, because a node ticking
against a socket that is gone is a node emitting nothing while reporting
nothing wrong.

That trade removes an alarm, and the alarm has to be replaced rather than
lost: a process that is up, on cadence, and silently dropping every cell is
invisible to a supervisor that only asks whether the process is up. The node
publishes `send_dropped` and `last_sent_at`, and `nomad-node --check-health`
fails a node that has not emitted inside a deployment-set window. Both values
are things an observer on the link reads directly off the wire, so publishing
them concedes nothing.

## Where these bounds stop

- **Fair access under Sybil.** A per-session quota stops one uplink session
  taking a whole airlock batch, but an attacker holding many *authenticated*
  sessions still competes for slots on equal terms with honest publishers.
  Nothing here allocates scarcity fairly; it only stops one client monopolising
  it.
- **Availability under flood.** Amplification is bounded and the peer set is
  fixed, but a sufficiently resourced attacker can still push a
  resource-constrained node past its lateness budget, at which point it stops
  emitting — correct fail-closed behaviour, and a denial of service. Measured:
  a replay flood shifted median cadence by 5.5% on a two-core host against
  0.7% on an eight-core one, with deadline misses on the smaller machine. A
  local *send* failure no longer does this (above); a missed lateness budget
  still does, and deliberately so, because emitting late is emitting a
  measurement of the host.
- **Coded-symbol pollution** cannot be prevented pre-admission with GF(2^8)
  coding and peer re-encoding; see `POLLUTION_AND_RESOURCES.md`. Budgets bound
  the cost, not the availability loss: at 50% or more malicious symbols a
  generation still fails to complete.
- **Governance capture.** Redirecting Sybil onto the approval quorum is only a
  gain if the quorum is genuinely independent. Five operators run by one
  administrator are one trust domain, and that is PROD-05 and EB-2, not
  something this document can establish.
- **Uplink session budget exhaustion.** The session budget above is a
  denial of service an attacker can buy cheaply: `SessionLimit` valid
  handshakes, each costing one ephemeral key, and the operator establishes no
  further sessions until it restarts. This is accepted rather than solved. The
  alternative is a responder that forgets accepted ephemeral keys in order to
  reclaim slots, and that reopens handshake replay onto a live session's
  nonces -- trading a bounded availability loss for a key-reuse break, in the
  direction the invariant forbids. What bounds the damage is operational: size
  the budget with headroom, and restart at topology-epoch boundaries, which a
  deployment does anyway. What is *not* established is a figure for that
  headroom against a real publisher population, which is the same missing
  deployment parameter as the bullet below.
- **Source-address binding.** Attributing a cell to a session by its source
  address is a decision about an unauthenticated value. The per-address cap
  keeps that from taking an established session away, but whoever binds an
  address first still holds it: an attacker that fills a victim's address with
  handshakes before the victim arrives locks the victim out of that operator
  for the epoch, silently. A publisher configured with a different entry
  operator is unaffected, and choosing one is a configuration decision, never a
  runtime response -- so there is no failover here and deliberately so, since
  failover triggered by a lockout would be publication activity steering an
  observable network event.
- **No economic analysis.** PROD-20 asks for economic as well as operational
  analysis. The operational side is above; costing an attack in money against
  a real deployment is not written, and needs deployment parameters that do
  not exist yet.
