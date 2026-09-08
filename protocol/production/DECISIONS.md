# Decision log

Engineering decisions with rationale. Newest first.

## DEC-029 (2026-09-03): The uplink session budget is spent and never returned, and its exhaustion is accepted

An entry operator's responder holds a `SessionLimit` and remembers every
ephemeral key it has accepted. Nothing frees a slot, so the limit is a budget
spent for the life of the process rather than an occupancy. That makes it a
denial of service an attacker buys with `SessionLimit` valid handshakes, each
costing one ephemeral key, after which the operator establishes no further
sessions until it restarts.

The decision is to accept that rather than solve it, and to write it down.

Reclaiming a slot means forgetting an ephemeral key. A responder that forgets
one it has accepted will accept a replay of that handshake, which establishes a
second session under the same key -- and the session's AEAD nonces are derived
from a sequence that restarts, so the second session reuses the first's nonces
under the first's key. Captured data cells could then be replayed into it and
deposited again. That is a key-reuse break traded for an availability gain, in
the direction the invariant forbids: availability loses to a privacy or
integrity property, not the other way round.

The rejected alternatives, and why each fails on the same point:

- **Expire sessions by time.** Expiry is forgetting with a clock in front of
  it. The replay window narrows; it does not close.
- **Bind the handshake to the release epoch and roll the memory with it.** This
  works -- a replayed handshake in a later epoch derives a different key, so
  there is no nonce reuse -- and it costs a wire-format change: the handshake
  derivations are frozen `-v1` labels with a published compatibility matrix and
  a second implementation reading them. The gain is availability under an
  attack no deployment has yet run, against a freeze that exists so a second
  implementation can be written. It stays on the table for a `-v2` uplink
  profile and is not worth breaking the freeze for now.
- **Rate-limit handshakes per source address.** Source addresses are free, so
  this bounds nothing an attacker cannot buy around, and making the operator's
  behaviour depend on a rate would give it a state an observer can drive.

What bounds the damage is operational and is now normative in
`docs/ADMISSION_AND_RATE_CONTROL.md`: size the budget for the publishers an
epoch is expected to carry, with headroom, and restart at topology-epoch
boundaries, which a deployment does anyway because the uplink context names one
topology epoch. What is not established is a figure for that headroom against a
real publisher population; that needs the same deployment parameters PROD-20's
economic blocker needs.

The related decision, taken at the same time, is that a full per-address
session list **refuses rather than evicts**. Eviction would reintroduce the
lockout the per-address list was added to remove -- an attacker filling a
victim's address would push the victim's live session out -- so a full address
is a refusal, and refusing is silent and fail-closed like every other refusal
on this path.

## DEC-028 (2026-09-03): Sphinx is not adopted for the hop envelope, and cross-test vectors against it would not mean anything

The plan asks whether Nomad's hop-by-hop envelope should use, or be
compatibility-tested against, established Sphinx constructions, naming six
properties: fixed packet geometry, unlinkable hop routing, padding, replay
resistance, domain separation and cover packet indistinguishability. The fork
studied is `Jtensetti/nym-vendor` at `common/nymsphinx` (Apache-2.0, so unlike
the Katzenpost study this one is not a licence question).

The two constructions answer different questions, and that is the decision.

Sphinx is a source-routed onion. The sender picks the path, layers the packet
so each hop learns only its predecessor and successor, and per-hop
unlinkability comes from re-randomising a group element in the header. Its
value is hiding the route from the relays that carry it.

Nomad does not have a route to hide. Peer selection comes from the signed
topology's public plan, and the core invariant requires exactly that: peer
selection must not depend on private state, so it is public by construction and
identical for every cell. What Nomad's envelope does instead is encrypt the
whole cell under a pairwise link key, with a fresh per-link sequence, so a cell
relayed onward shares no bytes with the cell that arrived. Content privacy
comes from the anytrust mix; traffic privacy from the fixed cadence. Neither
depends on the relay being ignorant of the path.

Adopting Sphinx would therefore import a header construction to solve a problem
this design has arranged not to have, and it would cost on the first property
named. Nym runs five packet sizes -- a 2 kB regular packet, an ack packet, and
extended packets at 8, 16 and 32 kB, plus outfox variants -- and which size a
client sends is observable and correlates with what it is doing. Nomad has one
cell size, always, whatever a cell carries. On fixed packet geometry the
existing design is stricter than the reference, and moving to it would be a
regression rather than a hardening.

Each of the other five properties is already implemented and tested here:
unlinkable hop routing by `TestARelayedCellDoesNotCarryItsStreamIDOnward` and
`TestTheSameStreamAtTwoHopsSharesNoBytes`; padding and geometry by the constant
cell size, which every capture check asserts; replay resistance in the node's
replay window; domain separation by the labelled key derivation
(`nomad-hop-link-stream-v2`, `nomad-hop-cell-v2`), with
`TestAnUnrecognisedVersionIsRefusedRatherThanDowngradedTo` refusing a version
rather than falling back to it; and cover indistinguishability by
`TestSealedWorkAndCoverAreIndistinguishable` and the two classifiers in
`live/uplink/distinguisher_test.go`. The header-encryption work these last
tests exist for was itself prompted by measuring two distinguishers that
version 1 left open, so this is not an untested assertion of equivalence.

Compatibility testing against Sphinx is rejected on the same grounds rather
than deferred. A cross-test vector is only meaningful between two
implementations of the same construction. Nomad's cell is not a Sphinx packet
and is not meant to become one, so a vector shared with nymsphinx would either
fail trivially or be constructed to pass, and neither says anything. The
cross-implementation evidence that does mean something already exists and is a
different thing: the conformance corpus and the second implementation, which
share no Go code with the first and are built from the specification.

The plan's own instruction -- avoid a large Rust FFI dependency where a small
verifiable Go implementation with cross-test vectors is safer -- points the
same way, and the size argument is secondary to the design one. The primary
reason is that the construction does not fit; the dependency cost is why it is
not worth doing anyway.

What would change this: if Nomad ever needed sender-chosen routing, or a reply
mechanism like a SURB, the analysis would have to be redone, because both are
properties Sphinx has and this envelope does not. Neither is in the protocol
today, and adding either would be a change to the invariant's peer-selection
rule before it was a change to the packet format.

## DEC-027 (2026-09-02): the Linux client is built and verified, and is not offered as a release

`linux-release.yml` had never run (F-29), so the question of how a Linux
artifact reaches anyone had never come up. Fixing the trigger makes the build
run; it does not answer the question, and the two should not be conflated.

What is true now: the Linux client is built reproducibly for amd64 and arm64
on every push that touches it, its networkless claim is verified on every push
by `scripts/verify-networkless.sh`, and a tarball, SBOM and provenance are
produced as run artifacts.

What is not true: `docs/RELEASE_PROCESS.md` describes a macOS release
throughout -- `NomadBrowser-X.dmg`, notarization, the two-approval manifest
verified by `nomad-browser-verify` -- and never mentions Linux. There is no
tag convention for a Linux release, no manifest, and nothing that would let a
user verify a Linux artifact the way the macOS process lets them verify a DMG.

The decision: the Linux client stays a build target and a test subject, and is
not offered as a release, until the release process covers it. The alternative
-- publishing the tarball because the workflow now produces one -- would ship
an artifact with no approval path and no verification story to the platform
whose whole argument is that its claims are checkable. A build artifact
attached to a CI run is not a release, and nothing here should let the two be
confused.

What that costs: PROD-26 and PROD-30 remain macOS-shaped, and the Linux
client's strongest property -- the network namespace with no interface to
refuse -- reaches nobody outside this repository. Extending the release
process to Linux is the work that changes it, and it is a decision about what
this project offers rather than an engineering gap.

**Amended 2026-09-02 (`Nomad-browser` `79ad4da`).** That work is done. The
release process now has a Linux section -- tag convention, the absence of any
notarization equivalent so the two approvals carry the whole authenticity
story, the same verifier command, and that a release publishes both
architectures or drops a platform -- and `update/linux_release_test.go`
exercises the mechanism with a real tarball rather than leaving it neutral by
construction and untested.

The decision itself is unchanged: nothing has been offered to anyone, and the
client stays a build target until someone decides to offer it. What has changed
is that the process no longer prevents that decision, which is what this entry
said was needed.

## DEC-026 (2026-09-02): Windows keeps its build target and stays unsupported for operators

The first Windows CI run showed that every mutation of the epoch chain store
fails there. The cause is not a bug in the store: `os.File.Sync` on a directory
handle is `ERROR_ACCESS_DENIED` on Windows, because Windows has no equivalent
of fsync on a directory. Nine places in nomad-testnet did that flush, each with
its own copy of the code, and all nine failed the same way.

`live/durable.Directory` is now the only copy, and its Windows implementation
does not flush. Two ways to read that, and this records which one is meant.

It is **not** a bypass of a check. Directory fsync is a durability primitive,
not a verification: nothing is being accepted that would otherwise be refused,
and the validation around it -- a missing path, a path that names a file -- is
identical on both platforms deliberately, so a Windows build never accepts
input a unix build rejects.

It **is** a weaker guarantee. On unix a rename becomes durable when the
containing directory is flushed. On Windows that step is absent and durability
rests on NTFS metadata journaling, which this project has not measured.

The decision: Windows stays in the build matrix, its epoch tests run in CI so
the platform-specific paths execute, and it remains not a supported platform
for running an operator. What is deliberately **not** done is a runtime guard
making the operator binaries refuse to start on Windows. That would be the
fail-closed move if Windows were being offered to operators; it is not, the
registry says so, and adding a refusal would also stop the tests that just
found this. If Windows is ever offered as an operator platform, the guard is
the work that has to happen first, and this entry is the record that it was
considered rather than missed.

## DEC-025 (2026-09-02): the signature journal's role separation is not tightened here, and why

`epoch.Journal` keys each recorded signature by (network, epoch, role), where
role is `activation` or `approval`. Writing the first test for
`ApproveWithJournal` -- which had none, while the activation path did -- raised
a question the tests cannot settle: dropping `role` from the key leaves every
test green.

**The role is not load-bearing in any reachable flow.** Both roles record
`Digest(descriptor)`, so activating and approving the *same* descriptor is
idempotent with or without the role. And in the normal flow the epoch numbers
already differ: an approval signs a successor, whose embedded epoch is one past
the descriptor an operator activates, so the two never collide on the key.

**A role-less key would be strictly stronger.** It would additionally refuse
the case the current key permits: one operator activating descriptor D1 for
epoch N and approving a different descriptor D2 for the same epoch. That is
two distinct endorsements for one epoch by one operator, which is exactly the
split-brain `ErrConflictingSignature` exists to prevent -- and the role
separation lets it through.

**It is not tightened here.** Making a fail-closed mechanism stricter can halt
a legitimate operation, and the flow this would have to be safe against is a
recovery path -- re-proposing at the same epoch after a failed activation --
that this session has not traced end to end. A wrong tightening here does not
lose a signature; it stops an operator signing at all, during exactly the
incident where signing matters.

So the finding is recorded rather than acted on, with the mutation left alive
and labelled at the test that cannot kill it, because a mutation that survives
and is documented is honest where a test contrived to kill it would not be.
Planner, implementer and evaluator were the same session again; this is the
kind of change that needs the second reader the process asks for.

## DEC-024 (2026-09-02): the publisher applies its own deposit bound; confirmation-driven re-submission is rejected

DEC-022 closed the deposit window as a loss term and named what it left open:
work is still lost when the epoch is full, when a per-session quota is
exhausted, or when a datagram is dropped. It proposed re-submission as a fresh
publication, "decided by the publisher failing to observe its own object in a
release". Building it starts with measuring the three terms, and the second one
turned out not to need any feedback at all.

**The quota term was the large one, and it is a publisher-side bug.** Every
in-window cell a session emits is a deposit, cover included -- the entry
operator cannot tell them apart, so it charges both against
`MaxDepositsPerSession`. At the deployed defaults a publisher emits roughly
1,800 cells into a 45-second window and the airlock accepts 8 of them. The
drain took work from the queue on every one of those ticks, and `Queue.Next`
unlinks as it hands out, so every work fragment after the eighth was destroyed:
silently, by the publisher itself, for a bound it could have read.

The bound is public policy in the signed epoch descriptor, the same bytes the
operator reads it from. `deposit.Drain` now counts the in-window cells it has
emitted in the current release epoch and stops taking work once the bound is
spent, exactly as it stops outside the window. The fragment stays on the queue
for the next epoch instead of being unlinked and refused. Nothing about the
emission changes: one cell per tick either way, cover in place of the work it
declined, sealed identically, no sequence repeated.

Measured before and after on the deposit path: with a bound of 2 and six
queued fragments, the drain emitted six work cells of which the airlock
accepted two and destroyed four; it now emits exactly two.

**Confirmation-driven re-submission is rejected.** The shape DEC-022 sketched
is an active-tagging channel against the party the two-layer construction
exists to blind.

An entry operator that drops one session's cells in epoch E, and watches the
release of E+1, sees any object that appears there and not in E. Under retry
that object is the one whose publisher noticed it missing -- so the operator
has linked an object to the set of sessions it chose to drop, and to a single
session if it dropped one. The mix hides which column is whose; a retry
decided by the outcome hands that back, because the operator controls the
outcome.

It does not help to spread the retry over epochs, or to randomize it: the
operator can repeat the experiment. Nor does fixed cross-epoch redundancy,
which was the obvious invariant-safe alternative -- with each object scheduled
into epochs E and E+1, dropping a session in E leaves exactly the objects it
dropped appearing in E+1 alone, which is the same inference through a
different door.

The property that fails in all of these is the same: an object's presence in a
release must not depend on whether it was present in an earlier one. Any
mechanism that makes it depend on that is readable by whoever controls
presence.

**So the three terms are answered separately, and two are not answered.**

- Per-session quota: fixed publisher-side, above. No feedback, no new
  observable.
- Full epoch: not fixable. The publisher cannot learn the batch occupancy, and
  DEC-022 already records why telling it would be worse than the loss.
- Transit loss: not fixable without an acknowledgement, and an acknowledgement
  is the signal.

Republication remains available and remains a decision made outside the
protocol: submitting the same object again produces the same fragment IDs,
takes fresh sequences and fresh seals, and is indistinguishable from a first
publication. What is refused is the automatic version, where the decision is a
function of something an adversary can set.

Planner, implementer and evaluator were again the same session. The rejection
argument above is the part most in need of a second reader, as DEC-022's was.

## DEC-023 (2026-08-31): the networkless client and a loopback model service cannot be the same build

Semantic search needs an embedding model. The architecture for attaching one is
now in place (nomad-semantic-basins basin/model, Nomad-browser search), and
implementing it surfaced a fork that has to be decided rather than left to
whoever wires a model up first.

**The two ways to run a model.** In process, through a runtime linked into the
binary. Or out of process, through the sealed loopback service in
basin/loopback, which is what PROD-24 built and which keeps multi-gigabyte
weights out of the address space that holds verified object bytes.

**Why the second is not available to the Linux client.** That client's central
claim is that it cannot reach the network, and the claim is asserted over its
transitive dependency graph: no net, no net/http, no crypto/tls, and no os/exec
either. A loopback service needs a socket, so linking a client to one makes the
claim false. Starting the service as a subprocess needs os/exec, which is
excluded for the same reason. There is no arrangement in which the networkless
client talks to a local model server and remains networkless.

**Decision.** The two are separate builds, and neither pretends to be the other.

- The networkless client ranks lexically until an in-process runtime exists,
  and says so in its banner rather than letting a word match read as an
  understanding of meaning.
- A build that wants the loopback service opts into the socket explicitly and
  cannot claim the dependency-graph guarantee.
- Verification is deliberately separated from inference. cmd/nomad-model hashes
  files and reads a manifest, needs no runtime, and therefore links neither a
  network stack nor os/exec -- so a reader can check what a pack is without
  giving the checker the capability the pack itself may need.

**What is not decided.** Which in-process runtime to adopt. A cgo GGUF or ONNX
runtime would put a large native dependency inside the most safety-critical
process in the system, and that needs its own dependency-graph assertion and
its own review before it is chosen. Recording the fork now so that the choice
is made deliberately rather than arrived at.

## DEC-022 (2026-08-28): DEC-020's retry is rejected; the publisher does not emit work into a shut window

DEC-020 recorded that a publisher destroys a fixed share of its work every
epoch and specified the shape of a fix: retain the sealed cell, retransmit it
verbatim, choose between retransmitting and fresh cover from the public
schedule alone. Implementing it found that the shape does not hold, on a
ground DEC-020 did not consider.

**Why verbatim retransmission cannot be used.** An uplink cell is eight
cleartext sequence bytes followed by one authenticated ciphertext
(live/uplink/session.go). The sequence is durable and strictly increasing
(live/uplink/sequence.go). Retransmitting a cell verbatim therefore repeats a
cleartext value on the wire, an epoch after its first appearance. Cover is
never retransmitted, because there is no reason to. So the repeat is a
reliable signal that this publisher had a work cell refused -- readable by a
passive observer and, more importantly, by the entry operator, which is the
party the two-layer construction exists to blind. That is private activity
modulating an externally observable event, which the core invariant forbids
outright. The airlock's idempotence does not help: it makes the second deposit
harmless to the batch, not invisible on the link.

**Why re-sealing is worse than DEC-020 said.** DEC-020 describes re-sealing
the same fragment as producing a different payload that the airlock refuses as
a conflict. It is also an AES-GCM nonce reuse: the nonce is derived from the
sequence, so sealing twice under one session key and one sequence encrypts two
different plaintexts under one key and nonce, giving their XOR and, through
GHASH, the authentication key. The airlock's refusal arrives after the cells
are already out. `deposit.Drain` now refuses a repeated sequence before
sealing, with `ErrSequenceReused`, in the one place that holds the state to
see it.

**What is implemented instead.** The publisher does not hand work to the
emission path while the deposit window is shut. The window is public schedule
policy anchored to the signed topology, so publisher and operator derive the
same boundaries from the same bytes. `deposit.Drain` takes an
`airlock.Schedule`, the filling goroutine does not call `Queue.Next` outside
the open window, and `Emit` leaves a buffered fragment alone and seals cover.

This satisfies every constraint DEC-020 named, and one it did not:

- the emission rate does not change -- one cell per tick either way, sealed
  identically, and no sequence is ever repeated;
- the decision depends only on the public schedule and the clock, never on
  feedback from the operator, of which there is none;
- what is retained is bounded, at the one slot the buffer always had;
- nothing is retransmitted, because nothing was sent.

**What it does not fix.** Work is still lost when an epoch is full, when a
per-session quota is exhausted, or when a datagram is dropped in transit. The
publisher cannot detect any of these -- by design, since an acknowledgement
would be the signal. The mechanism for those is re-submission as a *fresh*
publication: a new sequence and a fresh seal, indistinguishable from a first
publication, decided by the publisher failing to observe its own object in a
release. That needs the read path, is not implemented, and is not claimed.
The window closure was the dominant term -- 25% of every period at the default
schedule, 38-43% measured at a three-second period -- and it is now zero.

**Loss on shutdown.** At most one fragment, whatever sits in the one-slot
buffer, and it is gone: `Queue.Next` unlinks as it hands out and nothing puts
a fragment back. Holding it across a restart to emit later would be catch-up
traffic, which is the worse failure. Recorded as accepted, not as fixed.

Planner, implementer and evaluator here were the same session, which is a
weaker separation than the process asks for. The evaluator pass is recorded
as QA, not as independent review, and the rejection of DEC-020's shape is the
part most in need of a second reader.

## DEC-021 (2026-08-28): CI actions stay pinned by digest, at v7

The 2026-08-24 to 2026-08-28 Actions outage was an account spending limit
(EB-8), not an unresolvable action reference. This session concluded the
opposite mid-outage and downgraded actions/checkout and actions/setup-go from
v7 to v4.2.2/v5.3.0 across nine repositories on that false premise.

Digest pinning is kept, because a project that verifies its own dependency
digests should not run CI actions from a floating tag. The versions are moved
back to v7.0.1 and v7.0.0 -- what the workflows used before the outage, proven
by nomad-testnet 32301972409 -- which also clears the Node 20 deprecation
warnings the downgrade introduced. actions/upload-artifact and
actions/download-artifact are pinned to the digest of the v4 they already
floated on; their major version is deliberately not changed here, since
nothing indicates a problem with it and the artifact pair must stay matched.

The correction is recorded in EXTERNAL_BLOCKERS EB-8 rather than by amending
the commits, which are published and referenced.

## DEC-020 (2026-08-27): A refused deposit destroys publication work, and only a retained sealed cell can retry

Running the publication path as separate processes for the first time showed
that a publisher loses a fixed share of its work every epoch, silently, and that
neither side reports it.

The mechanism. A publisher emits at a constant cadence, by design, whether or
not it has work and whether or not anybody is listening. The airlock's deposit
window closes before the release boundary, by design, so the shuffle chain and
threshold decryption have a fixed budget. The two are independent, so every cell
emitted between the cutoff and the next epoch is refused. Measured across real
processes: 38-43% of cells in a short run at a three-second period; at the
default one-minute period with a fifteen-second cutoff it is 25% of every
period in steady state.

Being refused would be harmless if the publisher could send the work again, and
`PUBLICATION_AIRLOCK.md` says exactly that: deposits are idempotent so "a client
that cannot tell whether its uplink cell arrived -- and it cannot, since the
uplink carries no acknowledgement that would distinguish work from cover --
resends freely". The idempotence is real. What the specification does not say,
and what decides whether the property is usable, is *what* a client has to keep
in order to resend.

Two candidates, and only one works:

- **Retransmitting the byte-identical sealed cell** is idempotent. The airlock
  recognises the payload as one it already holds and consumes no second slot.
- **Re-sealing the same fragment** is not. The inner layer is a fresh
  encryption to the committee on every seal, so the second attempt presents a
  *different* payload for a held deposit slot, and the airlock refuses it as a
  conflict. It is right to refuse: a different payload for a held sequence is
  indistinguishable from an overwrite attempt, and resolving it silently would
  drop whichever publication lost.

The implementation keeps neither. `publish.Queue.Next` removes the fragment from
disk as it hands it out, and `deposit.Drain.Emit` seals it and retains nothing.
So the retry the airlock's idempotence exists to support cannot be performed at
all, and a work cell refused for any reason -- a closed window, a full epoch, a
datagram lost in transit -- is publication work destroyed.

This is recorded rather than fixed, deliberately. The fix changes what the
publisher holds and when it emits, which is the component the core invariant
constrains most tightly, and a wrong fix here is worse than the defect: the
obvious one -- keep the fragment and seal it again -- is precisely the case the
airlock refuses. Designing it, implementing it and judging it in the same breath
as discovering it is what the planner/implementer/evaluator separation exists to
prevent.

The shape a fix has to fit: the publisher retains the sealed cell rather than
the fragment; it retransmits it verbatim; the choice between retransmitting and
sealing fresh cover depends only on the public schedule and the publisher's own
queue, never on feedback from the operator, because there is none and inventing
one would be a private-state-dependent signal; the emission rate does not change,
since one cell goes out per tick either way; and what is retained is bounded,
because an unbounded retry buffer is a memory leak in the process that holds the
publication queue.

Two smaller things came out of the same run. Re-sealing produces different bytes
on the wire, so a retransmission is not distinguishable from any other cell by
repetition -- a concern worth checking and, having checked it, not a finding.
And `live/entry`'s first counters could not express any of this: one called
"deposited" counted cells the airlock had silently dropped, and one called
"refused" mixed authentication failures with cells that merely arrived outside a
window. A counter that cannot distinguish an attack from a schedule is not
instrumentation.

## DEC-019 (2026-08-26): Descriptors are distributed through a transparency log, and an unwitnessed chain cannot reach a publisher verdict

PROD-15's open blocker was that the recovery drill's step 6 showed a reader who
had not seen a recovery still accepting the attacker, with nothing bounding how
long that lasted. The chain already made rollback and equivocation detectable by
a verifier that sees both branches; what was missing was anything that made
anyone see both branches.

Descriptors now go into an RFC 6962 append-only log. A verifier accepts a
descriptor only with an inclusion proof against a checkpoint it has verified,
moves between checkpoints only with a consistency proof from the size it itself
holds, and stops issuing a publisher verdict once its checkpoint is older than
its freshness window.

Three choices in this are worth recording because the obvious alternative was
worse:

*The gate is structural, not advisory.* A chain built without a log view can
never return PUBLISHER_VERIFIED, and the witnessed and unwitnessed append paths
refuse to do each other's job. The alternative -- an optional distribution
argument -- would have meant that any deployment that forgot to wire it up
silently returned to exactly the unbounded case PROD-15 describes. That is the
kind of fallback the engineering rules forbid, and it would have been invisible
in precisely the deployments that needed the property.

*The freshness gate sits on the positive verdict only.* A contradicted claim is
still reported PUBLISHER_INVALID when the reader's log view is stale. Gating
the whole of Resolve would have traded a true negative for an absence, which is
strictly worse for the reader: it would tell someone "unknown" about a
publication the reader can prove is wrong.

*Distribution must not observe what a reader reads.* The obvious implementation
fetches a checkpoint or a proof when a user opens a site, which makes an
observable network event depend on private activity and violates the core
invariant outright. Instead the inclusion proof travels with the publication
over the same path as the object, and checkpoint refresh runs on a fixed cadence
that does not depend on what anyone is reading. It follows that a failed refresh
is never retried harder because a user is waiting -- that would be the
private-state-dependent catch-up traffic the invariant rules out. A reader whose
refresh fails goes stale and says so.

What this does not do is make the log honest. A log that signs two heads at one
size has equivocated, and the implementation produces transferable evidence
rather than preventing the act. Preventing it needs more than one log or
cosigning witnesses, which is a deployment decision and is recorded as an open
item rather than claimed.

Two defects were found and fixed while building it, both worth naming. Both
proof verifiers consumed the proof path root-to-leaf while the prover emits it
leaf-to-root, as RFC 6962 specifies; this passed a hand-traced example whose
decision sequence happened to be a palindrome and failed the exhaustive
all-sizes test. And the RFC 6962 split was computed by a doubling loop that
overflows on a size near the top of the uint64 range, after which the counter is
negative, the comparison never ends and the verifier spins forever allocating --
a denial of service reachable by anyone who can hand a reader a document, since
sizes come out of proofs.

## DEC-018 (2026-08-26): The uplink session is established in band, one-sided

The publisher read a shared secret from a file and the entry operator read the
same bytes from its own. That is a real deployment and it needs a channel that
distributes a per-publisher secret to a named operator before anything can be
published -- a channel that knows who publishes what, which is the fact the
whole airlock exists to keep from existing.

DEC-015 deferred this on the grounds that the 1200 bytes were spent and an
in-band handshake was a wire-format change. Two things changed that. The
wire-format cost was paid anyway for DEC-016, so the corpus and the second
implementation were already being regenerated. And the premise was wrong in a
way worth naming: it assumed the handshake had to fit *alongside* a fragment.
It does not. The first cell of a session carries the introduction instead of a
fragment, at the cost of one cell per session, and on the wire it is 1200 bytes
with an 8-byte counter like every other cell.

**One-sided, deliberately.** The publisher authenticates the operator against
the `kex_key` in the signed topology and proves nothing about itself. The
instinct is to make a handshake mutual; here mutual authentication would hand
the entry operator exactly the identity it must not have. Its only guarantee is
that somebody who verified the topology is speaking to it, and everything that
bounds abuse afterwards is per session.

**The session secret goes through the unchanged derivation.** The handshake
produces the same thing the file used to: 32 bytes fed into
`nomad-uplink-session-v1`. The data path, its published vectors and its second
implementation do not move because the way the secret is obtained changed.

**Three separated domains, and the reason is not symmetry.** The session
identifier is public -- the airlock derives deposit slots from it, so it appears
in state an operator can see. A domain collision between it and the session
secret is a one-character edit that publishes key material. It is a distinct
domain, and a test requires all three derivations to differ, because that is
the kind of defect no round-trip test notices.

**What was rejected:** an unauthenticated first cell with the key in the clear
and no tag (nothing binds the introduction to the epoch); a mutual handshake
(gives the operator an identity); and putting the ephemeral key in the 24 bytes
of existing padding (it does not fit, and shrinking the inner ciphertext to make
it fit would change the mix layer for the benefit of the link layer).

## DEC-017 (2026-08-26): The canonical topology encoding is specified, not inherited

The bytes every topology signature is computed over were the output of Go's
`encoding/json` on the reference implementation's structs. That is not a
specification, it is an implementation detail that happened to be reachable
from another language if you described it carefully enough — which the second
implementation did, and recorded as a defect while doing it.

**Specified instead:** members sorted by UTF-16 code unit, no whitespace,
minimal string escaping, integers only, an absent array as `[]`. Close to
RFC 8785, stricter about numbers: a fractional or exponential literal is
refused rather than given a canonical form, because every number in a Nomad
signed document is an integer and refusing the rest removes the entire
floating-point half of JCS.

**Two of the three inherited quirks were live.** Struct-declaration order meant
inserting a field in the middle of a struct would silently change the signed
bytes of documents that had not otherwise changed. An absent array as `null`
was the same class of accident.

**The third was latent, and that is the more interesting one.** Go's escaping
of `<`, `>` and `&` could not be reached by any valid document: every
free-form string in a topology is constrained by a pattern, a URL parser, an
RFC 3339 parser or base64, and none of those alphabets contains those
characters. The defect was real and unreachable at the same time. It is fixed
anyway, and a test pins the unreachability so that loosening a field turns
into a failing test rather than into two implementations disagreeing about a
signature. "The encoding is wrong but validation keeps the difference out of
reach" is two invariants pretending to be one, and only one of them is
written down anywhere.

**Cost:** the signed bytes changed, so the corpus was regenerated and the
second implementation ported — for the second time in one session, after
DEC-016. That is the cost DEC-015 was trying to avoid paying twice. Paying it
twice took an afternoon, and the alternative was carrying two known-wrong
formats into a freeze.

## DEC-016 (2026-08-26): The hop cell is encrypted per link. Supersedes half of DEC-015

DEC-015 deferred two wire-format questions to the freeze on the grounds that
each would invalidate the conformance corpus and the second implementation, and
that spending that cost twice was worse than spending it once. The reasoning
was sound and the conclusion was wrong for the first of the two, for a reason
DEC-015 did not weigh: the freeze is what the deferral was waiting for, and the
unencrypted header was itself a blocker on the freeze. Deferring a change to
the moment that the change is a precondition for is not a deferral, it is a
deadlock.

**Taken now: the hop cell is encrypted under the pairwise link key** — the
whole cell, payload and routing metadata, not only the header. Encrypting the
header alone would have left the second distinguisher in place: a work cell
carries mix ciphertext, which parses as compressed group elements, while a
cover cell is uniform random, and that separated the two perfectly without
reading a single header byte.

The cost DEC-015 named was paid rather than avoided. The corpus was
regenerated, the second implementation was ported, and both directions of the
cross-implementation check pass on the new format. That cost turned out to be a
day's work and it bought the evidence back: porting the second implementation
found a real specification gap (the two encrypted regions are not contiguous,
so "encrypt the payload and the metadata" has two readings that produce
different bytes), which is exactly what the second implementation exists for.

**The keystream is HMAC-SHA-256 in counter mode, not a block cipher.** That is
a protocol decision. It means an implementation needs SHA-256 and nothing else
to speak this format, which the second implementation demonstrates by being
written against the Python standard library, where there is no AES. At twenty
cells per second per link the arithmetic is free.

**Still deferred: the Ristretto-style group encoding.** DEC-015's second
question stands as recorded. It is a performance change with no privacy
consequence, the parallelised seal already clears the deployed interval, and
nothing about the freeze depends on it.

## DEC-015 (2026-08-25): Two wire-format questions are deferred to the freeze, not settled quietly

Both were found by measurement this session, both have a clear technical
answer, and both change bytes on the wire. Recording them together because the
reason for deferring is the same and the freeze is the moment to take them.

**The hop header is authenticated but not encrypted.** A link observer reads
the work flag, the batch coordinates and the 16-byte stream ID off every relay
cell, and the stream ID is unchanged across hops, so ingress and egress link by
reading 16 bytes with no correlation attack
(`nomad-testnet live/node/linkability_test.go`). Encrypting the header under
the existing pairwise hop key removes the linkability. It also invalidates the
published conformance vectors and the second implementation built against them.

**Embedding data in a point's y-coordinate costs sixteen discarded scalar
multiplications per chunk.** Of a 36 ms serial cell seal, about 30 ms is
kyber's `Point.Embed` rejection loop and under 4 ms is the ElGamal. A
prime-order group encoding (Ristretto-style) has no cofactor and no rejection,
which removes the cost rather than spreading it across cores as the current
parallelisation does.

**Decision: neither is made now.** Each is a protocol change with an
interoperability cost, and this project has exactly one second implementation
and one conformance corpus to invalidate. Making them separately, before a
freeze, spends that twice. Making them after a freeze costs far more. So both
are recorded as blockers on PROD-01 with the measurements attached, to be taken
together as one format revision or explicitly declined with a reason.

**What was done instead**, so the deferral is not an excuse for inaction: the
linkability is measured and stated in `THREAT_MODEL.md` rather than left as a
note; the seal cost is parallelised from 36 ms to 12 ms, which clears the 50 ms
deployed cadence with headroom, and the remaining gap to the 5 ms shortest
permitted cadence is recorded as a blocker naming this decision.

## DEC-014 (2026-08-25): A local failure costs one cell, never the schedule

Recorded because it trades availability for the emission invariant in a way a
later reader might otherwise mistake for a bug.

Any error from the sink used to end the scheduler, and in the live node that
closed the socket: an exhausted socket buffer or a full disk stopped a node
permanently. A node going silent is the loudest event a passive observer can
see, from causes that are local and ordinary.

A transient local failure now costs the cell it interrupted and nothing else --
never retried, never deferred and re-emitted, never followed by a catch-up, and
the peer rotation stays a function of the tick index. Which failures qualify is
an **allowlist** of named transient conditions, not a denylist: the first
version asked whether an error was fatal and answered with a list of one, so
hop sequence exhaustion became a counter. `EPERM` and `EINVAL` are deliberately
absent, being a firewall verdict and an unusable destination, and a transient
condition that does not clear stops the node after a bounded run.

The cost is that the crudest alarm an operator had -- the process exiting --
is gone. It is replaced rather than dropped: `last_sent_at` and `send_dropped`
are published, `nomad-node --check-health` fails a node that is up and emitting
nothing, and both deploy runbooks, the Compose healthcheck and the WAN campaign
use it.

## DEC-013 (2026-08-24): Nomad-browser is the browser; the engine forks are parked

The maintainer's decision, recorded because it changes what "done" means for
Workstream F and should not be re-litigated by a later session reading the
workstream list.

Nomad-browser is a working networkless browser core with a release pipeline,
an enforced sandbox entitlement, an adversarially tested materializer handoff
and a no-fallback adapter. `firefox-nomad` and `chromium-nomad` are full engine
checkouts carrying integration contracts and, as of today, a machine-checked
egress inventory each. Nothing more will be invested in them for now.

**What this means for the registry.** F-11 stays PARTIAL and PROD-22 keeps its
blocker saying no engine code is modified in either fork. Neither becomes MET,
and neither is deleted: the criteria still describe work that a full production
deployment would want, and the honest status is "not done and not being
pursued" rather than "not applicable". The inventories remain useful to whoever
picks this up, and their verifier keeps them from rotting.

**Why the decision is reasonable on the merits.** An engine integration is the
single largest remaining piece of work in the whole programme, it duplicates a
guarantee Nomad-browser already provides by construction rather than by
subtraction, and a networkless browser built from nothing is a far smaller
attack surface to defend than a networked engine with its network removed. The
egress inventories are the honest measure of that: thirty-one surfaces in Gecko
and eighteen in Blink, each of which would have to be closed and stay closed.

## DEC-009 (2026-08-20): One two-world capture harness, born in A, extended in E

The blind-capture/preregistration machinery required by the airlock DoD
(A-12) and by WAN testing (E-06/E-07) is a single harness to prevent
divergent methodology. Built during Workstream A, extended in E.

## DEC-008 (2026-08-20): Publication ingress spike before descriptor freeze

The client constant-rate uplink and online distributed mix path do not exist
yet (evaluator findings 1-2). An ingress spike runs immediately after C's
descriptor core lands; EpochDescriptor v1 reserves a versioned
`uplink_profile` field so the spike's traffic-class parameters land without
re-cutting the descriptor. A minimal authenticated operator-service layer is
pulled into A's scope; B extends it.

## DEC-007 (2026-08-20): Public rotation-failure policy for full-QUAL DKG

Full-QUAL ceremonies mean one unresponsive operator aborts rotation. Policy:
public retry ladder with fresh sessions; after three failed sessions the
sanctioned path is a membership transition excluding the non-completing
operator under the approval quorum; if no successor exists at retire_at the
epoch retires anyway (availability sacrificed, no silent extension). The
Pedersen abort-on-complaint/bias tradeoff is recorded in the spec for the
external cryptographic review.

## DEC-006 (2026-08-20): Membership transition is defined once, in Workstream C

The signed membership-transition primitive (approval quorum by previous-epoch
operators inside EpochDescriptor v1) is Workstream C protocol. Workstream B
governance tooling and PROD-07 accountability consume and extend it; they do
not define a second transition mechanism.

## DEC-005 (2026-08-20): Canonical binary encoding for all new signed objects

New lifecycle and identity objects (EpochDescriptor, approvals, activations,
revocations, erasure statements, SiteDescriptor) compute digests/signatures
over a specified canonical binary encoding (fixed field order, big-endian
integers, length-prefixed strings/lists, no floats). JSON is transport only.
Existing objects (topology v3, DKG certificate v1, batch descriptor v2) are
frozen as-is and embedded by exact bytes, preserving their digests and all
existing evidence. Rationale: Go json.Marshal is implementation-defined and
cannot support cross-platform vectors or a second implementation.

## DEC-004 (2026-08-20): Envelope window vs. active window

Topology v3 requires the DKG inside its own validity window, which conflicts
with prepare-while-active rotation if the window means "active". Resolution:
the topology window is the epoch's validity envelope (ceremony + DKG +
active + grace); the descriptor's activate_at/retire_at define the ACTIVE
sub-window; envelopes of consecutive epochs overlap. No topology schema
change; the epoch manager alone decides which epoch is ACTIVE.

## DEC-003 (2026-08-20): Epoch lifecycle extends the existing ceremony stack

Workstream C will generalize nomad-testnet's signed topology + DKG certificate
into a canonical EpochDescriptor and lifecycle state machine rather than
replacing the ceremony code. Rationale: DKG-01..12 are proven fail-closed at
fixture level with immutable evidence; rewriting would discard evidence and
risk regressions. New wire objects get new versioned domain strings; existing
domains keep their meaning.

## DEC-002 (2026-08-20): Execution artifacts live in nomad-protocol/production

workstreams.json is the requirement registry for GOAL.md; readiness.json
remains the sole authority for PROD gate status (CI-enforced against the DoD
table). workstreams.json never duplicates PROD statuses, only ownership
mapping, to avoid dual-source drift.

## DEC-001 (2026-08-20): Full goal text committed as production/GOAL.md

The complete production goal is versioned in-repo and referenced by the
session goal condition, so any future session recovers the full requirement
set from the repository alone.
