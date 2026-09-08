# Epoch and key lifecycle (v1)

Status: NORMATIVE for the release candidate, revised after internal evaluator
review 2026-08-20. The draft header's own condition for leaving draft was that
the implementation, vectors and tests land; they have. `live/epoch` is on the
production path (`cmd/nomad-operator`, `live/share/service.go`), the
descriptor vectors are published in `live/epoch/testdata/`, and every
transition below has positive, negative and adversarial tests.

Normative here means the wire formats, digests and transition rules are fixed
for this release candidate and change only through a versioned revision. It
does not mean the lifecycle has been operated by independent administrators:
that is PROD-05 and needs the operators of EB-2, and no claim on this page
should be read as evidence of it.

This specifies how Nomad transitions between committee epochs: descriptor
format, canonical encoding, chaining, activation, retirement, key erasure,
membership transition, revocation and compromise recovery. It builds on the
existing signed topology v3 (`nomad-live-topology-v3`) and DKG certificate
(`nomad-dkg-certificate-v1`) **without changing their schemas, domains or
digests**: the EpochDescriptor wraps them, so every existing object that
binds a topology digest (committee IDs, share files, hop keys, DKG
envelopes, batch descriptors) is unaffected and existing fixture evidence
remains reproducible.

## Canonical encoding rule for lifecycle objects

Digests and signatures over new lifecycle objects are computed over a
**canonical binary encoding**, not over JSON bytes. JSON (strict decoding,
bounded size, no unknown fields, no trailing data) is the storage/transport
encoding only. The canonical binary encoding of each object is specified
field-by-field: fixed field order, big-endian fixed-width integers,
length-prefixed byte strings (uint64 length), length-prefixed lists, no
floats, no optional-field ambiguity (absent optional fields encode as a zero
length). Embedded existing objects (signed topology v3, DKG certificate v1)
are embedded as their exact stored bytes, length-prefixed, so their existing
implementation-defined encodings are frozen by value rather than
re-canonicalized. Public test vectors pin every digest byte-exactly, and the
encoding is simple enough for an independent second implementation
(PROD-03) to reproduce from this document alone.

## Windows: validity envelope versus active window

Topology v3 requires an epoch's DKG schedule to sit inside that document's
`[not_before, not_after]`. This specification therefore defines, without any
topology schema change:

- The topology window `[not_before, not_after]` is the epoch's **validity
  envelope**: the interval in which any of the epoch's objects (ceremony,
  DKG, activation, active service, retirement grace) may exist.
- The descriptor fields `activate_at` and `retire_at` define the **ACTIVE
  window**, a sub-interval of the envelope.

Constraints: `not_before <= dkg_start`, `dkg_end <= activate_at <
retire_at <= not_after`. Epoch N+1's envelope deliberately overlaps epoch
N's ACTIVE window: N+1's ceremony and DKG run while N is active
(prepare-while-active), and N+1's `activate_at` equals N's `retire_at` for a
`scheduled` transition. Transport, share and materializer processes serve
exactly one ACTIVE epoch at any instant, chosen by the epoch manager from
the chain and the clock, never from the topology window alone.

## Objects

### EpochDescriptor v1

The canonical activation object for one epoch.

| Field | Meaning |
|---|---|
| `version` | `nomad-epoch-descriptor-v1` |
| `previous_epoch_digest` | SHA-256 descriptor digest of epoch N-1; all-zero for genesis |
| `transition` | `genesis`, `scheduled` or `emergency` |
| `activate_at` | RFC3339 public activation boundary |
| `retire_at` | RFC3339 public retirement boundary |
| `topology` | complete signed topology v3, embedded by exact bytes |
| `dkg_certificate` | complete DKG certificate v1, embedded by exact bytes |
| `uplink_profile` | reserved versioned client-uplink traffic-class extension (zero-length until the publication-ingress profile is specified; a non-empty value is versioned and validated) |
| `approvals` | cross-epoch approval signatures (empty for genesis) |
| `activations` | per-operator activation signatures by the epoch's own operators |

Descriptor digest:
`SHA-256("nomad-epoch-descriptor-digest-v1" || canonical_binary(descriptor
without approvals and activations))`.

Activation signature: Ed25519 by each listed operator identity over
`"nomad-epoch-activation-v1" || descriptor_digest`. Activation requires one
valid activation signature from every operator in the epoch's topology.

Approval signature (non-genesis): Ed25519 by an operator identity from the
**previous** epoch's topology over
`"nomad-epoch-approval-v1" || previous_epoch_digest || descriptor_digest ||
approver_identity_key`.

The approver's own identity key is part of the signed message. Without it
every approver signs identical bytes, so one approval is verbatim reusable
in every quorum slot and a single previous-epoch operator can mint an entire
quorum. Verifiers must additionally reject an approval whose index is
outside the previous membership, and must deduplicate on the resolved
operator rather than on the index as it appears on the wire, so that no
narrowing conversion can let one operator occupy several quorum slots.

### Approval quorum (membership transition lives here)

A non-genesis descriptor is valid only with approvals from at least
`max(previous.dkg.threshold, floor(previous_member_count / 2) + 1)` distinct
previous-epoch operators whose identities are not revoked. Membership change
is thereby a protocol action of the previous committee: the topology
authority assembles documents but cannot change membership alone; no single
previous operator can force or (below the quorum complement) veto a
transition. Workstream B governance tooling **consumes** this primitive; it
is defined only here.

`scheduled` and `emergency` transitions carry the same quorum rule. A
`scheduled` descriptor's `activate_at` must equal the previous descriptor's
`retire_at`. An `emergency` descriptor may activate before the previous
`retire_at`; its activation retires the previous epoch at `activate_at`.

If more previous-epoch operators are simultaneously lost than the quorum
tolerates, no valid transition exists: the network re-bootstraps with a new
genesis descriptor, which clients treat as a new trust decision, never as an
automatic continuation. This is deliberate fail-closed behavior.

## State machine

    PREPARING -> READY -> ACTIVE -> RETIRED

- **PREPARING**: enrollment/draft/attestation ceremony and signed DKG
  schedule exist; DKG incomplete.
- **READY**: full EpochDescriptor verifies; now < `activate_at`.
- **ACTIVE**: `activate_at <= now < retire_at`, descriptor verifies, and no
  valid `emergency` successor is active.
- **RETIRED**: `now >= retire_at`, or a valid `emergency` successor is
  ACTIVE.

Validation failure is terminal for a descriptor; there is no partially
active epoch. An interrupted DKG never resumes (existing journal rule).

All state transitions are pure functions of (persisted chain, wall clock).
Private user activity, queue depth, publication state and reader state are
never inputs, and a missed boundary defers work rather than accelerating it.

## Rotation-failure policy (public, fail-closed)

Full-QUAL DKG means one unresponsive operator aborts an N+1 ceremony. The
policy, all timings public:

1. The N+1 draft topology carries the primary DKG session and schedule.
2. On ceremony failure, replacement drafts with fresh sessions are issued at
   public retry offsets. Retries reuse the same membership.
3. After three failed sessions with the same membership, the sanctioned path
   is a membership transition excluding the non-completing operator(s),
   under the approval quorum, as either a `scheduled` replacement (if time
   allows before N's `retire_at`) or an `emergency` transition.
4. If no valid successor exists at N's `retire_at`, epoch N retires anyway
   and the network is down until a successor activates. Availability is
   deliberately sacrificed rather than extending N beyond its signed window
   (no silent extension).

Retry schedules, like everything else, must not respond to private state.

Recorded for external cryptographic review: Kyber's Pedersen DKG with
abort-on-complaint avoids the Gennaro et al. key-bias attack at the cost of
converting bias attempts into ceremony aborts. Nomad accepts this
availability cost; the accountability evidence for repeated aborts is the
signed DKG journals identifying the non-completing or equivocating member
(feeds PROD-07).

## Chain and verifier rules

Every verifier (operator, node, share service, materializer, client) keeps a
persisted epoch chain store with these rules:

1. **Chaining**: a non-genesis descriptor's `previous_epoch_digest` must
   equal the stored digest for epoch N-1; its epoch number must be exactly
   previous+1 on the same `network_id`.
2. **Monotonicity / rollback rejection**: a descriptor for an epoch number
   at or below the highest locally RETIRED epoch is rejected permanently.
   Epoch numbers of failed (never-activated) ceremonies are not reused; a
   retry keeps the same epoch number only until a descriptor for it
   activates, after which that number is burned.
3. **Equivocation fail-closed**: two distinct valid descriptor digests for
   the same `(network_id, epoch)` is fatal: the verifier records both
   digests as an equivocation proof, refuses to activate either, and halts
   epoch progression until a manually authorized re-bootstrap. Conflicting
   descriptors can never both (or either) silently become active.
4. **Operator single-signature rule**: an operator must refuse to sign
   activation or approval for a second distinct descriptor digest for the
   same epoch; its local signature journal enforces this and the refusal is
   itself evidence. Signing must go through the journal rather than merely
   consulting it: because rule 3 makes any second valid descriptor halt every
   verifier that sees it, an unjournalled signer turns a routine operational
   mistake into a network-wide outage.

Rule 3's halt is in-memory first and persisted second. A verifier that has
observed two valid descriptors for one epoch stops serving epochs even if it
cannot write the evidence (full disk, read-only mount, a marker another
instance already wrote); a persistence failure is reported alongside the
halt, never in place of it.

Rule 2 is enforced against a persisted high-water mark, not merely against
the descriptors still present in the store, so removing a descriptor file
cannot silently re-open a burned epoch number for a different successor.

Equivocation is defined over `(network_id, epoch)` read from the embedded
topology. A verifier must not match candidates by their previous-epoch
digest alone: every genesis descriptor shares the all-zero previous digest,
so doing that would misrecord a lawful re-bootstrap at a later epoch as
equivocation and halt every verifier that saw it.

A store is pinned to one `network_id` and rejects descriptors from any other
network, including the first genesis it is ever offered.

Revocation is forward-scoped. A verifier applies its revocation set to what
it admits from now on, and must not re-check already-accepted history
against it: doing so would make a compromise announcement render the
verifier unable to open its own chain at exactly the moment it needs to
accept the emergency successor that excludes the compromised operator.

## Context binding

All existing bindings are unchanged: DKG packets bind network, topology
digest, epoch, session, phase and sender; committee IDs bind topology
digest, session, epoch and threshold; shuffle proofs and receipts bind
committee, epoch, batch and round; partial decryptions bind committee,
epoch, member and batch digest; hop keys bind network, epoch, topology
digest and direction. Because the committee ID commits to the topology
digest and session, no share, partial decryption, shuffle proof, receipt,
DKG message, attestation or session key can be transplanted between epochs
or committees.

New lifecycle domains, all versioned:

- `nomad-epoch-descriptor-digest-v1`
- `nomad-epoch-activation-v1`
- `nomad-epoch-approval-v1`
- `nomad-operator-revocation-v1`
- `nomad-epoch-erasure-v1`

## Committee shape

The production profile is five operators with DKG threshold 3 (3-of-5).
Topology v3 already validates threshold in [2, n] and the threshold layer
already recovers with t-of-n shares; the profile is configuration plus
required negative tests: t-1 partial decryptions insufficient; cross-epoch
share/partial mixtures rejected; full-QUAL still required for ceremony
completion. Airlock evidence must be produced on this committee shape.

## Retirement, forward secrecy and erasure

When epoch N retires:

- Share services and materializers refuse partial-decryption work for
  committee N by policy (retirement), even though N's shares remain
  cryptographically bound to N's ciphertext only.
- Each operator runs the erasure procedure: overwrite-and-unlink of the
  epoch's private share file and DKG journal, followed by a signed erasure
  statement in the `nomad-epoch-erasure-v1` domain containing operator ID,
  epoch, descriptor digest, the SHA-256 of each erased file, method,
  filesystem type and timestamp.
- **Documented limitations**: on journaling filesystems, SSDs with wear
  leveling, snapshots or backups, overwrite-then-unlink does not guarantee
  physical destruction. Deployment guidance requires full-disk encryption
  and no share-directory backups; the recorded claim is file destruction
  within an encrypted volume, not physical-media erasure.

Forward-secrecy adversarial experiment (required evidence): capture epoch-N
wire ciphertext; retire N and run erasure on every operator; hand an
evaluator the complete post-erasure persisted state of all operators; the
evaluator must fail to decrypt the captured epoch-N batch, while a control
run with pre-erasure state succeeds.

## Revocation and compromise recovery

A revocation statement is the `nomad-operator-revocation-v1` domain over the
canonical binary of `{network_id, operator_id, identity_key,
epoch_observed, reason}`, signed either by the revoked operator's own
identity (self-revocation) or by an approval-quorum of current-epoch
operators (compromise revocation, a list of signatures over the same
statement).

Effects, applied by every verifier that accepts the statement:

- the identity's future approvals/activations/attestations are invalid;
- the identity cannot appear in any later epoch's operator set;
- an `emergency` transition excluding the operator is the recovery path:
  remaining operators approve a successor epoch with a replacement operator
  and a fresh DKG.

Required and drilled recovery flows: operator credential compromise,
lost/unresponsive operator, operator replacement, stale descriptor
distribution, DKG failure (abort, fresh session), interrupted ceremony
(journal refusal, fresh session), emergency transition. A single compromised
operator never requires re-bootstrapping the network; losing more than the
approval-quorum complement does.

## Non-claims

- This lifecycle does not by itself establish administrative independence of
  operators (Workstream B / EB-2).
- Erasure evidence is bounded by the documented storage limitations.
- Genesis trust distribution (how clients obtain the genesis descriptor and
  authority key) is deployment policy, pinned at packaging time; this
  specification binds everything after genesis.
- The client publication-uplink traffic class is not yet specified; the
  descriptor reserves the field and the publication-ingress spike
  (Workstream A) supplies its parameters before descriptor freeze.
