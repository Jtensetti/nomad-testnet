# SiteID and publisher identity (normative v1)

Status: NORMATIVE v1 as of 2026-08-21. The implementation
(`Jtensetti/nomad-local-reconstruction`, package `site`), its published
vectors and its adversarial tests are in place, including a full
key-compromise recovery drill. The condition this header carried while it was
a draft has been met.

Changing anything here now is a protocol change: it needs a version bump and
the compatibility matrix updated, not an edit.

Object integrity and publisher identity are separate claims. The existing
signed manifest (`nomad-object-v1` / `nomad-manifest-v1`, 228 bytes) proves
*this exact object was signed by this key*. It cannot answer *is this
currently the valid key for the site the user intended*. This specification
adds that second claim without changing the manifest wire format: the
manifest stays byte-identical and is referenced, never modified.

## Concepts

- **ObjectID** — the SHA-256 content root of exact object bytes. Already
  implemented; unchanged.
- **SiteID** — a persistent publisher identity that survives content
  changes, many publications and routine signing-key rotation.
- **SiteDescriptor** — one link in a hash-linked, monotonically sequenced
  chain that states which keys are currently authorized for a SiteID.
- **SitePublication** — a small signed record binding one ObjectID to a
  SiteID under a specific descriptor. This is the join between the two
  claims.

## Canonical encoding

Identical discipline to the epoch lifecycle (DEC-005): digests and
signatures are computed over a specified canonical binary encoding — fixed
field order, big-endian fixed-width integers, uint64 length prefixes for
byte strings and lists, no floats, absent optional fields encode as zero
length. JSON is storage/transport only and is never hashed or signed
directly. This is what makes cross-platform derivation (D-03) and an
independent second implementation (PROD-03) possible.

## SiteID derivation

    SiteID = SHA-256("nomad-siteid-v1" || canonical_binary(genesis_core))

where `genesis_core` is the genesis SiteDescriptor with its `site_id` field
set to 32 zero bytes and its `authorizations` list empty. Every other field
— including the full signing-key set, the recovery policy and the validity
window — is covered. The genesis descriptor's own `site_id` field must equal
this derivation, so a descriptor chain is self-certifying: the SiteID is a
commitment to the exact genesis key material and policy.

A SiteID is therefore **not** a trust-on-first-use name. Learning the
correct SiteID out of band (a link, a QR code, a printed address, another
verified site) *is* the trust decision, exactly as with a self-certifying
onion address. This is the explicit genesis/first-key trust policy required
by D-11: Nomad clients never infer a first key from the network, and a
SiteID that the user did not obtain out of band conveys no authority.

## SiteDescriptor v1

| Field | Meaning |
|---|---|
| `version` | `nomad-site-descriptor-v1` |
| `site_id` | 32 bytes; zero in genesis_core, else the derived SiteID |
| `sequence` | uint64, 0 for genesis, exactly previous+1 otherwise |
| `transition` | `genesis`, `rotation`, `recovery` or `revocation` |
| `previous_descriptor_digest` | 32 bytes; zero for genesis |
| `valid_from`, `valid_until` | canonical UTC RFC3339 |
| `signing_keys` | ordered list of active Ed25519 publishing keys |
| `revoked_keys` | ordered list of permanently revoked keys |
| `recovery` | recovery policy: ordered recovery key list + threshold |
| `authorizations` | signatures authorizing this descriptor |

Descriptor digest:
`SHA-256("nomad-site-descriptor-digest-v1" || canonical_binary(descriptor
with authorizations emptied))`.

Constraints: at least one signing key and at most 8; at least one recovery
key and at most 8; `revoked_keys` has its own, far larger bound (1024),
because revocation is absorbing and sharing the active-key bound would make
a site permanently unrotatable after eight revocations; recovery threshold
between 1 and the recovery key count;
`valid_from < valid_until`; no key may appear in both `signing_keys` and
`revoked_keys`; no duplicate keys within a list; a key listed in
`revoked_keys` of any ancestor may never reappear in `signing_keys` or
`recovery` of a descendant.

Recovery keys must not also be signing keys. Online publishing keys and
recovery authority are separate by construction, so theft of a publishing
key does not confer recovery authority.

## Authorization rules

The authorization message is
`"nomad-site-authorization-v1" || descriptor_digest || role_byte || key`
where `role_byte` is `0x01` for a signing-key authorization and `0x02` for a
recovery-key authorization, and `key` is the authorizing public key. Binding
both the role and the exact key prevents an authorization from being
replayed as a different role or attributed to a different key.

| Transition | Required authorizations |
|---|---|
| `genesis` | every key in `signing_keys` (role 0x01) and every key in `recovery` (role 0x02) of the descriptor itself |
| `rotation` | a majority of the **previous** descriptor's `signing_keys` (role 0x01), and the recovery policy must be byte-identical to the previous descriptor's |
| `recovery` | at least the previous descriptor's recovery `threshold` distinct previous recovery keys (role 0x02) |
| `revocation` | either a rotation-style signing majority or a recovery-style threshold |

**Recovery-policy authority.** Changing `recovery` at all, or revoking a
currently active recovery key, additionally requires the previous
descriptor's recovery `threshold` in role-0x02 authorizations, whatever the
transition kind. Without this rule a thief holding only the online signing
keys could install their own recovery set and revoke the real one; because
revocation is absorbing, the rightful owner could then never recover. Online
publishing authority must never reach offline recovery authority.

**Possession of new keys.** Every key that first appears in `signing_keys`
or `recovery` in any transition must carry a role-appropriate self-signature,
not only at genesis. Installing a recovery key nobody holds is a one-shot
permanent brick of the site.

Recovery is deliberately stricter than rotation: it is the only transition
that can replace a signing-key set the holder no longer controls, and it
requires the offline recovery quorum. A `recovery` transition additionally
must place every previously active signing key into `revoked_keys`, so
compromise recovery is always accompanied by explicit revocation of the
compromised set.

Genesis self-signature by every listed key proves possession of each key at
genesis and prevents a publisher from committing to a recovery key it does
not hold.

## Chain, rollback and equivocation

Every client keeps, per SiteID it has ever verified, the highest-sequence
descriptor digest it accepted. Rules:

1. **Chaining** — a non-genesis descriptor's `previous_descriptor_digest`
   must equal the digest of the descriptor for `sequence - 1`, and its
   `site_id` must equal the chain's SiteID.
2. **Monotonicity** — a descriptor whose sequence is at or below the
   highest accepted sequence is rejected unless its digest is identical to
   the stored one for that sequence (idempotent re-delivery). This is the
   rollback defense: a superseded descriptor can never be reinstated.
3. **Equivocation is fatal, per site** — two distinct valid descriptor
   digests for the same `(site_id, sequence)` are recorded as an
   equivocation proof. The site is marked EQUIVOCATING; the client refuses
   to treat any publication from it as identity-verified from then on, and
   refuses further descriptor updates for that site. It does not halt the
   client or any other site. Only a fully valid competing descriptor
   triggers this, so malformed bytes cannot be used to poison a site.
4. **Expiry** — a descriptor outside its validity window authorizes
   nothing. Publications previously accepted are not retroactively
   invalidated; new publications under an expired descriptor are not
   identity-verified.

The equivocation proof carries both encoded descriptors **and the accepted
chain from genesis to the contested sequence**. The prefix is not optional:
judging whether either branch is authorized requires its ancestors, and a
proof that only compared shapes could be fabricated against any honest site,
turning split-view detection into an attacker-controlled kill switch. A
verifier re-derives the SiteID from the proof's genesis and verifies both
branches against the prefix before accepting the conflict.

A descriptor for a different site is never equivocation. A verifier pins the
SiteID it is tracking and rejects anything else as unrelated, because a
genesis descriptor only proves that it commits to its own derived SiteID.

## Descriptor distribution

The chain makes rollback and equivocation *detectable by a verifier that sees
both branches*. Nothing in it makes anyone see both branches. A reader shown
only an attacker's descriptor accepts it, and the rules above bound that for
exactly as long as the attacker can keep the honest branch away -- which is
indefinitely. Distribution closes that.

Descriptors are published to an append-only transparency log with RFC 6962
hashing: a leaf is `SHA-256(0x00 || entry)`, an interior node is
`SHA-256(0x01 || left || right)`, and the split at size *n* is the largest
power of two strictly less than *n*. A log entry for a descriptor is
`"nomad-site-log-entry-v1" || uint64(len(encoded)) || encoded`.

A log signs its head as a **checkpoint**: `version`, `origin`, `size`, `root`
(32 bytes, lower-case hex), `time` (canonical UTC RFC3339), and an Ed25519
`signature` over
`"nomad-site-log-checkpoint-signature-v1" || len||origin || size || root ||
len||time`, every variable-length field length-prefixed. `origin` names the
log and is supplied out of band by the verifier, never read from the document:
a checkpoint that named its own log could be replayed as any other's.

Rules:

5. **Witnessing** — a verifier operating in the witnessed profile accepts a
   descriptor into a chain, including its genesis, only with an inclusion
   proof against a checkpoint it has verified. A descriptor an attacker showed
   to one reader alone is not in the log, has no proof, and is refused. A
   descriptor that *is* accepted is one the site's owner can see, which is
   what makes recovery possible at all.
6. **Consistency** — a verifier moves to a new checkpoint only with a
   consistency proof from the size it currently holds to the size the new
   checkpoint names, and the verifier supplies its own held size. A proof that
   could name its own starting point would let a log claim the reader had held
   nothing and hand it any branch. A checkpoint at a smaller size, or dated
   before the one held, is refused.
7. **Freshness** — a verifier whose most recent checkpoint is older than its
   freshness window stops treating publications as identity-verified and
   stops accepting descriptors. It reports PUBLISHER_UNKNOWN, never
   PUBLISHER_VERIFIED, and never falls back to accepting. A checkpoint dated
   more than five minutes into the future is refused, or a log could date a
   head forward and make every reader permanently and falsely fresh.
8. **Log equivocation is fatal, per log** — two checkpoints of one size, signed
   by one log key, with different roots, are a split-view proof: transferable
   evidence anyone holding the log's key can check. Only checkpoints whose
   signatures have already verified may take part, so a split-view proof cannot
   be manufactured by anyone who is not the log. A verifier that finds one
   refuses every later checkpoint and every later descriptor from that log. The
   state is absorbing, mirroring the chain's EQUIVOCATING state and for the same
   reason: a log that has served two histories has no branch a verifier is
   entitled to prefer, and one that could be re-entered at another size would
   let an attacker step around the detection simply by advancing. No other log
   is affected. When a consistency proof fails, the verifier cannot yet
   distinguish a forked log from a corrupted proof; the next step is to demand
   a signed checkpoint at the size already held, which either matches -- the
   proof was merely broken -- or equivocates and becomes evidence.

   A verifier's split-view memory may be bounded, and a bounded verifier cannot
   notice equivocation at a head older than its memory. The bound must always
   retain the size the verifier currently holds, because that is the head the
   escalation above demands.

An unwitnessed chain can never reach PUBLISHER_VERIFIED. This is structural
rather than advisory: a deployment that fails to configure distribution loses
the identity verdict instead of silently returning to the unbounded case.

### Distribution must not observe what a reader reads

Fetching a checkpoint or an inclusion proof because a user opened a site would
make an externally observable network event depend on private activity, which
the core invariant forbids. Two rules keep it out, and both are normative:

- The inclusion proof travels **with** the publication, over the same path as
  the object. Reading a site fetches nothing extra.
- Checkpoint refresh runs on a **fixed cadence that does not depend on what
  the reader is reading, has read, or is about to read**, and runs whether or
  not anyone opens a site.

It follows that a failed refresh is never retried harder because a user is
waiting. That would be precisely the private-state-dependent catch-up traffic
the invariant rules out. A reader whose refresh fails goes stale and says so;
losing the identity verdict is the cheaper of the two failures.

### Two following profiles, and what each bounds

- **Entry-following.** A reader that mirrors the log's entries on its own
  cadence obtains a recovery descriptor as soon as it syncs, because an
  attacker cannot both get a descriptor accepted and keep it out of the log.
  Recovery propagates promptly. The cost is bandwidth proportional to the log
  rather than to what the reader cares about -- which is exactly why it leaks
  nothing about the reader's interests.
- **Checkpoint-following.** A reader that follows only checkpoints is cheaper
  and weaker: within its freshness window an attacker who can withhold the
  recovery still wins. Past the window the reader stops issuing a verdict.

The residual exposure of the checkpoint-following profile is one freshness
window, and it is a deployment choice with a cost at both ends: too short and
a reader loses its verdict whenever the log is briefly unreachable, too long
and an attacker who can partition a reader has that long to serve a private
branch.

### What this does not do

It does not make the log honest. A single log that equivocates is caught only
by a reader that sees both heads, and the mechanism above produces the proof
rather than preventing the act. Preventing it requires more than one log, or
witnesses that cosign heads. That is a deployment decision and is recorded as
such; nothing in this specification claims a single log is trustworthy.

## SitePublication v1

The join between object integrity and publisher identity, kept separate
from the manifest so the 228-byte manifest format is untouched.

| Field | Meaning |
|---|---|
| `version` | `nomad-site-publication-v1` |
| `site_id` | the publishing site |
| `descriptor_digest` | digest of the descriptor authorizing the signing key |
| `signing_key` | the Ed25519 key used, which must be active in that descriptor |
| `object_root` | the manifest's 32-byte content root (the ObjectID) |
| `manifest_digest` | SHA-256 of the exact 228 manifest bytes |
| `published_at` | canonical UTC RFC3339 |
| `signature` | Ed25519 over `"nomad-site-publication-v1" \|\| canonical_binary(record without signature)` |

Binding both `object_root` and `manifest_digest` means a publication cannot
be re-pointed at a different manifest that happens to share a content root,
and cannot be transplanted onto another object.

Acceptance as *publisher-identity verified* requires all of:

1. the object verifies exactly (existing manifest rules: length, root,
   object signature, manifest signature);
2. the publication record's `object_root` and `manifest_digest` match that
   exact object and manifest;
3. the publication's signature verifies under `signing_key`;
4. `signing_key` is active (and not revoked) in the descriptor identified by
   `descriptor_digest`;
5. that descriptor is an accepted descriptor for the SiteID which was inside
   its validity window at the publication's `published_at`, the head has not
   revoked the signing key, and the site is not EQUIVOCATING. It need not be
   the head: a routine rotation must not turn a publisher's back catalogue
   into failed identity claims;
6. the descriptor chain from genesis to that descriptor verifies, and the
   SiteID re-derives from the genesis descriptor.

Any failure yields a lesser state; nothing degrades to a warning.

## Client identity states

The browser must render exactly these, never an ambiguous "verified":

| State | Meaning |
|---|---|
| `OBJECT_VERIFIED` | bytes are exactly the signed object; publisher identity not established |
| `PUBLISHER_VERIFIED` | all six acceptance conditions above hold for a SiteID the user asked for |
| `PUBLISHER_UNKNOWN` | no publication record, or a SiteID with no locally verified chain |
| `PUBLISHER_INVALID` | signature, chain, revocation, expiry, rollback or equivocation failure, including a claim contradicted by a chain the client holds |
| `OBJECT_INVALID` | the bytes are not the signed object; no identity claim was reached |

`PUBLISHER_INVALID` is not a softer `PUBLISHER_UNKNOWN`: it means an
identity claim was made and failed, and it must be visually distinct.
`PUBLISHER_UNKNOWN` is reserved for a well-formed claim whose chain is
genuinely not cached yet. A malformed claim, or one naming a descriptor the
client's accepted chain cannot contain, is INVALID: otherwise an attacker
chooses the softer state simply by naming a digest the client never saw.
Content whose identity state is `PUBLISHER_INVALID` must not be presented
as belonging to the requested site.

## Resolution must not create query-dependent traffic

Descriptors and publication records are ordinary Nomad objects distributed
by the same public, periodic, private-state-independent mechanism as all
other content. A client must never fetch a descriptor because a user asked
for a site, and must never emit a lookup, probe or refresh whose existence,
timing or destination depends on which SiteID the user is interested in.
Identity verification runs entirely against locally cached material; if the
required descriptor is not cached, the result is `PUBLISHER_UNKNOWN` and the
client waits for ordinary cache maintenance. This is D-10 and it is a hard
requirement of the core privacy invariant, not a performance preference.

## Non-claims

- A verified SiteID says nothing about the honesty, legality or safety of
  the publisher; it says the same party that created the genesis descriptor
  authorized this object.
- Out-of-band SiteID distribution is outside this specification. A user
  given the wrong SiteID verifies the wrong site correctly.
- Equivocation detection is per client and depends on a client actually
  seeing both descriptors; it bounds an attacker's ability to sustain a
  split view over time, and does not prevent a one-shot split view against a
  client that never sees the other branch.
- Nothing here protects a publisher who publishes identifying content, nor a
  publisher whose signing key is stolen and used before revocation
  propagates.
