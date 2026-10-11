# Publication airlock (draft v1)

Status: DRAFT. Nothing here is active protocol until the online distributed
mix path (A-15) lands and this header changes.

Publishing is private activity. The airlock is the boundary where a
publisher's sealed fragment enters the network and, some fixed time later,
a plaintext fragment leaves it, with nothing observable in between that
depends on who published, whether anyone published, or how much.

It sits between two pieces that already exist: the client's local
publication queue (`nomad-testnet/live/publish`, which has no network
capability at all) and the uplink cell profile
(`nomad-testnet/live/uplink`, whose work and cover cells are
indistinguishable to both a network observer and the entry operator). The
airlock is what happens to a fragment after an entry operator receives it.

## The three things an observer must not learn

| Observable | Fixed by |
|---|---|
| when a batch closes and releases | a public schedule, never queue state |
| how many fragments are in a batch | a fixed batch size, padded with cover |
| which entering ciphertext became which released fragment | a verifiable shuffle chain across the whole committee |

Each is a separate mechanism, and each fails closed on its own.

## Release schedule

`Schedule` is public deployment policy carried in the signed epoch
descriptor: a genesis instant, a period, a deposit cutoff, and a batch size.
Every derived time is a pure function of those four values and an epoch
number:

    deposit window for epoch e = [genesis + e*period,
                                  genesis + e*period + (period - cutoff))
    release of epoch e         = genesis + (e+1)*period

There is no API by which a deposit moves any of these. `Seal` refuses to run
before the window closes even when the batch filled in the first second,
because closing early is itself the statement that the batch was full. The
cutoff exists so the shuffle chain and threshold decryption have a fixed
budget between the last deposit and the release, rather than a budget that
depends on how much work arrived.

## Deposits

A deposit is one client-sealed committee ciphertext: exactly one column of a
mix batch, and exactly the inner layer of one uplink cell. The airlock holds
them keyed by a client-chosen deposit ID.

- **Slots are named by the airlock, not the caller.** The deposit ID is
  derived from an opaque per-session value the entry operator holds from the
  uplink key agreement, plus the client's sequence number. When callers named
  their own slots the 32-byte namespace was unauthenticated: anyone could
  probe whether an ID was held — a "did X publish this epoch?" oracle for any
  ID derived from content or from a publisher — and could permanently block a
  publisher by squatting its ID.
- **Idempotent.** Re-offering the identical payload for the same sequence
  succeeds without consuming a second slot.

  This is duplicate suppression at the operator, not a client retry
  mechanism, and the earlier text here said otherwise. It read: a client
  "cannot tell whether its uplink cell arrived — and it cannot, since the
  uplink carries no acknowledgement that would distinguish work from cover —
  resends freely". A client must not resend. An uplink cell begins with its
  sequence number in **cleartext**, the sequence is durable and strictly
  increasing, and cover is never resent — so a repeated sequence, arriving an
  epoch after the first, tells the entry operator that this publisher had a
  work cell it wanted back. That is the one fact the whole construction exists
  to keep from the entry operator, and no amount of idempotence at the airlock
  removes it from the wire. What the property is actually good for is the
  network duplicating a datagram, which no one chose and which is not
  correlated with having work.

  Re-*sealing* the fragment for the same sequence is worse than useless: it is
  an AES-GCM nonce reuse under the session key, since the nonce is derived
  from the sequence. It yields the XOR of the two inner layers and, through
  GHASH, the authentication key. The airlock would refuse the second deposit
  as a conflict, but only after the damage was on the wire. `live/deposit`
  refuses a repeated sequence before sealing, in the one place that holds the
  state to see it.

  What a client does instead: it does not emit work outside the deposit
  window at all. The window is public schedule policy, so the publisher
  computes it from the same signed bytes the operator does and leaves the
  fragment on its durable queue until the window is open. Nothing is
  retransmitted because nothing was sent. See DEC-020 and DEC-022.
- **Conflicts are refused, not resolved.** A different payload for a held
  sequence is an error. Overwriting would silently drop whichever publication
  lost. Reporting it is safe because a caller can only collide with its own
  earlier deposit.
- **A full epoch is silent.** A deposit beyond `BatchSize` is dropped and
  counted operator-locally, and the caller is told nothing. Reporting "epoch
  full" gave any depositor the exact real-deposit count — subtract the
  accepted count from the public batch size — and probing for it consumed
  every remaining slot. Losing the work is the right trade: the client keeps
  emitting uplink cells at the same rate either way, so nothing on the wire
  changes.
- **One session cannot take the batch.** `MaxDepositsPerSession` bounds how
  many slots a session may hold. This does not solve Sybil — an attacker with
  many authenticated sessions still competes for slots — which is an
  admission question (G-05..G-09), not one this boundary can answer.

  Every in-window cell counts against the bound, cover included: the operator
  cannot tell cover from work, so it charges both. A publisher therefore
  deposits at most `MaxDepositsPerSession` fragments per epoch however long
  the window is, and the drain stops taking work from the queue once the bound
  is spent. The bound is public policy in the same signed bytes the operator
  reads it from, so applying it needs no answer from anyone; emitting past it
  destroys the work, because `Queue.Next` has already unlinked the fragment
  and the airlock refuses the deposit in silence. See DEC-024.

## Sealing

At the scheduled instant the airlock produces a batch of exactly `BatchSize`
columns:

1. Real deposits are ordered by deposit ID, so the entry operator's view of
   arrival order is not carried into the batch even momentarily.
2. The remainder is filled with cover: real committee encryptions of the
   reserved empty fragment, produced on the same code path a client uses.
   Filler that was not a valid ciphertext would fail the shuffle proofs and
   announce itself; filler that was distinguishable from a real deposit would
   publish the count. Cover is generated when the airlock opens, before the
   window, and the wire form of the whole batch is re-derived from the parsed
   batch so real and cover columns get their padding from one code path. Both
   were defects: generating cover in `Seal` made its runtime linear in the
   number of *empty* slots, and copying a 1152-byte deposit into a 1200-byte
   cell left the difference zero while cover had it random.
3. The whole set is permuted by a uniform draw from the system CSPRNG, so
   cover position does not announce how many real deposits preceded it.

The sealed batch is therefore the same size and shape whether nobody
published or the epoch filled. It is deliberately *not* reproducible: the
placement is a fresh draw each time.

## Shuffle chain

Every certified committee member shuffles the batch in turn, in the
committee's certified order, each producing a Neff sequence-shuffle proof
**and a receipt signed by that member's certified identity key**.
`VerifyChain` re-verifies the whole chain from the sealed batch, against the
ordered identity keys.

The signature is not decoration. A Neff proof binds only to the encryption
key and the input/output digests, so with an unauthenticated round label an
entry operator holding no committee share could run every shuffle itself,
label the rounds with the certified member indices, and be accepted -- knowing
the whole ingress-to-egress map, with the anytrust assumption inverted so that
it needed to corrupt *no* shufflers. The receipt's proof domain is derived
from the committee ID, the committee epoch, the batch ID and the round number,
so a proof cannot be lifted to another member, round, batch or epoch, and the
sealed batch carries a digest commitment naming its release epoch so a whole
chain cannot replay from one epoch into another.

A round must also **re-randomise**. A Neff proof shows that some permutation
with some blinding exists, and zero is a valid blinding, so a chain of pure
permutations verifies and anyone who saw the sealed batch reads the map
straight off the bytes. Every output column must therefore differ from every
input column.

**Every member must appear exactly once, in order.** This is the anytrust
assumption made mechanical: the chain is unlinkable only if at least one
shuffler is honest, so a chain that skipped a member is not a shorter chain,
it is a chain with a smaller honest-party assumption. A missing member, an
extra round, members out of order, one member standing in for another, a
corrupted proof, a proof borrowed from another round, a substituted
ciphertext, a batch that grew or shrank, an output that is not a valid
ciphertext — each fails the epoch closed. There is no partial-chain path and
no degraded mode for an unreachable member.

## Release

Threshold decryption opens the chain's output, per column. Cover is dropped
**here and nowhere earlier**: it is indistinguishable from a real deposit
until it has been decrypted, which is the entire point of it.

Decryption is per column rather than all-or-nothing. A ciphertext of valid
points that is not a real encryption passes every structural check and every
shuffle proof -- a shuffle proof shows a permutation, not decryptability --
and fails only at release, so an all-or-nothing decryption let one deposit
censor every other publisher in the epoch after the committee had already
spent its budget on it. A column that cannot be decrypted is dropped and
counted; the rest are released. The number of real fragments
is therefore known only to a party already holding threshold authority, and
never becomes part of the public record of the epoch.

A released fragment is not trusted for having come out of the airlock. It
still faces the ordinary object rules: exact hash, manifest signature, and —
where a publisher identity is claimed — the SiteID chain in
`SITE_IDENTITY.md`. The airlock provides unlinkability, not authenticity.

## Capability boundary

`live/airlock` must have no transitive path to a socket, a scheduler, or peer
selection. It decides when a batch closes and what goes in it; if it could
reach the transport, the release boundary could be made to depend on queue
state, which is the one thing the fixed schedule exists to prevent. The
boundary is enforced by an in-package architectural test and by a CI
dependency gate, and the package derives its deposit size from the mix
parameters rather than importing `live/hop`, which would pull in the
transport.

## What is claimed, and what is not

Claimed, and evidenced by tests at the package boundary:

- release timing is a pure function of public parameters, at every occupancy
  from empty to full, and sealing costs the same at every occupancy;
- batch size and shape do not vary with deposit count, across the whole
  1200-byte wire form rather than only the ciphertext region, and every
  column including cover decrypts;
- deposits are idempotent with a constant-time comparison, conflicts are
  refused, capacity does not grow, and a malformed or small-order deposit is
  refused before it takes a slot;
- a restart re-derives the same window and accepts a duplicate of the same
  deposit;
- a publisher does not hand work to its emission path while the deposit
  window is shut, so the fragment stays on its durable queue instead of
  becoming a refused cell, and no uplink sequence is ever sealed twice;
- sealed position carries no stable information about arrival order;
- a chain in which no certified member participated is refused, as is one
  with a substituted signer, a borrowed receipt, a round that does not
  re-randomise, or a chain replayed into another release epoch, committee or
  committee epoch, alongside the earlier structural deviations;
- one undecryptable column does not censor the epoch;
- the ingress-to-egress permutation is uniform across trials.

**Not** claimed:

- Unlinkability as a proof. The permutation-uniformity measurement is over a
  small number of trials at a small batch size. It establishes that the chain
  permutes uniformly in this sample; the guarantee rests on re-randomised
  ElGamal being IND-CPA and on the anytrust assumption, and a test establishes
  neither. An earlier byte-similarity measurement was withdrawn after review
  showed it passed against a chain that preserved order exactly.
- The anytrust assumption, which cannot be tested: if every shuffler colludes
  the chain is linkable by construction. What is tested is that the code
  requires every member to participate with an authenticated round.
- Fair access under Sybil. One session is bounded, but an attacker holding
  many authenticated uplink sessions still competes for slots on equal terms
  with honest publishers. Admission and rate control (G-05..G-09) are not
  designed.
- The uplink carries no deposit sequence on the wire today, so the session
  and sequence a caller passes are supplied by the entry operator's own
  session handling rather than authenticated end to end by the client.
- `Seal` takes the current time from its caller and never reads a clock, so
  "release timing is a pure function of public parameters" holds only if the
  caller is honest about `now`.
- Nothing here is a wire capture. Publish/no-publish equivalence at a real
  interface (A-04, A-12) is not evidenced.
- The online distributed mix path (A-15) does not exist. The chain is
  exercised in-process; a deployment needs per-operator shuffle and
  decryption services with authenticated inter-operator sessions, and the
  fixture bootstrap that holds every identity in one process is not a
  production ceremony.
- Deposits are held in memory. An operator restart loses them, and the client
  resends. That is the intended trade: the alternative is an operator that
  persists publication ciphertexts and a recovery step whose existence
  depends on how much was queued.
- Selective dropping by a malicious entry operator (A-09) is not analysed
  here.
