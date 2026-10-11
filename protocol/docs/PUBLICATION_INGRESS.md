# Publication ingress: spike finding and uplink profile (draft v1)

Status: DRAFT. Records the result of the publication-ingress spike
(DEC-008) and specifies the client uplink traffic class that follows from
it. Not active protocol until the full airlock lands.

## Why the spike ran first

The execution plan originally assumed publication fragments could ride
"pre-existing fixed-size fixed-cadence cells". An internal evaluator
challenged that: the fixed-cadence fabric in the tree is
operator-to-operator, clients have only a downlink fetcher, and a
publisher-facing uplink does not exist. Since the shape of that uplink
determines what the epoch descriptor must encode, it was prototyped before
the descriptor was frozen.

## Finding: the operator cell profile cannot carry publication traffic

Measured, not assumed, in `nomad-testnet/live/uplink` (test
`TestCurrentProfileWorkCellsAreDistinguishable`). Cells were built exactly
as `live/node` builds them, and two independent passive classifiers were
run over 16 work cells and 16 cover cells:

| Classifier | Feature | Result |
|---|---|---|
| Header flag | `Flags & FlagWork` in the cleartext hop header | 32/32 |
| Ciphertext structure | payload region parses as compressed group elements | 32/32 |

Both separated work from cover perfectly on the version 1 profile. The hop
header was authenticated but not encrypted, so bytes 1152..1199 stated in
the clear whether a cell carried work, along with its stream identifier and
batch coordinates; and a work payload is a batch of ElGamal ciphertext
points while cover is uniform random, so even with the header removed the
two were trivially separable.

Hop cell version 2 encrypts the whole cell per link (see DEC-016), and
`live/uplink/distinguisher_test.go` now runs both classifiers against sealed
cells and requires both to fail. The measurement above is kept as the
before, on a cell in memory, because it is what the uplink profile was
designed against and because the two profiles solve different problems: the
relay profile is now indistinguishable to an observer of a *link*, while the
uplink profile is indistinguishable to the receiving operator as well.

**This does not contradict the reader claim the project already makes.**
Operator relay work is driven by public replication policy, so the
observable is the same whichever object a reader is interested in, and
reader non-interference is unaffected. What the finding establishes is
narrower and decisive: this cell profile cannot carry publisher uplink
traffic, because there the existence of work *is* the private fact that
must not be observable. Had the airlock been built on the assumption of
reuse, the resulting system would have announced every publication in
cleartext.

## Uplink profile v1

An uplink cell is exactly `fabric.CellSize` (1200) bytes:

| Region | Bytes | Content |
|---|---:|---|
| Sequence | 8 | big-endian counter, cleartext |
| Sealed body | 1192 | AES-256-GCM ciphertext and tag |

The sealed body covers a 1176-byte plaintext: a 1152-byte inner committee
ciphertext followed by 24 zero bytes. The sequence is the AEAD's associated
data, and the nonce is derived deterministically from the session key and
that sequence, so nothing random needs transmitting and a nonce cannot
repeat without a sequence repeat.

Two properties follow, and both are tested:

1. **A network observer cannot distinguish work from cover.** Every cell is
   a counter followed by a pseudorandom string of fixed length. Both
   classifiers above fail against it.
2. **The entry operator cannot distinguish work from cover either.** Cover
   is a *real* committee encryption of the reserved empty fragment,
   produced on the identical code path. After stripping the outer layer the
   entry operator holds a 1152-byte committee ciphertext in both cases.
   Only threshold decryption reveals which it was, and by then the mix
   boundary stands between ingress and released plaintext.

The second property is what keeps a malicious entry operator from being a
publication oracle. Its cost is that cover cells are mixed and threshold
decrypted like real ones; that cost is accepted, because the alternative is
an operator that learns exactly when each client published.

Session keys are derived by HKDF from the client's key agreement with the
entry operator, bound to network, epoch, topology digest and operator slot,
so a captured session cannot be replayed into another epoch or against
another operator.

## Session establishment, in band

The session used to begin with a secret both parties already had: the
publisher read 32 bytes from a file and the entry operator read the same 32
bytes from its own. How they came to be the same bytes was outside the
protocol, and it needed a channel that distributes a per-publisher secret to
a named operator before anything can be published -- a channel that knows who
publishes what.

The publisher now agrees with the entry operator's static X25519 key from the
signed topology, which is the same `kex_key` the pairwise hop keys already
use. The first cell of a session carries the handshake:

| Region | Bytes | Content |
|---|---:|---|
| Sequence | 8 | big-endian counter, cleartext, as in every uplink cell |
| Ephemeral key | 32 | the publisher's X25519 public key, cleartext |
| Sealed body | 1160 | AES-256-GCM over 1144 zero bytes, and its tag |

The additional data is the sequence and the ephemeral key together. The
sealed region **must be all zero** and is checked: a handshake is an
introduction and carries nothing else, so there is no room in it for a covert
channel from a party the operator cannot identify.

Three values are derived from the agreement, by HKDF-SHA-256 with the
topology digest as salt and an info string of the domain, the network
identifier length-prefixed, the epoch, the entry operator slot and the
ephemeral public key:

| Domain | Produces |
|---|---|
| `nomad-uplink-handshake-v1` | the key that seals the handshake cell |
| `nomad-uplink-handshake-secret-v1` | the 32-byte session secret, fed unchanged into the existing session-key derivation |
| `nomad-uplink-handshake-id-v1` | the public session identifier the airlock derives deposit slots from |

They must be three distinct domains. The session identifier is public -- it
appears in airlock state an operator can see -- so a domain collision with
the secret would publish key material.

Feeding the derived secret into the unchanged `nomad-uplink-session-v1`
derivation is deliberate: the data path, its published test vectors and its
second implementation do not move because the way the secret is obtained
changed.

**The handshake is one-sided, and that is the direction this system needs.**
The publisher authenticates the operator and proves nothing about itself. The
entry operator must not learn who is publishing -- that is what the airlock
exists for -- so its only guarantee is that somebody who verified the topology
is speaking to it, and everything that bounds abuse afterwards is per session
rather than per identity.

A responder refuses an ephemeral key it has already accepted in this epoch. A
handshake is a cell like any other, so a replay would otherwise establish a
second session on the same key, and the data path's nonces come from a
sequence: the same key twice is the same nonces twice. It also bounds how many
sessions it will hold, because accepting handshakes without a limit turns a
cheap cell into unbounded state.

On the wire a handshake is 1200 bytes with an 8-byte counter, like every other
uplink cell, so an observer cannot tell a session beginning from a session
continuing.

## What is still open

- The entry operator service exists: `cmd/nomad-entry` runs the responder
  against the deposit mailbox, and the publication path has been exercised as
  two separate processes on a real socket with a packet capture. What is not
  exercised is separate *hosts* -- loopback is a real interface and these are
  real processes, but WAN loss, reordering and a network adversary are not.
- `EpochDescriptor.uplink_profile` remains reserved and must stay empty
  until this profile is finalized; the descriptor already refuses a
  non-empty value.
- Cadence parameters (interval, and whether a client uplink runs whenever
  the client is online) are not yet fixed. Participation visibility is
  already inside the declared threat model, but the exact rate is a
  deployment decision that needs the WAN campaign in Workstream E.
- A packet-level capture of a running publisher now exists, judged by the same
  fail-closed rule the relay fabric's capture is judged by. It is a single-world
  capture: the two-world comparison, which is what would establish that private
  activity does not change the wire, is still missing for this path.
- **A refused deposit destroys publication work.** A publisher emits at a
  constant cadence across a deposit window that closes, so a fixed share of
  every period is refused -- 25% at the default schedule. The airlock is
  idempotent so a client can retry, but only a byte-identical retransmission of
  the sealed cell is: re-sealing a fragment produces a fresh encryption to the
  committee, which is a different payload for a held slot and is refused as a
  conflict. `publish.Queue.Next` removes the fragment as it hands it out and
  `deposit.Drain` retains nothing, so the retry cannot be performed. This is a
  release blocker; see DEC-020 for the shape a fix has to fit.

## Non-claims

- Cell indistinguishability is not publication anonymity. It removes one
  necessary leak; the deposit, mixing, threshold release and timing
  separation still have to hold, and none of that is implemented yet.
- Nothing here addresses an active adversary that selectively drops a
  target's uplink; that analysis belongs with the airlock's failure
  behavior.
