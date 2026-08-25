# Wire compatibility matrix

Every versioned format a Nomad release reads or writes, what it is, and how a
peer that does not recognise it must behave. `TestCompatibilityMatrixCoversEveryWireVersion`
fails if a version constant exists in the source and is missing here, so this
document cannot silently fall behind the code.

**There is one supported version of each format.** Nomad does not negotiate
versions and does not accept a version it was not built for: an unrecognised
version string is refused, never downgraded to. That is the whole downgrade
rule, and it is why the "accepted" column below has a single entry per row. A
format changes by bumping its version and refusing the old one, which forces a
coordinated epoch change rather than a silent split.

| Format | Accepted | Carried in | Refusal on mismatch |
|---|---|---|---|
| `nomad-live-topology-v3` | v3 only | signed topology document | `unsupported topology version`; v2 is refused |
| `nomad-topology-watermark-v1` | v1 only | node-local state | refuses to start rather than treat an unreadable watermark as permission |
| `nomad-topology-attestation-v2` | v2 only | per-operator attestation inside the topology | attestation verification fails, so the whole topology is refused |
| `nomad-operator-enrollment-v2` | v2 only | operator ceremony enrollment | enrollment refused |
| `nomad-operator-revocation-v1` | v1 only | signed revocation | revocation refused, so the operator stays in the set |
| `nomad-operator-secrets-v3` | v3 only | operator-local secret file | node refuses to start |
| `nomad-epoch-descriptor-v1` | v1 only | epoch chain | descriptor refused; the chain does not advance |
| `nomad-epoch-descriptor-digest-v1` | v1 only | digest domain separator | digest mismatch, descriptor refused |
| `nomad-epoch-activation-v1` | v1 only | activation statement | activation refused |
| `nomad-epoch-approval-v1` | v1 only | quorum approval | approval not counted toward quorum |
| `nomad-epoch-erasure-v1` | v1 only | erasure statement | statement refused |
| `nomad-dkg-manifest-v1` | v1 only | DKG session manifest | DKG does not start |
| `nomad-dkg-envelope-v1` | v1 only | DKG transport envelope | packet refused |
| `nomad-dkg-result-vote-v1` | v1 only | DKG result vote | vote not counted |
| `nomad-dkg-certificate-v1` | v1 only | committee certificate | certificate refused, no committee |
| `nomad-threshold-share-v2` | v2 only | operator-local threshold share | share refused before first use |
| `nomad-partial-decryption-v1` | v1 only | partial decryption proof | partial refused, not counted toward threshold |
| `nomad-partial-fetch-plan-v1` | v1 only | public fetch plan | plan refused |
| `nomad-batch-descriptor-v3` | v3 only | signed batch descriptor | descriptor refused; v2 lacked source commitments |
| `nomad-publication-entry-v1` | v1 only | publication queue entry | entry refused |
| `nomad-publication-fragment-v1` | v1 only | publication fragment | fragment refused |
| `nomad-seed-bundle-v1` | v1 only | public seed bundle | bundle refused |
| `nomad-conformance-v1` | v1 only | golden vector corpus | corpus check fails |

## Domain separators and derivation labels

These are not document versions but they are equally frozen: each is a byte
prefix inside a signature, MAC or digest, so changing one invalidates every
value ever produced under it and partitions the network as surely as a format
change. They are listed so a freeze covers them, and because a second
implementation that guesses one produces valid-looking signatures nobody
accepts.

| Label | Binds |
|---|---|
| `nomad-topology-authority-v3` | the authority signature over a topology |
| `nomad-topology-digest-v3` | the canonical topology digest |
| `nomad-topology-draft-v3` | the draft digest operators attest before signing |
| `nomad-operator-attestation-v3` | one operator's attestation of a topology |
| `nomad-epoch-committee-v2` | the committee identity inside a certificate |
| `nomad-dkg-manifest-digest-v1` | the DKG session manifest digest |
| `nomad-dkg-envelope-signature-v1` | a DKG transport envelope signature |
| `nomad-dkg-result-attestation-v1` | an operator's attestation of a DKG result |
| `nomad-batch-descriptor-authority-v1` | the authority signature over a batch descriptor |
| `nomad-partial-fetch-plan-authority-v1` | the authority signature over a fetch plan |
| `nomad-hop-cell-v1` | the hop cell header authentication |
| `nomad-hop-mac-kdf-v2` | derivation of the per-hop MAC key |
| `nomad-live-stream-v1` | the stream identifier over an ordered cell set |
| `nomad-uplink-session-v1` | an uplink session identifier |
| `nomad-uplink-nonce-v1` | uplink nonce derivation |
| `nomad-airlock-deposit-id-v1` | a deposit identifier derived from session and sequence |

## Component library labels

The vendored component modules carry their own frozen labels. They are part of
the same freeze because a Nomad node links them: a change to any of these
changes what the node produces on the wire, even though the label never appears
in a document a peer parses by name.

| Label | Binds |
|---|---|
| `nomad-mix-batch-v1` | the ElGamal batch encoding |
| `nomad-mix-round-context-v1` | one shuffle round's committee, epoch, batch and round |
| `nomad-mix-round-receipt-v1` | a mixer's signed receipt for a round |
| `nomad-mix-receipt-digest-v1` | the receipt digest |
| `nomad-mix-non-receipt-v1` | one observer's signed statement that a mixer's round had not arrived by the round's public deadline |
| `nomad-neff-sequence-shuffle-v1` | a Neff sequence shuffle proof |
| `nomad-contextual-neff-shuffle-v1` | the same proof bound to its round context |
| `nomad-mix-sequence-challenge-v1` | the shuffle challenge derivation |
| `nomad-threshold-decryption-v1` | a partial decryption proof |
| `nomad-threshold-decryption-context-v1` | that proof's committee and batch binding |
| `nomad-authenticated-dkg-transcript-v1` | the in-memory DKG transcript |
| `nomad-authenticated-distributed-dkg-transcript-v2` | the networked DKG transcript |
| `nomad-object-v1` | a published object envelope |
| `nomad-manifest-v1` | an object manifest |
| `nomad-generation-v1` | an RLNC generation identifier |
| `nomad-rlnc-source-commitment-v1` | a per-source-symbol commitment |
| `nomad-basin-hyperplane-v1` | a semantic basin hyperplane |
| `nomad-selection-firewall-plan-v1` | an emission plan |
| `nomad-observable-plan-v1` | the public observable plan |

## Operator endpoint grammar and canonical form

Two implementations must agree on which topologies are admissible, and the
operator distinctness check makes that depend on how an endpoint is parsed. A
document one implementation admits as three operators and another as two has not
been agreed on, which is the same failure duplicate JSON keys produce and is
refused for the same reason.

An operator's `endpoint` is `host:port`; `partial_endpoint` and `dkg_endpoint`
are URLs whose host and port are subject to the identical rules. **No lookup is
performed at any point**: admission is a function of the document's bytes.

**Port.** Base-ten digits only, 1 to 65535. Leading zeros are accepted and
denote the same port. `+4200`, `0x1068`, `4_200`, whitespace and non-ASCII
digits are refused. Port `0` is refused: it names nothing a peer can send to.

**Host, as an address.** Any address `netip.ParseAddr` accepts, then:

- IPv4-mapped IPv6 is folded to the IPv4 address it means, so `127.0.0.1` and
  `[::ffff:127.0.0.1]` are one host.
- Textual variation is folded by RFC 5952 canonical form, so `[::1]`,
  `[0:0:0:0:0:0:0:1]` and `[2001:0db8::0001]` fold as expected.
- A zone (`fe80::1%eth0`) is **refused**. A node keys inbound peers on address
  and port with the zone dropped, so admitting one would promise a distinctness
  the runtime does not deliver.
- Unspecified (`0.0.0.0`, `::`), multicast and the IPv4 limited broadcast
  address are **refused**: none names a peer.
- Loopback (`127.0.0.0/8`, `::1`) folds to a single reserved host key.

**Host, as a name.** Letter-digit-hyphen only, ASCII: labels of 1 to 63 bytes
from `[A-Za-z0-9-]`, no label beginning or ending with a hyphen, at most 253
bytes in total, and at most one trailing dot, which is the root label and is
removed. Case folds ASCII-only. The top-level label must not be all digits
(RFC 1123 2.1), so `2130706433` and `0177.0.0.1` are refused rather than
admitted as names that other parsers read as `127.0.0.1`. `localhost`
(RFC 6761) folds to the same reserved key as a loopback literal.

**No fallback.** A bracketed host that is not a valid address is refused, never
reinterpreted as a name. Embedded NUL bytes, spaces, underscores and non-ASCII
characters are refused.

**Distinctness.** Two operators may not share one canonical `host:port`. For the
URL fields the key is the canonical authority alone: the scheme and the path are
validated but are not part of the identity, so `http://h:4300`,
`https://h:4300` and `http://h:4300/` are one endpoint.

**What this does not establish.** Two operators at different ports on one host
are two entries; two hostnames pointing at one machine are indistinguishable
from the document. Neither operator independence nor trust-domain separation
follows from this check.

## Unversioned formats

Three wire objects carry no version string, because they are fixed-width binary
frames whose shape is pinned by the golden vectors rather than by a field:
the 1200-byte hop cell, the uplink cell frame, and the RLNC packet. A change to
any of them changes the corpus digest, which is checked in CI on two
architectures. They cannot be versioned in band without spending bytes that the
fixed cell size does not have.

## What this matrix is not

It records what the code accepts. It is not evidence that a second
implementation reading these formats would interoperate: nothing outside this
repository has parsed them. That is PROD-03's gate and EB-5's dependency.

## The second implementation

`reference/nomadwire.py` implements the `hop-cell-v1` wire format a second
time: another language, no shared build, no dependency beyond the Python
standard library, and written from `nomad-protocol/docs/PROTOCOL.md` rather
than from this repository's Go. That restriction is what makes it worth
having. An implementation that consults the first one tests nothing about
whether the specification is sufficient to build from, which is the question
PROD-03 asks.

`reference/crosscheck.py` runs four directions, and
`live/conformance/crossimpl_test.go` runs it:

| | What it establishes |
|---|---|
| A | The second implementation verifies every authenticated vector in the committed corpus, and re-seals each one to the same bytes. Verifying alone would show only that it can be convinced. |
| B | The second implementation produces cells the first has never seen; the Go test verifies them and recomputes their stream ID. |
| C | Sixteen mutations and cross-context replays are refused. Two implementations that accept everything also "interoperate". |
| D | The second implementation verifies cells the first sealed *at test time*, not months ago. |

Direction D exists because of a gap the other three did not close. Mutating
the header field offsets in the Go encoder was invisible to every test in the
conformance package: direction A reads a committed snapshot, and direction B
only exercises the Go *decoder*. Only a fresh seal, verified independently,
catches an encoder that drifts after the corpus was written. All five
divergence mutations tried — MAC domain, header layout, stream-ID domain,
stream-ID preimage, and sealing without zeroing the tag region — are caught.

### What writing it found

Three defects in the specification and one in this corpus, none of which the
corpus alone would have revealed:

1. `docs/PROTOCOL.md` described bytes 1152..1200 as "random representation
   padding, fresh filler, not application data". They are the hop header. An
   implementation built from that text could not interoperate at all.
2. It did not say the tag region is zeroed before the tag is computed. The
   ambiguity is silent: both readings produce sixteen bytes and only one
   matches.
3. It did not say the stream-ID hash covers the batch size. A wrong stream ID
   still carries a valid tag over itself, so this shows up only when two
   implementations exchange work cells.
4. This corpus published authenticated cells without the key or the context
   the tag binds. A MAC vector without its key demonstrates that the encoder
   is self-consistent and nothing more. The vectors now carry
   `conformance_hop_key`, `topology_digest`, `network_id`, `epoch` and
   `receiver`. That key exists to be published — it is derived from a fixed
   label in a public repository and authenticates nothing outside this corpus
   — and it must never appear in a topology or an operator secret.

### The signed topology, and what specifying it took

`reference/nomadtopology.py` is the second format: the document that is the
root of trust for everything else. Direction E of the cross-check verifies both
corpus topologies, reproduces their digests byte for byte, refuses five
structural mutations and requires four content changes to move the digest.

Reproducing the digest is the check that carries. It is a SHA-256 over the
canonical encoding, so matching it means having produced those bytes exactly.
Two mutations of the Go encoder show that is not a formality: changing the
digest domain is caught, and so is *sorting the members* — the shape a
well-meaning "canonicalise this properly" change would take, which would
silently stop every existing verifier from agreeing.

Writing it needed the specification written first, because there was none.
`docs/PROTOCOL.md` described the wire cell, the RLNC packet, the mix batch, the
object manifest and the basin, and said nothing about the document they all
depend on. And the encoding it signs is the output of Go's `encoding/json` on
its own structs: member order from the struct declaration rather than sorted,
`<`, `>` and `&` escaped in a way no JSON specification requires, and an absent
array as `null`. That is written down now, and recorded as a defect that should
not survive the freeze — a canonical encoding defined by one language's library
defaults is not a specification, and the escaping is invisible until a
`network_id` or an endpoint contains an ampersand.

One further trap, because it is the first mistake available here: the file is
pretty-printed and the signed encoding is not. A verifier must parse and
re-encode; hashing the file as found verifies nothing.

The signature check uses `cryptography` where it is importable rather than
hand-rolling Ed25519 for a conformance tool. Where it is absent the
canonical-encoding and digest checks still run, and those are the ones that
test interoperability.

### What it does not establish

The second implementation covers `hop-cell-v1` and `topology-document-v3`. The
object manifest and the uplink cell profile have vectors in this corpus but no
second implementation, so interoperability for those is unevidenced.

And both implementations were written by the same author. That tests whether
the specification is sufficient to build from — it demonstrably was not, which
is the point — but it does not test what two independent teams would: that
the specification is read the same way by someone who did not write it. PROD-03
stays PARTIAL for that reason.

