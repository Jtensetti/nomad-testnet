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
