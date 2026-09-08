# Security properties under investigation

These are target properties with bounded implementation evidence, not proven
system-wide guarantees.

## Reader action non-interference

Let R be private reader state and P be public network-planning state. The
required dependency is:

    observable emission plan = f(P)

and never:

    observable emission plan = f(P, R)

The Go planner API contains only P. CI also rejects dependency paths from the
network packages into semantic selection/reconstruction and from private
packages into planner/fabric/mix.

The composed loopback experiment schedules the same prefilled network-domain
queue in idle and active worlds and in two distinct query worlds. Receiver-side
capture checks count, 1200-byte size, peer slot, encrypted payload, plan digest
and bounded cadence. Those tests currently pass.

This evidence is narrower than end-to-end non-interference. It does not cover a
browser engine, kernel packet timestamps, a WAN, congestion/churn, resource
contention, cache state across long periods or a global deployment adversary.

## Object verification

A reconstructed byte sequence is never accepted merely because an RLNC decoder
succeeds or a basin is close. Acceptance checks signed manifest metadata, exact
length, SHA-256 content root, domain-separated Ed25519 object signature and
domain-separated manifest signature.

This authenticates an object relative to the embedded public key. SiteID key
discovery, rotation, revocation and human-facing identity policy are separate.

## Mix payload preservation and unlinkability

The v0.1 mix encrypts 18 chunks per cell as ElGamal point pairs and delegates
the shared-permutation proof to Kyber's Andrew Neff sequence shuffle. Tests
establish that:

- decrypted input and output payload multisets match;
- ciphertext batch digests change;
- tampered outputs fail proof verification;
- two independently randomized verified rounds compose in the testnet.

The privacy assumption is anytrust: at least one relevant mixer must choose its
permutation and randomness honestly. The reference implementation still uses a
single test decryption key and has no DKG, threshold decryption, authenticated
committee protocol, replay/drop/delay accountability or independent audit.
Therefore it is not a deployable mixnet claim.

## RLNC integrity boundary

An inconsistent dependent symbol is rejected immediately. An innovative
polluted symbol can still enter the decoding basis and waste or poison a
generation. Exact post-reconstruction verification detects the wrong object but
does not provide pollution resistance or availability against an injector.

## Browser local-resource boundary

Nomad-browser accepts only verified immutable objects and resolves renderer
paths through a signed bundle. Its egress contract denies ordinary schemes and
browser background network capabilities by default.

This is an integration contract. It becomes an endpoint security property only
after Firefox/Chromium route every relevant engine and service path through it
and packet-level negative tests observe no egress.

## Publisher unlinkability

Reader non-interference does not remove the causal fact that new information
enters the network somewhere. The testnet publisher is a local fixture, not an
airlock. A global active adversary may selectively isolate candidate publishers
and create an availability oracle before independent replication.

Any publisher-anonymity claim requires a separately specified deposit/airlock,
time separation, failure model and adversary analysis.
