# Security boundary

## One-way reader architecture

The only supported direction is:

```text
signed public topology -> fixed UDP scheduler -> authenticated raw cache
authenticated raw cache -> offline threshold/reconstruction -> verified object cache
verified object cache -> Nomad Browser local search
```

There is no node, fetcher, share-server or materializer API for a query, basin,
selected document or browser action. The UDP node and public partial fetcher
are separate executables from reconstruction. CI checks their dependency graph.
The reference deployment also starts bootstrap and materializer with
`network_mode: none`; the materializer crosses the boundary only through
read-only raw/partial volumes and its verified-object output volume.

## Transport authentication

The 1200-byte test profile already reserves 48 bytes after the 1152-byte Kyber
ciphertext. Live transport uses exactly that region for a versioned header and
a 128-bit truncated HMAC-SHA-256 tag. The tag binds the signed topology digest,
network, epoch, receiver, sender, stream, batch coordinate, persistent sequence
and all ciphertext bytes. Each operator holds one epoch-scoped X25519 private
key. Directed 256-bit keys are derived locally with X25519 and HKDF-SHA-256,
salted by the signed topology digest and domain-bound to network, epoch, sender
and receiver. The topology authority never generates or receives these hop
keys.

The sequence allocator reserves ranges on durable storage before emission. A
64-cell receive window permits bounded UDP reordering and rejects duplicates.
Deleting sequence state requires an epoch and key rotation.

HMAC authenticates Nomad datagrams; it does not conceal IP metadata or defeat
denial of service. Production operators should use stable signed tunnel
addresses (for example WireGuard) and keep the Nomad hop authentication enabled
inside the tunnel.

## Offline operator ceremony

`nomad-operator init` creates an Ed25519 identity and X25519 epoch key on the
operator's own machine, plus a self-signed public enrollment. `nomad-topology
draft` deterministically orders those enrollments and creates one complete
proposal. Each operator inspects and signs that exact proposal with
`nomad-operator attest`; all attestations blank one another before hashing, so
collection order cannot alter the signed draft. `nomad-topology finalize`
rejects missing, duplicate, mixed-draft or invalid attestations before the
authority signs. `nomad-operator verify` then derives only that operator's
inbound and outbound hop keys and validates them against the final topology.

This removes the topology authority and bootstrap as hop-key distributors. It
does not turn the current in-memory threshold DKG or fixture shuffle into a
distributed ceremony.

## Cache and reconstruction

Only successfully authenticated work cells enter the raw cache. Cover cells are
discarded. Stream and batch coordinates are immutable; a conflicting write is
an equivocation error. The cache is bounded and never consults private state.

Threshold shares and partial proofs are scoped to one committee, epoch and
ciphertext digest. Partial artifacts are public cryptographic outputs, fetched
on a fixed public cadence, and verified again by the networkless materializer.
The final object is accepted only after exact RLNC reconstruction, SHA-256 and
Ed25519 verification.

## Deliberate limitations

- Bootstrap uses Kyber's authenticated Pedersen DKG messages in an honest
  in-memory harness. A production inter-operator DKG transport is not claimed.
- The bundled object is a pre-signed publication fixture, not an anonymous
  publication airlock.
- HTTP partial endpoints are suitable only inside the isolated demo network or
  an authenticated operator tunnel. Proofs prevent forgery and replay across
  batches, but transport blocking remains a denial-of-service vector.
- The repository supplies a multi-host-capable data plane and a single-host
  reproducible deployment. Independent administration and WAN evidence are
  external production gates.
