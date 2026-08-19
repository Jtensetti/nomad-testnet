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

## Transport authentication

The 1200-byte test profile already reserves 48 bytes after the 1152-byte Kyber
ciphertext. Live transport uses exactly that region for a versioned header and
a 128-bit truncated HMAC-SHA-256 tag. The tag binds the signed topology digest,
network, epoch, receiver, sender, stream, batch coordinate, persistent sequence
and all ciphertext bytes. Directed 256-bit keys are generated independently.

The sequence allocator reserves ranges on durable storage before emission. A
64-cell receive window permits bounded UDP reordering and rejects duplicates.
Deleting sequence state requires an epoch and key rotation.

HMAC authenticates Nomad datagrams; it does not conceal IP metadata or defeat
denial of service. Production operators should use stable signed tunnel
addresses (for example WireGuard) and keep the Nomad hop authentication enabled
inside the tunnel.

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
