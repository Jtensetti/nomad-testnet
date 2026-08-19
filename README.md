# Nomad Testnet

Runnable integration harness for the Nomad v0.1 research reference stack.

## What the composed test does

1. Creates canonical content and a signed object manifest.
2. Produces fixed 504-byte RLNC generation packets over GF(2^8).
3. Encrypts them and performs two independently randomized, verified Neff
   sequence shuffles through Kyber v4.
4. Serializes each ciphertext as an exact 1200-byte wire cell.
5. Emits 16 cells at a 20 ms cadence through the fixed-rate scheduler to four
   UDP loopback peers selected by the public Selection Firewall plan.
6. Captures real datagrams on the receiver side and checks size, destination,
   count, cadence and public-plan conformance.
7. Runs the same stream in an idle reader world and a concurrent private-query
   world, then compares normalized observer traces.
8. Parses, decrypts and RLNC-decodes only the captured cells, then verifies the
   exact SHA-256 commitment and Ed25519 signatures locally.

The workflow also inspects Go's dependency graph: network-domain modules may
not import semantic selection/reconstruction modules, and private-domain
modules may not import the fabric, planner or mix.

## Reproducible private-module composition

The component repositories are private, so a repository-scoped Actions token
cannot check them out. `components/` is a generated source snapshot used only
for integration CI. `COMPONENTS.lock` records the exact source commit for every
snapshot. Component changes must update both the snapshot and lock entry.

## Security status

**Research software, not an audited anonymity network.** The shuffle now
preserves payloads and carries a Kyber Neff proof, but the test profile still
uses a single decryption key. Production gates include independent
cryptographic review, threshold key generation/decryption, committee identity
and accountability, replay/drop/delay handling, WAN/NAT/Sybil work, a
publication airlock, and browser-engine isolation.

The lexical hashing embedder is an offline development baseline, not a semantic
model. A real embedding model must remain local.

```bash
go test -race ./...
go vet ./...
go run ./cmd/nomad-testnet
```
