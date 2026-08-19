# Nomad Testnet

Integration harness for the Nomad research stack.

It exercises the actual sibling modules for:

- constant-rate fixed-size cells
- anytrust batch-mix *simulation*
- GF(2^8) random linear network coding
- semantic basin mapping
- local candidate/reconstruction logic
- Selection Firewall non-interference
- SHA-256 + Ed25519 exact-object verification

## Security status

**Research software. Not an audited anonymity network.** The current mix repository models the unlinkability property and deliberately does not claim deployable mixnet cryptography. This repository must therefore not be used to claim production anonymity.

## Layout

Clone the Nomad repositories side-by-side:

```text
workspace/
  nomad-testnet/
  nomad-anytrust-mix-sim/
  nomad-constant-rate-fabric/
  nomad-local-reconstruction/
  nomad-rlnc/
  nomad-selection-firewall/
  nomad-semantic-basins/
```

The `replace` directives in `go.mod` make local integration explicit and reproducible.

## Run

```bash
go test -race ./...
go vet ./...
go run ./cmd/nomad-testnet
```

Expected invariants include exact content reconstruction and identical externally observable Selection Firewall traces for idle and active reader worlds.

## What this testnet does not yet provide

- deployable verifiable re-randomizing mix cryptography
- real UDP peer discovery or NAT traversal
- distributed persistence
- browser engine integration
- a security proof for the composed implementation
