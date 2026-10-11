# Nomad verifiable batch-mix prototype

This repository carries payloads through independently randomized, verifiable batch shuffles. It uses Kyber's implementation of Andrew Neff's verifiable shuffle of ElGamal pairs. Nomad code does not implement the shuffle proof itself.

The v0.1 profile encodes each 504-byte clear cell as eighteen ElGamal pairs. A mixed representation occupies 1152 bytes and receives 48 bytes of fresh padding to form one 1200-byte wire cell. All chunks of a cell follow the same secret permutation.

Implemented:

- payload-preserving ElGamal re-randomization;
- non-interactive correctness proofs for every shuffle round;
- exact batch-size preservation and fail-closed proof verification;
- an anytrust committee chain: one honest permutation is sufficient to hide the ordering from the other mixers;
- strict 1200-byte serialization for the constant-rate test profile.
- committee/epoch/batch/round-bound shuffle proofs with Ed25519-signed mixer
  receipts and replay/equivocation tracking;
- Kyber's authenticated Pedersen DKG state machine with signed deals and
  responses, plus a dealer fixture kept only for focused unit tests;
- threshold decryption without reconstructing the aggregate secret;
- Fiat-Shamir proofs that each partial decryption uses the member share
  committed in the public committee configuration.

Run go test -race ./..., go vet ./... and go run ./cmd/mix-sim.

## Security boundary

This is a research integration of established constructions, not an audited
Nomad mixnet. The authenticated DKG currently runs through an in-memory
broadcast harness. Production transport, secret-service/process isolation,
membership admission, network-level delay/drop accountability, forward-secure
epoch rotation and independent review remain production gates.
Kyber also requires an application-specific security review before
security-critical deployment.
