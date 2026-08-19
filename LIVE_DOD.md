# Live fabric-to-cache release gate

This gate covers a deployable reader-side Nomad testnet: public encrypted work
crosses separately keyed operator processes at a fixed cadence, becomes an
immutable raw cache, receives independently proved threshold-decryption shares,
is reconstructed locally, and is exported as the signed object format consumed
by Nomad Browser.

It does **not** redefine “production anonymity network.” Anonymous publication,
independently administered operators, WAN soak time, browser notarization and
independent review remain separate production gates.

## Automated gates

| ID | Requirement | Required evidence | Status |
|---|---|---|---|
| LIVE-01 | A pinned authority signature and every operator attestation bind the same complete draft: membership, validity, network ID, epoch, traffic class, endpoints, identity/KEX keys and every peer plan. | Independent ceremony and topology tamper tests. | MET |
| LIVE-02 | Every node receives only its own Ed25519 identity and epoch-scoped X25519 private key. Directed 256-bit hop MAC keys are derived locally with X25519+HKDF and bound to topology, epoch, sender and receiver; secret files with group/other access fail closed. | Cross-operator KDF agreement, mismatch tests and per-operator volumes. | MET |
| LIVE-03 | Every emitted UDP payload is exactly 1200 bytes at the signed interval, including idle periods; missed deadlines fail rather than catch up. | Scheduler tests and packet capture. | MET |
| LIVE-04 | The existing 1152-byte mix ciphertext is unchanged; the 48-byte padding region authenticates stream, batch coordinate, sender and persistent sequence with a 128-bit HMAC-SHA-256 tag. | Hop round-trip and tamper tests. | MET |
| LIVE-05 | Unknown sources, wrong sizes, invalid tags, wrong receivers, duplicate sequences and expired replay-window entries are rejected before cache or relay. | Negative hop/node tests and counters. | MET |
| LIVE-06 | Relay queues and stream counts are publicly bounded; cover cells are not cached; cache pressure cannot change the emission schedule. | Queue/cache tests and dependency inspection. | MET |
| LIVE-07 | Raw cache coordinates are immutable, atomically written and committed by a 128-bit stream digest over the complete ordered ciphertext batch. | Cache idempotence/equivocation tests. | MET |
| LIVE-08 | The UDP node import graph contains no semantic selection or reconstruction package. The materializer directly imports no socket or network-control package. | CI `go list` gate. | MET |
| LIVE-09 | Three or more operators run with distinct identities, endpoints, caches, sequence state and threshold shares. | Eight long-running processes plus networkless one-shot bootstrap in Compose. | MET |
| LIVE-10 | Partial proofs move through a separate fixed-cadence public fetcher. The offline materializer never contacts an operator. | Compose topology and dependency gate. | MET |
| LIVE-11 | A 2-of-3 threshold decrypt requires unique, proof-valid shares bound to committee, epoch and batch; no aggregate secret is reconstructed. | Kyber threshold tests and live pipeline test. | MET |
| LIVE-12 | The fixture descriptor contains one contextual, identity-signed Kyber Neff shuffle for every operator, and the materializer verifies the full chained transcript. | Descriptor transcript and end-to-end tests. | MET |
| LIVE-13 | Acceptance requires exact RLNC dimensions, SHA-256 commitment and Ed25519 signature over `nomad-object-v1 || SHA256(payload)`. | End-to-end materializer test. | MET |
| LIVE-14 | Output is an immutable `.nomadobject` already trusted by the current Nomad Browser demo trust anchor. | Compose fixture and output digest. | MET |
| LIVE-15 | Race tests, vet, module tidiness, snapshot checks, container isolation and pcap verification pass on one commit. | GitHub Actions run. | MET |
| LIVE-16 | Operators can generate credentials independently, exchange only self-signed public enrollments, attest one common draft offline and verify their own derived live configuration without disclosing private keys to the topology authority. | `nomad-operator`, `nomad-topology` and ceremony CLI/unit e2e. | MET |

All LIVE gates are `MET`. The release job is dependency-gated on both CI jobs,
so it can tag only the same commit that produced unit and live packet evidence.
The measured baseline is recorded in `RELEASE_EVIDENCE.md`.

## External production gates

These cannot be truthfully manufactured inside one repository or one Docker
administrator:

- at least three legal/administrative operators control separate hosts,
  credentials, networks and incident processes;
- signed production endpoints are reachable over a measured WAN profile, with
  NAT, loss, reordering, clock faults and regional outages exercised;
- DKG messages run between isolated operator processes instead of the current
  authenticated in-memory ceremony used by bootstrap;
- each shuffle round is executed under the corresponding operator's separate
  administration; the fixture bootstrap currently holds all demo identities;
- third-party cryptographic, systems, browser and traffic-analysis review is
  closed with no unresolved critical or high findings;
- publication airlock, Sybil/admission policy, forward-secure epoch rotation,
  revocation, long-duration pcap evidence and operational response are live.

The single-host Compose network is evidence for process/key separation and a
reproducible integration path. It is not evidence of independent governance.
