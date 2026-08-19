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
| LIVE-01 | A pinned authority signature and every operator attestation bind network ID, epoch, traffic class, endpoints, identity keys and peer plan. | Topology positive/tamper tests. | PENDING CI |
| LIVE-02 | Every node receives only its own Ed25519 identity and directed 256-bit peer MAC keys; secret files with group/other access fail closed. | Secret-validation tests and per-operator volumes. | PENDING CI |
| LIVE-03 | Every emitted UDP payload is exactly 1200 bytes at the signed interval, including idle periods; missed deadlines fail rather than catch up. | Scheduler tests and packet capture. | PENDING CI |
| LIVE-04 | The existing 1152-byte mix ciphertext is unchanged; the 48-byte padding region authenticates stream, batch coordinate, sender and persistent sequence with a 128-bit HMAC-SHA-256 tag. | Hop round-trip and tamper tests. | PENDING CI |
| LIVE-05 | Unknown sources, wrong sizes, invalid tags, wrong receivers, duplicate sequences and expired replay-window entries are rejected before cache or relay. | Negative hop/node tests and counters. | PENDING CI |
| LIVE-06 | Relay queues and stream counts are publicly bounded; cover cells are not cached; cache pressure cannot change the emission schedule. | Queue/cache tests and dependency inspection. | PENDING CI |
| LIVE-07 | Raw cache coordinates are immutable, atomically written and committed by a 128-bit stream digest over the complete ordered ciphertext batch. | Cache idempotence/equivocation tests. | PENDING CI |
| LIVE-08 | The UDP node import graph contains no semantic selection or reconstruction package. The materializer directly imports no socket or network-control package. | CI `go list` gate. | PENDING CI |
| LIVE-09 | Three or more operators run with distinct identities, endpoints, caches, sequence state and threshold shares. | Eight-process Compose topology. | PENDING CI |
| LIVE-10 | Partial proofs move through a separate fixed-cadence public fetcher. The offline materializer never contacts an operator. | Compose topology and dependency gate. | PENDING CI |
| LIVE-11 | A 2-of-3 threshold decrypt requires unique, proof-valid shares bound to committee, epoch and batch; no aggregate secret is reconstructed. | Kyber threshold tests and live pipeline test. | PENDING CI |
| LIVE-12 | Every operator performs one contextual, signed Kyber Neff shuffle and the materializer verifies the full chained transcript. | Descriptor transcript tests. | PENDING CI |
| LIVE-13 | Acceptance requires exact RLNC dimensions, SHA-256 commitment and Ed25519 signature over `nomad-object-v1 || SHA256(payload)`. | End-to-end materializer test. | PENDING CI |
| LIVE-14 | Output is an immutable `.nomadobject` already trusted by the current Nomad Browser demo trust anchor. | Compose fixture and output digest. | PENDING CI |
| LIVE-15 | Race tests, vet, module tidiness, snapshot checks, container isolation and pcap verification pass on one commit. | GitHub Actions run. | PENDING CI |

All LIVE gates must be `MET` on the same commit before a live-testnet release is
tagged.

## External production gates

These cannot be truthfully manufactured inside one repository or one Docker
administrator:

- at least three legal/administrative operators control separate hosts,
  credentials, networks and incident processes;
- signed production endpoints are reachable over a measured WAN profile, with
  NAT, loss, reordering, clock faults and regional outages exercised;
- DKG messages run between isolated operator processes instead of the current
  authenticated in-memory ceremony used by bootstrap;
- third-party cryptographic, systems, browser and traffic-analysis review is
  closed with no unresolved critical or high findings;
- publication airlock, Sybil/admission policy, forward-secure epoch rotation,
  revocation, long-duration pcap evidence and operational response are live.

The single-host Compose network is evidence for process/key separation and a
reproducible integration path. It is not evidence of independent governance.
