# Definition of Done: distributed epoch DKG

Last reviewed: 2026-08-19.

This gate closes the software blocker between independently held operator
identities and the live fabric-to-cache threshold path. It is narrower than the
project-wide production definition of done in `nomad-protocol`: passing it does
not establish independent administration, anonymous publication or a reviewed
production anonymity claim.

## Acceptance rule

A criterion is `MET` only when it exists in the live data path, has a negative
test, and the same commit passes race, vet and multi-process Compose evidence.
The ceremony must fail closed; partial membership, disagreement, late start,
equivocation, invalid storage or an unverifiable share cannot activate an epoch.

| ID | Required result | Evidence | Status |
|---|---|---|---|
| DKG-01 | The signed topology binds the ordered membership, threshold, 256-bit session ID, absolute start, phase duration, HTTPS endpoint and a dedicated prime-subgroup DKG identity for every operator. | Topology validation, tamper and low-order-point tests. | MET |
| DKG-02 | DKG private identities are distinct from Ed25519 node identities and X25519 hop keys, stored only in a 0600 operator secret and verified against the signed topology. | Secret-schema, permission and mismatch tests. | MET |
| DKG-03 | The process uses Kyber v4's Pedersen `Protocol` state machine and Schnorr packet authentication; Nomad does not implement a replacement DKG primitive. | Dependency pin, component snapshot digest and protocol integration test. | MET |
| DKG-04 | Every packet has a bounded canonical wire encoding and an outer Ed25519 signature over network, topology digest, epoch, session, phase, sender and payload digest. | Mutation, context, canonicalization and sender-binding tests. | MET |
| DKG-05 | The board broadcasts to every signed member, disables environment proxies and redirects, requires TLS 1.3 for HTTPS, and retries only until the public signed deadline. | Transport inspection and three-process TLS ceremony. | MET |
| DKG-06 | No message is accepted before the signed ceremony start or after its phase deadline. Missing delivery aborts instead of silently reducing the committee. | Schedule and timeout tests. | MET |
| DKG-07 | The append-only 0600 journal makes identical retries idempotent, treats a second sender/phase value as fatal equivocation, and refuses to resume an interrupted ephemeral session. | Replay, equivocation and restart tests. | MET |
| DKG-08 | Activation requires the exact ordered topology membership in QUAL; threshold-only or partial QUAL success is rejected. | Full-QUAL integration and missing-member failure tests. | MET |
| DKG-09 | Every operator independently derives the same public committee/transcript and signs the same manifest; activation requires one valid result attestation from every member. | Identical-certificate and split-view rejection tests. | MET |
| DKG-10 | Each operator writes only its own private threshold share, and loading proves that the private scalar matches the public share in the certified polynomial. No aggregate secret is reconstructed. | Distinct-share, permission, mismatch and partial-proof tests. | MET |
| DKG-11 | Batch descriptor v2 embeds the exact all-operator DKG certificate; the share service and networkless materializer reject any descriptor/share not bound to it. | Authority-resigned certificate-tamper test and fabric-to-cache reconstruction. | MET |
| DKG-12 | The isolated Compose gate runs three DKG processes over TLS, records one identical public certificate and three distinct share hashes, then uses those artifacts for the live fixed-cadence fabric-to-cache object. | GitHub Actions packet/process/DKG evidence archive. | MET |

## Evidence that cannot come from this repository

Production gate `PROD-05` additionally requires at least five independently
administered operators, real WAN endpoints, witnessed key custody and erasure,
rotation and compromise drills, and independent cryptographic review. A
single-host Compose run proves protocol/process separation only; it cannot
prove separate organizations or anytrust governance.
