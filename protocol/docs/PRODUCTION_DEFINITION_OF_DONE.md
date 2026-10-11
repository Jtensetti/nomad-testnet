# Definition of Done: production Nomad anonymity network

Last reviewed: 2026-08-19.

## Meaning of production-ready

Nomad is production-ready only when a supported end-user release can operate on
a real multi-party network and the complete reader and publisher paths satisfy
the security, reliability and operational gates below. A laboratory component,
loopback test, design document or passing unit test is evidence, but it is not
by itself production evidence.

The release must fail closed. If cadence, verification, mix quorum, local model,
cache integrity or browser isolation cannot be maintained, the client must stop
the affected operation without falling back to ordinary networking.

Current score: **2/30 production gates MET.**

The machine-readable source of status and evidence is
[`production/readiness.json`](../production/readiness.json). CI rejects missing
criteria, unknown status values, status drift between this document and the
registry, and a `MET` claim without immutable evidence.

## Evidence rule

A gate may be `MET` only when all of the following are true:

1. the behavior exists in the release-candidate data path;
2. a test exercises the behavior at the boundary named by the criterion;
3. the evidence identifies immutable source and build artifacts;
4. the relevant GitHub Actions or external test report is successful;
5. no open severity-1 or severity-2 finding contradicts the claim;
6. evidence with an expiry has not expired.

`PARTIAL` means useful implementation or evidence exists but the full boundary
has not been tested. `BLOCKED` means completion requires an identified external
dependency. `NOT_MET` means the required result does not yet exist.

## Production gates

| ID | Required result | Minimum acceptance evidence | Status |
|---|---|---|---|
| PROD-01 | A frozen, versioned protocol specification defines every wire message, state transition, error, timeout, limit and downgrade rule used by the release. | Conformance schema, golden vectors, compatibility matrix and signed specification tag. | PARTIAL |
| PROD-02 | The security claim and threat model cover global passive observation, malicious peers, compromised minority mixers, replay, delay, drop, injection, Sybil pressure, endpoint fallbacks and long-horizon correlation. | Reviewed threat model with explicit assumptions, exclusions and claim-to-test traceability. | PARTIAL |
| PROD-03 | Two independently built implementations interoperate for the public wire protocol without sharing protocol code. | Cross-implementation transcript corpus and successful conformance run. | PARTIAL |
| PROD-04 | All cryptographic constructions and parameter choices are established, domain-separated and independently reviewed; no unreviewed custom primitive protects anonymity or integrity. | Design rationale, test vectors, dependency provenance and independent cryptographic review. | PARTIAL |
| PROD-05 | Mix committee keys are created with authenticated distributed key generation and threshold decryption; no machine ever holds a complete long-term decryption key. | At least five independently administered nodes, DKG transcript, threshold-decryption tests and compromise drill. | PARTIAL |
| PROD-06 | Every mix hop preserves payload, proves its shuffle, binds proof to committee, epoch and batch, and rejects replayed or equivocated batches. | Verifiable multi-hop transcripts, negative proof tests and third-party verification tool. | PARTIAL |
| PROD-07 | Drop, delay, duplication, replay, selective failure and malformed-input attacks are detected or bounded without private-dependent recovery traffic; accountable evidence can identify a faulty committee member where the protocol claims it can. | Active-adversary fault injection and signed blame/availability reports. | PARTIAL |
| PROD-08 | Committee membership, epoch rotation, forward secrecy, key erasure and compromise recovery are specified and exercised. | Rotation/erasure tests and a completed key-compromise recovery drill. | MET |
| PROD-09 | The Selection Firewall is enforced in every shipping dependency graph and process boundary: private selection cannot reach network-control capabilities. | Build-time import/capability policy plus runtime process-boundary tests for release binaries. | PARTIAL |
| PROD-10 | For equal public state, private reader activity does not change packet size, count, cadence, peers, retransmission, congestion response, cache maintenance or speculative networking. | Blind two-world packet/DNS captures across idle and diverse private workloads, including failures and congestion. | PARTIAL |
| PROD-11 | Constant cadence is maintained on the actual wire across clock drift, suspend/resume, loss, congestion and process stalls without catch-up bursts. | At least 72 hours of WAN capture per supported platform with preregistered tolerances and zero unexplained violations. | PARTIAL |
| PROD-12 | Network coding is generation-bound and pollution-resistant; malicious innovative symbols cannot cause accepted corruption or unbounded resource use. | Authenticated coding design, fuzz/property tests and Byzantine pollution campaign. | MET |
| PROD-13 | Distributed storage meets measured availability and durability targets while replication, eviction, repair and cache warming remain independent of private reads. | Multi-region churn/partition tests, repair traces and private-state non-interference comparison. | PARTIAL |
| PROD-14 | All queues, batches, generations and caches have explicit resource limits and safe backpressure that does not create private-dependent wire behavior. | Load tests at every limit, OOM/disk-full tests and wire-trace comparisons. | PARTIAL |
| PROD-15 | SiteID and publisher-key discovery, binding, rotation, expiry, revocation and recovery are authenticated and resistant to rollback/equivocation. | Normative specification, transparency/equivocation tests and recovery drill. | PARTIAL |
| PROD-16 | Objects, manifests, bundles and executable MIME decisions use canonical encodings and exact hash/signature verification; ambiguous or stale representations fail closed. | Cross-platform vectors plus mutation, truncation, rollback and parser-differential tests. | PARTIAL |
| PROD-17 | A publication airlock accepts new content without exposing a direct publisher-to-object mapping to the stated adversary. | End-to-end anonymous-deposit implementation and controlled correlation experiment. | PARTIAL |
| PROD-18 | Publication uses constant-rate ingress, threshold mixing, replication and protocol-defined time separation; failure and retry do not expose a private publication event. | Multi-publisher packet capture under success, timeout, restart and adversarial loss. | PARTIAL |
| PROD-19 | Peer discovery, admission and session handshakes authenticate protocol state, prevent downgrade/replay and do not depend on private content. | Interoperability, downgrade, replay and stale-directory tests. | PARTIAL |
| PROD-20 | Sybil, eclipse, amplification, resource-exhaustion and abusive-peer risks are bounded by a documented admission and rate-control model. | Economic/operational analysis plus red-team saturation and eclipse tests. | PARTIAL |
| PROD-21 | The transport works across IPv4, IPv6, NAT, churn, partitions and multiple operators/regions while preserving the traffic-class contract. | At least three independent operators and regions, WAN chaos tests and recovery evidence. | PARTIAL |
| PROD-22 | At least one supported browser/client build routes every Nomad resource through verified local data and has no ordinary-network fallback in the Nomad security context. | Engine-level implementation, source review and release-binary integration tests. | PARTIAL |
| PROD-23 | DNS, TCP, UDP, QUIC, WebSocket, WebRTC, preconnect, speculative fetch, reports, service workers, extensions, updates, telemetry, crash upload and reputation services cannot egress from the Nomad context. | Packet/DNS capture of negative tests for every path on every supported platform. | PARTIAL |
| PROD-24 | Query embedding and semantic selection run in a sandboxed local service with authenticated IPC, no network capability, bounded inputs and reproducible model identity. | Sandbox/capability tests, model hash attestation and attempted-egress capture. | PARTIAL |
| PROD-25 | Release builds are reproducible, signed, SBOM-attested, dependency-pinned and continuously checked for vulnerable or malicious dependencies. | Two independent builders produce matching artifacts; provenance, SBOM and vulnerability gate pass. | PARTIAL |
| PROD-26 | Installation, secure update, rollback prevention, key storage, local-data deletion and uninstall are supported and tested on every supported platform. | Signed update/rollback tests, OS-keystore tests and clean-removal verification. | PARTIAL |
| PROD-27 | Operational metrics, logs and crash data are data-minimized and cannot contain queries, basins, object choices, plaintext, stable cross-epoch identifiers or secret keys. | Schema allowlist, log-scraping tests, retention controls and privacy review. | PARTIAL |
| PROD-28 | Reliability and capacity targets are met under sustained load, node loss and regional failure; runbooks, on-call, backup and incident response are exercised. | Published SLOs, 30-day soak, disaster-recovery exercise and incident drill. | PARTIAL |
| PROD-29 | Independent cryptographic, systems, browser and privacy assessments have no unresolved severity-1 or severity-2 findings. | Publicly identifiable final reports, fixes and auditor verification of remediation. | BLOCKED |
| PROD-30 | A release candidate has completed a monitored multi-operator beta, passed a release red team and been approved through a documented two-person release process. | Signed release decision, immutable artifacts, beta report, red-team report and rollback plan. | PARTIAL |

## Required release artifacts

Completion of the table also requires a single release record containing:

- source commit and signed tag for every repository;
- reproducible binary digests and SBOMs;
- protocol and configuration version;
- supported platforms and traffic classes;
- mix committee and operator identities for the release epoch;
- all conformance, capture, chaos, fuzz, soak, audit and red-team reports;
- all known limitations and residual risks;
- emergency shutdown, rollback and key-compromise procedures.

The live reader testnet at nomad-testnet commit
`80b9f5c83e30114f6f749a39b89a6d77638abe4c`, CI run
`32301972409` and release `nomad-live-testnet-80b9f5c83e30` provides concrete partial evidence
for PROD-05, PROD-06, PROD-09 through PROD-14, PROD-16, PROD-21, PROD-22 and
PROD-25, and for the admission portion of PROD-19. Its release gate exercises
three authenticated fixed-cadence UDP nodes, bounded immutable caches, three
isolated threshold-share processes and a networkless materializer. The signed
topology binds dedicated DKG identities and HTTPS endpoints. Three separate
TLS operator processes execute Kyber v4 Pedersen DKG, require every member in
QUAL, sign one identical activation certificate, produce distinct private
shares and bind that exact certificate into descriptor v2 before live
threshold decryption. A strict capture on a dedicated bridge records exact
1200-byte cells and protocol cadence. This closes the testnet software DKG
integration, but it is still a single-administrator Docker fixture—not evidence
of five independently administered operators, regions, WAN behavior, witnessed
key custody/erasure, epoch rotation, a general peer session handshake,
separately administered shuffles or independent review.

The native macOS branch at Nomad-browser commit
`b19710be10b896e47e97885d5f7391c0c9213455`, source CI `32303046813` and universal-build CI
`32303046809` provides concrete partial evidence for PROD-09, PROD-16, PROD-22,
PROD-23, PROD-25 and PROD-26. It retains the search-only SwiftUI client,
query-independent cache reload, effective App Sandbox without network
client/server entitlement, source/binary egress gates and verified universal
DMG. It also adds a protected, fail-closed workflow for ephemeral Developer ID
key import, expected-team/runtime/timestamp checks, Apple notarization, stapling
and Gatekeeper assessment. No credentialed run or notarized artifact exists
yet; the downloadable `f5d1d6aa` alpha remains ad-hoc signed. Production still
requires the Apple-provisioned IPC boundary, release-binary packet/DNS capture,
a successful credentialed notarization record, secure update/rollback work and
independent review.

## Claim discipline

Until all 30 gates are `MET`, the project may claim only the level demonstrated
by its evidence. In particular, `production-ready anonymity network`,
`anonymous publishing`, `browser-isolated` and `safe against a global passive
observer` are prohibited release claims before the corresponding gates pass.

No project maintainer may self-approve PROD-04 or PROD-29. External review is a
security control, not documentation work that can be replaced by CI.
