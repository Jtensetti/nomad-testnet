# Execution plan: Nomad production readiness

Derived from [`GOAL.md`](GOAL.md). Requirement registry:
[`workstreams.json`](workstreams.json). Progress journal:
[`claude-progress.md`](claude-progress.md). Revised after internal evaluator
critique (2026-08-20, DEC-004..DEC-009).

## Baseline (2026-08-20)

All eight Go repositories pass `go build ./...`, `go vet ./...` and
`go test -race ./...` at their current branch heads.
`python3 scripts/check_docs.py` passes in nomad-protocol. Registry state:
0/30 MET, 18 PARTIAL, 11 NOT_MET, 1 BLOCKED (PROD-29).

Existing hard-won assets to preserve, not rewrite:

- nomad-testnet `live/`: signed topology ceremony, Kyber v4 Pedersen DKG over
  TLS with journaled fail-closed semantics (DKG-01..12 MET at fixture level),
  isolated share services, networkless materializer, strict pcap gate.
- nomad-anytrust-mix-sim: ElGamal batches + verified Neff sequence shuffles,
  t-of-n threshold decryption (already generic in t and n).
- Nomad-browser: sandboxed networkless SwiftUI client, egress gates, protected
  fail-closed notarization workflow (uncredentialed).
- Selection Firewall dependency gates in CI.

Known understatements the plan must not repeat (evaluator findings 1-2):
the publisher-facing constant-rate **client uplink does not exist** (the
fixed-cadence fabric is operator-to-operator; clients only have a downlink
fetcher), and the mix pipeline runs as a **single-process fixture** whose
bootstrap holds every demo identity key. Workstream A therefore contains two
large pieces of new protocol surface, not reuse.

## Standing track — external-dependency initiation (starts now)

EB-1 (Apple Developer enrollment), EB-2 (recruiting 3-5 independent operator
administrators) and EB-4 (booking external assessors) are wall-clock and
third-party bound. The user should initiate them immediately per
[`EXTERNAL_BLOCKERS.md`](EXTERNAL_BLOCKERS.md) so the waits overlap
engineering. The PROD-28 soak clock starts no later than end of Phase 3.

## Phase plan

### Phase 1 — Protocol foundations (C -> D -> A, with managed overlap)

**C. Epoch/key lifecycle.** Canonical `EpochDescriptor` v1 **wrapping** the
unchanged signed topology v3 + DKG certificate (no digest cascade; existing
evidence stays reproducible). Envelope-vs-active-window semantics resolve the
prepare-while-active constraint without a topology schema break
(`docs/EPOCH_LIFECYCLE.md`). Lifecycle digests/signatures use a canonical
binary encoding, never raw JSON (DEC-005). The signed membership-transition /
approval-quorum primitive lives in C; Workstream B consumes it (DEC-006).
Public rotation-failure policy for full-QUAL DKG is part of the state
machine (DEC-007). The five-operator 3-of-5 committee profile and its
negative tests land in C, so later airlock evidence is produced once on the
production committee shape. Then: retirement, retired-share rejection, key
erasure runbook + forward-secrecy experiment, revocation and recovery
drills, CI regression.

**D. SiteID/publisher identity.** Canonical SiteDescriptor chain (same
canonical-binary-encoding discipline), domain-separated SiteID derivation,
rotation/recovery/revocation, rollback prevention, equivocation handling,
parser differential tests; integration into nomad-local-reconstruction and
Nomad-browser identity display states. D's spec/vector work may start while
C's long tail (erasure runbook, drills, forward-secrecy experiment)
executes; D does not depend on C's machinery.

**A. Publication airlock.** Two explicitly new protocol surfaces:

1. **Client uplink traffic class** — constant-rate publisher-facing cells
   from client endpoints to entry operators. Does not exist today. An early
   **ingress spike** (minimal client uplink to one entry operator,
   cover-vs-fragment injection, non-blind two-world capture) runs
   immediately after C's descriptor core lands, and its parameters fill the
   descriptor's reserved `uplink_profile` field before descriptor freeze.
2. **Online distributed mix path** — per-operator shuffle/decrypt services
   with authenticated inter-operator sessions (bound to network, epoch,
   topology, role). The current fixture bootstrap holds all identities and
   is not reusable as-is. A minimal authenticated operator-service layer is
   in A's scope; Workstream B extends (not introduces) it.

Then: local-only Publish -> bounded persistent encrypted queue ->
constant-rate injection -> anytrust mix -> threshold deposit mailbox (bound
to network/epoch/batch/deposit/purpose) -> public release epochs ->
replication. Verified by two-world captures with preregistered tolerances.
The two-world capture/preregistration harness is built once here and
extended in E (single-harness rule, DEC-009).

### Phase 2 — Hostile network (B + G in parallel)

**B.** Operator lifecycle tooling (init/enroll/verify/join/rotate/recover)
around C's transition primitive; WAN-ready deployment package; external
operator onboarding package; accountability evidence (signed blame and
availability reports, PROD-07) on top of the DKG journals and mix receipts.
Real administrative independence stays BLOCKED externally (EB-2); everything
up to that boundary ships.

**G.** Pollution-resistant symbol admission (authenticated-pipeline +
bounded-decoder design; on the reader path cells already reach the decoder
only through the signed descriptor/transcript chain), hard per-generation
resource bounds, Byzantine campaigns including 100% malicious symbols,
admission/rate model, eclipse/amplification/disk-full/OOM tests,
backpressure non-interference.

### Phase 3 — Prove the network (E)

netem loss/latency/jitter/congestion matrix, suspend/clock/stall campaigns,
NAT/IPv6 profiles, blind two-world classification (extending A's harness)
with a separate evaluator and preregistered thresholds, validated 72-hour
harness, availability/durability measurement (PROD-13), intersection
analysis. Real multi-region WAN runs are BLOCKED on infrastructure (EB-3);
the harness, local campaigns and exact deployment procedure ship.

### Phase 4 — Shippable client (F + H)

**F.** Atomic handoff hardening (symlink/traversal/partial-write/oversize
negative tests), query-isolation proofs, semantic-service sandbox/
attestation (PROD-24), DNS/packet negative captures of the built browser
binary in CI, engine-fork contract status honestly documented.

**H.** Reproducible dual builds, SBOM, SLSA-style provenance, vulnerability
gate + policy, updater design (authenticated, anti-rollback, fail-closed,
and architecturally unable to grant the browser web capability),
Keychain-backed key storage, uninstall tests, allowlisted logging,
update-check cadence independence. Apple signing/notarization remains a
credentialed external step (EB-1).

### Phase 5 — Stabilize (workstream M)

Protocol freeze + conformance vectors (PROD-01), claim-to-test matrix
completion (PROD-02), second-implementation enablement package (PROD-03),
telemetry privacy (PROD-27), SLO/soak/incident scaffolding (PROD-28 — soak
clock started earlier), wire-format change freeze.

### Phase 6 — Independent validation (I)

Complete audit package; external crypto/systems/browser/privacy
assessments, red team, beta, two-person release decision. All externally
independent items remain BLOCKED until real external parties act; the
package makes their work immediately executable.

## Working rules

- Sprint contract before each substantial security-sensitive unit; separate
  evaluator agent challenges contracts touching privacy/crypto claims.
- Negative/adversarial tests written before implementation where the threat
  is clear.
- Every completed unit updates workstreams.json, EVIDENCE_INDEX.md and, when
  a PROD gate status changes, readiness.json + the DoD table together (CI
  enforces consistency).
- No parallel conflicting protocol definitions: epoch/SiteID/airlock wire
  formats are defined in nomad-protocol docs first, then implemented.
- This plan never restates registry counts except in the baseline snapshot
  above; `readiness.json` is the only authority.
