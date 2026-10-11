# Nomad independent assessment package

This package exists so that an external assessor can begin work immediately,
without a discovery phase and without asking the maintainers what to look
at. It is assembled by the project; it is **not** an assessment, and nothing
in it should be read as one.

## Scope of what is being asked

Four independent assessments plus a red team, matching PROD-04, PROD-29 and
PROD-30:

1. **Cryptographic** — Nomad's *composition* around established primitives:
   domain separation, transcript binding, DKG orchestration, threshold
   semantics, verifiable shuffle composition, epoch binding, replay and
   equivocation handling, the publication airlock's cryptography as far as it
   exists, and the SiteID identity chain. Please do not spend scope
   re-proving Ed25519, SHA-256, Kyber's Neff shuffle or Pedersen DKG from
   first principles unless you find a specific primitive-level concern.
2. **Systems** — process and capability boundaries, IPC, caches, filesystem
   handoff, concurrency, resource exhaustion, restart, scheduler, deployment,
   key custody.
3. **Browser** — sandbox, entitlements, egress, App Group or IPC boundary,
   malicious object handling, updater, external navigation, local storage.
4. **Privacy / traffic analysis** — given the declared threat model and the
   captures, attempt classifiers for idle, search, read, reconstruction,
   publication, retry and failure, and attempt correlation and intersection
   attacks. Reading the source is welcome but is not the assignment; the
   assignment is to try to break the indistinguishability claims.
5. **Red team**, after remediation — reader unlinkability, publisher
   unlinkability, anytrust and threshold assumptions, SiteID trust, and the
   supply and release chain.

## Where to start

| You want | Read |
|---|---|
| What the system claims | `docs/SECURITY_PROPERTIES.md`, `PRODUCTION_STATUS.md` |
| What it claims *against* | `docs/THREAT_MODEL.md` |
| What is proven and to what depth | `production/CLAIM_TEST_MATRIX.md` |
| The wire protocol | `docs/PROTOCOL.md`, `docs/ARCHITECTURE.md` |
| Epoch and key lifecycle | `docs/EPOCH_LIFECYCLE.md` |
| Publisher identity | `docs/SITE_IDENTITY.md` |
| Publication ingress | `docs/PUBLICATION_INGRESS.md` |
| Pollution and resource bounds | `docs/POLLUTION_AND_RESOURCES.md` |
| Operator lifecycle and failure handling | `nomad-testnet/deploy/OPERATOR_ONBOARDING.md`, `deploy/RECOVERY_RUNBOOK.md` |
| Immutable evidence references | `production/EVIDENCE_INDEX.md` |
| Why gates are not MET | `production/readiness.json`, `docs/PRODUCTION_DEFINITION_OF_DONE.md` |

## Review target

The frozen target is the tip of `claude/nomad-production-ready-dxv4ql` in
each repository at the time the package is handed over. The exact commit per
repository must be recorded in `FROZEN_TARGET.md` before assessment begins;
that file is filled in at handover, not before, so it always names real
commits.

## Test vectors and reproduction

- Epoch descriptor vectors: `nomad-testnet/live/epoch/testdata/`, including
  canonical preimages, digests, and real signatures from a published test
  key so an independent implementation can validate its signing path.
- Site identity vectors: `nomad-local-reconstruction/site/testdata/`.
- Every repository: `go build ./...`, `go vet ./...`, `go test -race ./...`.
- nomad-testnet additionally has the Compose live gate and the Selection
  Firewall dependency checks.
- Nomad-browser has `scripts/generate-sbom.sh`, `scripts/generate-provenance.sh`
  and `scripts/compare-builds.sh`.

## What we already believe is wrong or missing

Assessors should not have to discover the known gaps. They are listed in
`production/CLAIM_TEST_MATRIX.md` (every row at level `none`) and summarized
in `PRODUCTION_STATUS.md`. The largest:

- the publication airlock's deposit, mixing, threshold release and time
  separation are **not built**; only the local queue and the uplink cell
  format exist;
- no WAN, multi-region, loss, congestion, NAT, IPv6, suspend/resume or
  clock-drift evidence exists; all network evidence is single-host;
- no blind two-world classification has ever been run;
- the release binary has never been packet- or DNS-captured;
- there is no admission or rate-control model, so no Sybil, eclipse or
  amplification claim is made;
- coded-symbol pollution is bounded in cost but not prevented, for reasons
  documented in `docs/POLLUTION_AND_RESOURCES.md`;
- the browser engine forks carry integration contracts only.

## Prior internal review

Two adversarial reviews were run internally during development. Each found
exploitable defects in code that looked finished:

- an approval quorum satisfiable by a **single** previous-epoch operator on
  the production 3-of-5 profile, via wire-index aliasing combined with an
  approval message that bound nothing about the approver;
- a remote, unprivileged denial of service that permanently bricked any
  site, by submitting a valid genesis descriptor for an unrelated site;
- an equivocation proof verifier that proved nothing, allowing forged proofs
  against honest sites;
- a stolen online signing majority able to rewrite the offline recovery
  policy;
- several fail-open paths, including an equivocation halt that did not halt
  when it could not persist its evidence.

All are fixed with regression tests, and the fixes are in the review target.
They are listed here for two reasons: so assessors can check the fixes, and
because the rate at which internal review found real defects is the main
reason no gate has been promoted on internal confidence.

**These were internal reviews by the implementing agent's own tooling. They
are QA. They are explicitly not independent assessment and must never be
recorded as satisfying PROD-04 or PROD-29.**

## Severity policy and remediation

Production release requires zero unresolved Severity 1 and Severity 2
findings. "Fixed" is insufficient: the assessor who raised a finding
verifies its remediation. Material security design changes made in response
to a finding are re-reviewed rather than assumed correct.

Findings and their resolution are recorded in
`production/audit/FINDINGS.md`, which is created when the first assessment
begins.

## What the maintainers will not do

- Ask an assessor to soften, delay or withhold a finding.
- Mark a gate MET on the strength of a remediation the assessor has not
  verified.
- Represent any internal review, including an AI-assisted one, as
  independent.
