# External blockers

Genuine external dependencies that cannot be produced autonomously. Everything
up to each boundary is (or will be) completed so the external party performs
only the listed action. Never fabricate these.

## EB-1: Apple Developer ID signing and notarization credentials

- **Missing:** Developer ID Application certificate + Apple notarization
  credentials for Nomad-browser releases.
- **Why not autonomous:** requires a paid Apple Developer Program membership
  and legal identity; credentials must never be created or held by an agent.
- **Where obtained:** <https://developer.apple.com/programs/> (enrollment),
  then an App Store Connect API key or app-specific password for `notarytool`.
- **Where configured:** protected GitHub environment secrets in
  `Jtensetti/Nomad-browser` used by the existing fail-closed release workflow:
  `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `NOTARY_KEY_ID`,
  `NOTARY_ISSUER_ID`, `NOTARY_PRIVATE_KEY` (names per the workflow file; set
  values only in GitHub environment secrets, never in the repo).
- **Verification afterward:** re-run the release workflow; it must show
  Developer ID identity check, hardened runtime, notarization `Accepted`,
  stapling and `spctl` Gatekeeper assessment, and attach the notarization log
  and artifact digests as immutable evidence.
- **Already complete:** the protected fail-closed signing/notarization
  workflow exists and is validated without credentials (commit `b19710b`).

## EB-2: Independently administered operators (>=3, ideally 5)

- **Missing:** three to five genuinely independent administrators (separate
  people/organizations, accounts, billing, credentials, hosts, regions) to run
  Nomad operators and perform DKG/topology attestation themselves.
- **Why not autonomous:** administrative and legal independence cannot be
  synthesized; five processes under one admin are one trust domain.
- **Where obtained:** recruit operators (e.g. privacy-community organizations,
  universities, individuals) willing to run the operator package.
- **Where configured:** each operator follows
  `nomad-testnet/deploy/OPERATOR_ONBOARDING.md`, generating all private
  material locally and publishing only signed public enrollments.
- **Verification afterward:** signed enrollments from distinct identities,
  WAN DKG transcript across their hosts, per-operator attestations of the
  activated epoch descriptor, and (for PROD-05) witnessed key custody/erasure
  statements from each administrator.
- **Already complete:** the onboarding package is written and the lifecycle
  tooling exists. `nomad-testnet/deploy/OPERATOR_ONBOARDING.md` is addressed
  to an external administrator and needs no other project knowledge; it
  covers identity generation, reading and attesting the draft, verifying the
  signed topology, the DKG, serving, rotation and erasure, and states what
  an operator will never be asked for. `nomad-operator` provides init,
  inspect, attest, verify and erase; `deploy/RECOVERY_RUNBOOK.md` covers the
  failure cases and is exercised by TestRecoveryDrill. **The only remaining
  action is recruiting the people.**

## EB-3: Multi-region WAN test infrastructure

- **Missing:** hosts in >=3 regions/providers (with IPv4+IPv6) for real WAN
  campaigns and 72-hour captures; requires cloud accounts and payment.
- **Why not autonomous:** infrastructure costs money and accounts that are
  not available in this execution environment.
- **Where obtained:** any three diverse providers/regions (can be modest VMs);
  operator machines from EB-2 can double as WAN endpoints.
- **Where configured:** Workstream E ships deployment scripts and an exact
  run procedure; secrets are limited to ordinary SSH access held by the user.
- **Verification afterward:** capture archives with kernel timestamps and
  digests from each region, matching the preregistered tolerances, attached
  as immutable CI/release artifacts.
- **Already complete / in progress:** dedicated-bridge pcap gate exists;
  Workstream E is building the netem matrix, blind-classification harness and
  72-hour capture harness validated locally.

## EB-4: Independent external assessors and red team (PROD-04, PROD-15, PROD-29, PROD-30)

- **Missing:** independent cryptographic, systems, browser and
  privacy/traffic-analysis assessors, plus a release red team, none of whom
  are project maintainers or Claude agents.
- **Why not autonomous:** independence is the security control; an agent
  self-review is QA, not an audit, and must never be recorded as one.
- **Where obtained:** commercial audit firms, academic groups, or established
  independent researchers chosen by the project owner.
- **Where configured:** assessors receive the audit package produced under
  Workstream I (frozen target, spec, threat model, claim/test matrix,
  vectors, reproducible builds, captures, limitations).
- **Verification afterward:** publicly identifiable final reports, recorded
  findings, and assessor-verified remediation with zero unresolved Sev1/Sev2.
- **Already complete / in progress:** specifications, published test
  vectors, adversarial test suites and claim documentation are being
  assembled continuously; two internal adversarial reviews have already run
  and their findings are fixed with regressions. Booking assessors is
  wall-clock bound and should start now rather than after implementation.
- **PROD-15 specifically:** the publisher identity design -- descriptor chain,
  recovery policy, and now transparency-log distribution -- is specified,
  implemented, adversarially tested, mutation-verified and cross-checked by a
  second implementation, and every one of those was authored here. That is the
  criterion's only remaining blocker. What an assessor is being asked for is a
  judgement on the *design*: whether a single log plus a freshness window is
  the right bound for the split-view threat, and whether the two following
  profiles are the right choice to offer. No further code closes it.

## EB-5: Second independent protocol implementation (PROD-03)

- **Missing:** an interoperating implementation of the public wire protocol
  built without sharing protocol code.
- **Why not autonomous:** independence requires a separate implementer; an
  agent-written second implementation in this project shares authorship and
  cannot count as independent for PROD-03.
- **Where obtained:** external contributor/team, aided by the frozen
  specification and conformance vectors from PROD-01 work.
- **Verification afterward:** cross-implementation transcript corpus and a
  successful conformance run in CI.
- **Already complete:** the formats an implementer needs are published and
  enforced, and — since this was written — one of them has actually been
  reimplemented. `nomad-testnet/conformance/reference/nomadwire.py` is a
  second implementation of the hop cell in another language, sharing no code
  and written from the specification rather than from the Go, with a
  bidirectional conformance run in CI.
  It found that the specification could not be built from: it described the
  last 48 bytes of every cell as "random representation padding, fresh filler,
  not application data" when they are the authenticated hop header, so nobody
  could have interoperated at all. Two further ambiguities and a corpus that
  published MAC vectors without their key came out of the same attempt. All
  four are fixed.
  So what remains for the second party is smaller and sharper than it was:
  the specification is now known to be *sufficient* to build from, because
  someone did. What it is not known to be is *unambiguous to a stranger*,
  which is the half a single author cannot supply, and the object manifest,
  signed topology and uplink profiles still have no second implementation at
  all.

## EB-6: Two-person release decision (PROD-30)

- **Missing:** a second human release approver.
- **Why not autonomous:** the control exists precisely to prevent a single
  actor (human or agent) from approving a release alone.
- **Where obtained:** project owner designates a second maintainer.
- **Verification afterward:** signed release decision recorded in the release
  evidence with two distinct identities.
- **Already complete:** the rule is enforced rather than documented. A release
  manifest carries approvals, and `Nomad-browser update.Decode` refuses one
  without signatures from at least two *distinct* trusted approver keys —
  including refusing a build whose trusted set is one key, or one key listed
  twice, before it reads a manifest at all. Exercised end to end with the
  shipped binary, which refuses a single-approver build with "One person who
  can approve alone is not a two-person process".
  **The exact minimal handoff:** generate two Ed25519 keypairs on two separate
  machines held by two separate people; compile both public halves into the
  release binary as a comma-separated `releaseKeys`; each approver runs
  `update.Approve` with their own key on their own machine. Note the limit
  that no code can close: two keys held by one person satisfy every check.
  Custody is the control. And because there is no revocation channel, do not
  ship a build that trusts exactly two keys if losing one is meant to be
  survivable — see `Nomad-browser docs/RELEASE_PROCESS.md`.

## EB-7: Project release key for the signed specification tag (PROD-01)

- **Missing:** a signing key under project control, and a signed tag on the
  frozen specification.
- **Why not autonomous:** a release key is long-lived signing authority over
  what the project asserts the protocol *is*. An agent must not create or hold
  one, and a key generated here would prove only that this session signed
  something. This is not an independence requirement -- the maintainer may
  sign their own specification -- it is a custody one.
- **Where obtained:** the project owner generates the key on hardware they
  control (a hardware token is preferable to a file), publishes the public
  half in the repository, and keeps the private half off any machine an agent
  can reach.
- **Where configured:** `git config user.signingkey`, then
  `git tag -s protocol-v1 -m "..."` on the commit that freezes the
  specification. The public key belongs in the repository so a verifier needs
  nothing but the clone.
- **Verification afterward:** `git tag -v protocol-v1` succeeds against the
  published public key, and the tagged tree's conformance corpus digest
  matches the one recorded in the evidence index.
- **Already complete:** everything the tag would cover. The corpus, the
  compatibility matrix, the downgrade rule and the cross-architecture check
  are in place and enforced; the specification content is written. What is
  missing is a signature over it, and only custody prevents that.

## EB-8 (RESOLVED 2026-08-28): Actions jobs were not dispatched -- account billing

- **Was missing:** the ability to run any workflow. From 2026-08-24, workflow
  runs on this session's branches completed as `failure` three to eight
  seconds after creation.
- **Cause, established from the run record:** GitHub attached exactly one
  annotation to each failed job, and it says what happened:

  > The job was not started because recent account payments have failed or
  > your spending limit needs to be increased. Please check the 'Billing &
  > plans' section in your settings

  (`nomad-testnet` check-run 98432458214, on run 33046757052, head
  `bb113e1f`.) The observable shape matches: the jobs record zero steps, not
  even `Set up job`, so nothing was ever dispatched to a runner.
- **How it was resolved:** the account owner made the repositories public on
  2026-08-28. GitHub-hosted runner minutes are free for public repositories,
  so the spending limit stopped applying. The first successful run afterwards
  was `nomad-protocol` 33171161765; all nine repositories have executed real
  jobs since.
- **Verification:** a run that executes for longer than its setup and whose
  job logs are retrievable. On 2026-08-28, eight of nine repositories ran for
  25-312 seconds with full logs. This entry stays as a record; it is not a
  live blocker.

### A wrong correction, recorded because it is in published history

Between the diagnosis above and this resolution, this session replaced the
correct diagnosis with an incorrect one, and committed it to nine
repositories in `ci: pin actions/checkout and actions/setup-go to SHAs that
exist` (`nomad-testnet` bd271e8 and its siblings). That message asserts:

- "v7 is not a version either action has". False.
  `git ls-remote https://github.com/actions/checkout` resolves `refs/tags/v7`
  to `3d3c42e5` (v7.0.1, tagged 2026-07-17), and `actions/setup-go` resolves
  `refs/tags/v7` to `b7ad1dad` (v7.0.0, 2026-07-15). Both existed throughout.
- "this is what GitHub does when it cannot resolve an action reference".
  False for this failure shape. An unresolvable action still produces a
  `Set up job` step and a log; these jobs had neither.
- "Making the repositories public did not change the failure, which is what
  ruled the billing theory out". This was asserted without an observation
  behind it. There is no run in the record between the repositories becoming
  public and the pin change, so nothing had ruled anything out.

What actually made the canary run go green was the visibility change, not the
pin change; the two were minutes apart and the pin was given the credit.

The pins were kept -- pinning a CI action by digest is right for a project
that verifies its own dependency digests -- but they were moved back to the
v7 releases the workflows originally used and that ran successfully in
`nomad-testnet` 32301972409 on 2026-08-19. The v4.2.2/v5.3.0 pins were a
two-major downgrade adopted on a false premise, and they were also what
raised the Node 20 deprecation warnings in the 2026-08-28 runs.

The generalisable error is not the wrong guess. It is that a diagnosis was
overwritten on the strength of an argument rather than an observation, when
the observation was one API call away: the annotation on the failed check-run
had been sitting there, in plain language, since 2026-08-24.

## What none of these are

None of the seven open blockers is a design problem, and none is waiting on
further engineering here. (EB-8 is retained as a resolved entry, not counted
among them.) Each names a person, a credential, a machine or an elapsed
duration. Where a blocker sits between "the work is done" and "the gate is
MET", the work is described above as already complete so that the external
party performs exactly one action and no more.

Two further gates are held by the same principle without appearing here,
because they need a second party rather than an external one: PROD-02 (a
reviewed threat model) and PROD-27 (a privacy review). Both artifacts are
finished; in each case the author must not also be the judge. A maintainer who
did not write them can close either without any external dependency at all.

## EB-9: A semantic embedding model (PROD-24, reader relevance)

- **Missing:** trained model weights and a runner for them. `basin.Embedder`
  is the interface; the only implementation in the tree is
  `basin.LexicalHashEmbedder`, which its own documentation states is a lexical
  baseline and not a semantic model. No Nomad repository builds, trains or
  ships a model, and none should: weights are a supply-chain artifact with its
  own provenance and licensing, not something an agent synthesizes.
- **Why not autonomous:** the weights are third-party artifacts requiring a
  license decision, a provenance chain and a size/latency budget chosen for
  target hardware. Fabricating a "model" here would be exactly the kind of
  claim this file exists to prevent.
- **Where obtained:** any sentence-embedding model whose license permits
  redistribution, published with a digest that can be pinned.
- **Where configured:** two supported attachment points, both already built.
  - Out of process, preferred: the sealed loopback service in
    `nomad-semantic-basins/basin/loopback`. `HTTPEmbedder` accepts literal
    loopback IPs only, disables proxies, rejects redirects, and seals the
    request under a service key with no unauthenticated mode. This keeps the
    browser core socket-free, which is what
    `TestTheLinuxClientLinksNoNetworkingPackage` and
    `TestTheSearchIndexLinksNoNetworkingPackage` assert.
  - In process: any `basin.Embedder`, or a `model.Runtime` behind the adapter
    layer. This links the runtime into the process that holds verified object
    bytes and would end the socket-free property if the runtime opens sockets,
    so it needs its own dependency-graph assertion before it is used.

  **These two are not interchangeable for the Linux client**, and DEC-023
  records why: that client's networkless claim is asserted over its dependency
  graph, which excludes `os/exec` as well as every networking package, so it
  can neither speak to a loopback service nor start one. Attaching a model to
  it requires the in-process route. Which runtime that should be is
  deliberately still open.
- **Verification afterward:** pin the weight digest; give the embedder a
  distinct `search.Provenance` so no ranking it produces can be reported as
  lexical or vice versa; re-run `TestASearchCostsExactlyOneEmbeddingCall`,
  which must still show one call per search; measure indexing cost per object
  and set `Config.Budget` from the measurement rather than the default; re-run
  the dependency-graph assertions if attached in process.
- **Already complete:** everything up to the boundary.
  - The model-agnostic architecture (nomad-semantic-basins `basin/model`):
    manifests, a registry that verifies packs against their digests, built-in
    `gemma`, `e5`, `qwen` and `plain` adapters, and a fingerprint over
    everything that can move a vector. A model family this build has never
    heard of is added by writing an adapter; nothing else moves. The catalogue
    names EmbeddingGemma 300M as the recommended default with
    multilingual-e5-small and Qwen3-Embedding-0.6B as first-class alternatives,
    and deliberately carries **no digests**: writing plausible ones for weights
    nobody measured would produce a registry that verifies packs against
    invented numbers, which is worse than no verification because it looks
    verified. A draft manifest does not validate, so there is no path from a
    catalogue entry to a loadable model that skips measuring the real files.
  - Licensing enforced rather than described. E5 is MIT and Qwen is Apache
    2.0; EmbeddingGemma is under Gemma Terms, which oblige a redistributor to
    pass the terms on and carry a NOTICE. `LoadPack` refuses a pack declaring
    that obligation without one, and does not refuse an MIT pack for lacking a
    NOTICE it does not need.
  - One index per fingerprint (`Nomad-browser/search`), so two models' vectors
    are never compared and switching models is reversible.
  - `Nomad-browser/search` embeds and tokenizes each object when it is added,
    so a search is one embedding call and set lookups whatever the corpus size,
    and a slow model is slow once per object rather than once per keystroke.
  - `Config.Budget` is required and enforced through the context;
    `TestAHangingEmbedderIsAbandonedAtItsBudget` pins that an embedder which
    never returns is abandoned rather than waited on.
  - `Config.Provenance` is required and travels with every result, so a
    lexical ranking can never be presented as a semantic one.
  - An object that fails to embed is left out of the index and counted, never
    stored with a zero basin that would rank as a real one.
  - The sealed loopback channel is built and tested (PROD-24).

**Not a blocker on the privacy invariant.** Inference latency depends on the
query, the object and the number of candidates, all private. It cannot modulate
an observable event: the packages holding query text are on the private side of
the Selection Firewall and cannot reach the emission planner, and the fabric
emits on a fixed cadence regardless of whether inference finished. A slow model
costs a reader a wait and costs the wire nothing. Attaching a model therefore
does not reopen PROD-14/17/18; it is a relevance and cost question only.

## EB-10: which licence applies where, and to vendored code (project owner)

- **Missing:** a decision by the project owner about the licence split across
  the nine repositories, and about what an MIT-licensed repository may do with
  restricted-source code it vendors.
- **What is true today:** two repositories carry the Nomad Restricted Source
  License 1.0 -- `Nomad-browser` (`80f2361`) and `nomad-constant-rate-fabric`
  (`8b00852`), both adopted on their `main` on 2026-08-27 -- and the other
  seven carry MIT. `nomad-testnet` is MIT and vendors
  `nomad-constant-rate-fabric` as a byte-for-byte snapshot, so an MIT
  repository now ships code under the more restrictive licence.
- **Why not autonomous:** which licence applies to which repository, and
  whether that combination is permissible, is a decision with legal
  consequences that belongs to the person who owns the work. An agent
  vendoring a snapshot is the last party who should be settling it.
- **Everything up to the boundary:** the vendored tree carries its upstream
  licence faithfully, because `COMPONENTS.sha256` pins the snapshot by content
  and replacing the vendored `LICENSE` would make the manifest describe a tree
  that does not exist upstream. `nomad-testnet COMPONENT_LICENSES.md` records
  the mismatch and `supplychain/licence_test.go` fails on any vendored licence
  that differs from the repository's own without being written down, so the
  next change of this kind cannot arrive as an unread line in a snapshot diff.
  Three failure paths verified by mutation.
- **What the owner decides:** whether the seven MIT repositories adopt the
  restricted licence, whether the two restricted ones revert, or whether the
  split is intended and the vendoring relationship needs different handling.
