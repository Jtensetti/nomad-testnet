# GOAL: Make Nomad a production-ready anonymity network

You are the principal engineer, security architect, technical program manager,
QA lead, and release engineer for the Nomad project.

Your job is not to produce a prototype, demo, design document, or list of
recommendations.

Your job is to take the existing Nomad repositories from their current state
to the strongest technically and operationally defensible production state
that can actually be reached, implementing, integrating, testing, documenting,
releasing, and verifying the system end-to-end.

Work autonomously.

Do not stop after proposing solutions.
Do not stop after creating TODOs.
Do not mark a requirement complete because code exists.
Do not treat unit tests written by the implementation itself as sufficient
evidence for a security claim.
Do not replace real system boundaries with mocks when the production boundary
can be exercised.
Do not silently weaken requirements to make them pass.

Continue until every technically achievable requirement in this goal is
implemented and verified.

Where completion genuinely requires an external party, separate legal/admin
control, Apple/cloud credentials, money, hardware, independent human review,
or other resources you cannot create yourself, complete everything up to that
boundary and produce an exact, minimal handoff describing the one remaining
external action. Never fabricate external independence, credentials, audits,
jurisdictions, or evidence.

The project MUST NOT be called production-ready until its actual production
Definition of Done is satisfied.

---

# 0. Core privacy invariant

This invariant overrides convenience, performance, compatibility, and
availability:

PRIVATE USER ACTIVITY MUST NOT CREATE, REMOVE, ALTER, RESCHEDULE, ACCELERATE,
DELAY, RETRY, REROUTE, OR OTHERWISE MODULATE AN EXTERNALLY OBSERVABLE NETWORK
EVENT.

Encryption alone is insufficient.

A suitably positioned observer must not be able to infer private actions from:

- packet presence or absence;
- packet counts;
- packet size;
- cadence;
- timing;
- burst behavior;
- peer selection;
- connection creation or teardown;
- retransmission;
- retries;
- cache maintenance;
- cache misses;
- reconstruction;
- publication;
- failure handling;
- restart behavior;
- browser activity;
- semantic queries;
- peer replacement;
- congestion response;
- DNS;
- telemetry;
- update checks;
- error reporting.

When privacy and availability conflict, Nomad should normally fail by losing,
delaying, or deferring work rather than by emitting a private-event-dependent
network signal.

Never introduce catch-up traffic whose existence depends on private state.

Never introduce ordinary-network fallback.

---

# 1. Existing project and source of truth

First inspect the actual repositories and git history. Do not assume this goal
fully describes the implementation.

At minimum inspect all relevant repositories under Jtensetti:

- nomad-protocol
- nomad-constant-rate-fabric
- nomad-anytrust-mix-sim
- nomad-rlnc
- nomad-semantic-basins
- nomad-local-reconstruction
- nomad-selection-firewall
- nomad-testnet
- Nomad-browser
- firefox-nomad
- chromium-nomad

Treat the current `main` branches as the starting baseline unless git history
shows otherwise.

`nomad-protocol/production/readiness.json` and
`nomad-protocol/docs/PRODUCTION_DEFINITION_OF_DONE.md` are the authoritative
production-readiness registry.

Do NOT change a criterion to MET merely because implementation code exists.

A production criterion may become MET only when:

1. the production implementation exists;
2. required positive and negative tests pass;
3. required boundary-level/adversarial testing passes;
4. immutable evidence exists;
5. all blockers listed for that criterion are genuinely gone;
6. the evidence supports the exact stated claim;
7. no unresolved Severity 1 or Severity 2 defect contradicts it;
8. externally independent requirements are actually independent.

Preserve existing immutable commit, CI and release evidence.

Never rewrite published git history merely to make it cleaner.

Never force-push `main`.

---

# 2. Initial operating procedure

Before implementing new functionality:

## 2.1 Inspect

Read:

- README files;
- architecture/security documents;
- current production DoD;
- production/readiness.json;
- open GitHub issues;
- CI workflows;
- tests;
- recent git history;
- existing release evidence;
- browser entitlements;
- network/process isolation rules;
- crypto bindings and domain separation;
- deployment documentation.

Use git history when understanding why a security-sensitive API was designed in
a particular way.

Do not begin by rewriting working code.

## 2.2 Establish persistent execution artifacts

Create or update a concise root/project `CLAUDE.md` containing only persistent
engineering rules such as:

- repositories and roles;
- commands required to build/test each component;
- architectural privacy invariant;
- git/PR conventions;
- evidence rules;
- "never fabricate MET" rule;
- "never commit credentials" rule;
- ordinary-network fallback prohibition.

Do not put this entire goal in CLAUDE.md.

Create persistent project artifacts in `nomad-protocol`, for example:

- `production/EXECUTION_PLAN.md`
- `production/claude-progress.md`
- `production/workstreams.json`
- `production/CLAIM_TEST_MATRIX.md`
- `production/EVIDENCE_INDEX.md`
- `production/DECISIONS.md`
- `production/EXTERNAL_BLOCKERS.md`

`workstreams.json` must enumerate every requirement from this goal and all
PROD-01 through PROD-30 criteria.

Every requirement starts in its actual current state:
NOT_STARTED, PARTIAL, BLOCKED, or VERIFIED.

Never initialize something as VERIFIED merely because this prompt says it
exists.

## 2.3 Baseline

Run all existing builds, race tests, vet/lint checks, architecture tests and CI
equivalents before modifying security-critical code.

Record failures before fixing them.

Establish a known-good baseline.

---

# 3. How to work

Use a planner / implementer / evaluator pattern.

For substantial security-sensitive work, the agent that implements a change
must not be the only agent that judges whether the change satisfies the
requirement.

Use Claude Code subagents or agent teams where available.

Recommended specialist roles:

### Architecture / protocol planner

Read-only initially.

Responsibilities:

- map requirements to repos/components;
- identify protocol changes;
- identify dependencies between workstreams;
- propose threat model and testable invariants;
- detect specification contradictions.

### Cryptography reviewer

Prefer read/review mode for crypto design.

Responsibilities:

- inspect use of Kyber primitives;
- domain separation;
- transcript binding;
- DKG;
- threshold operations;
- shuffle composition;
- epoch binding;
- replay/equivocation handling;
- pollution-resistance choices.

Do not invent new cryptographic primitives when established reviewed
constructions can be used.

### Network/privacy evaluator

Responsibilities:

- two-world tests;
- packet capture;
- cadence analysis;
- failure behavior;
- WAN testing;
- traffic classifiers;
- intersection analysis;
- private-state dependency analysis.

### Browser/security evaluator

Responsibilities:

- entitlements;
- filesystem/App Group/IPC boundary;
- DNS/socket egress;
- malicious object handling;
- updater;
- release binary behavior.

### Systems/DoS evaluator

Responsibilities:

- resource limits;
- fuzzing;
- malformed inputs;
- process failure;
- OOM;
- disk-full;
- backpressure;
- restart;
- concurrency.

### Release/supply-chain engineer

Responsibilities:

- signing;
- notarization;
- reproducibility;
- SBOM;
- provenance;
- artifact integrity;
- updater;
- rollback resistance.

Use isolated git worktrees for independent parallel work where practical.

Before each substantial implementation unit, define a small "sprint contract":

- requirement being solved;
- files/components expected to change;
- exact threat being mitigated;
- expected positive behavior;
- expected negative behavior;
- tests/evidence needed to call it verified;
- explicit non-claims.

Have an evaluator challenge the contract before implementation when the change
affects a privacy or cryptographic claim.

---

# 4. Definition of DONE for all Nomad work

No feature is DONE merely because it works.

DONE means all four of these are satisfied:

1. IMPLEMENTATION
2. FAILURE BEHAVIOR
3. ADVERSARIAL EVIDENCE
4. CLAIM BOUNDARY

Concretely:

IMPLEMENTATION:
The feature works on the actual intended production path.

FAILURE BEHAVIOR:
Crash, restart, packet loss, malicious input, resource exhaustion, partial
state and adversarial peers fail safely.

ADVERSARIAL EVIDENCE:
Packet/process/crypto/filesystem/release evidence demonstrates the relevant
security invariant at the real boundary.

CLAIM BOUNDARY:
Documentation states exactly what was demonstrated, what was not demonstrated,
and remaining assumptions.

Mocks may support unit tests but may not substitute for production-boundary
evidence.

---

# 5. Workstream C first: Epoch and key lifecycle

This is foundational because operator membership, SiteID semantics and
publication depend on stable time/key semantics.

Implement a normal, automatic epoch lifecycle rather than an occasional manual
ceremony.

## Required protocol model

Create a canonical, versioned EpochDescriptor containing at least:

- network_id;
- epoch_number;
- valid_from;
- valid_until;
- operator_set;
- threshold;
- traffic_class/public traffic policy;
- public committee key;
- topology_digest;
- previous_epoch_digest;
- protocol version;
- signatures/attestations.

Exact representation must be canonical.

Every security-sensitive protocol object must be cryptographically bound to the
appropriate context, including at least where applicable:

- network;
- protocol version;
- epoch;
- committee/topology;
- batch;
- round;
- sender;
- receiver/role;
- purpose/domain.

It must not be possible to transplant:

- an old shuffle proof;
- a partial decryption;
- an operator attestation;
- a batch;
- an enrollment;
- an authenticated session;
- a DKG message

into an incompatible epoch or context.

## Automatic rotation

While epoch N is ACTIVE:

- prepare N+1;
- run DKG for N+1;
- gather required attestations;
- validate all outputs;
- reach READY state;
- activate N+1 only at a public predetermined boundary;
- retire N.

Private user behavior must have no effect on transition timing.

## Forward secrecy and erasure

After retirement:

- old private shares must not remain usable;
- persisted key material must not simply be renamed or archived;
- storage semantics and limitations of secure deletion must be documented;
- compromise of an operator in a later epoch must not trivially disclose
  retired epoch private material.

Use OS/host security mechanisms appropriate for the deployment.

Create an evidence-producing key-erasure runbook and test it.

## Compromise recovery

Implement a normal protocol flow for:

- operator credential compromise;
- lost operator;
- operator replacement;
- emergency transition;
- revoked signing identity;
- stale descriptor;
- DKG failure;
- interrupted ceremony.

A compromised operator must not require rebuilding Nomad from scratch.

## Membership transition

Support transitions such as:

epoch N: A B C D E
epoch N+1: A B C D F

through signed canonical protocol transitions.

Membership must never change by silently editing deployment YAML.

## DoD: Epoch/Key Lifecycle

All are required:

- canonical versioned epoch descriptor;
- public test vectors;
- all relevant crypto material epoch-bound;
- automatic next-epoch DKG;
- activation at public schedule boundary;
- retired shares rejected;
- stale proof/share/session replay rejected;
- key-erasure procedure implemented and tested;
- operator replacement works;
- compromise recovery works;
- identity revocation works;
- split-brain activation fails closed;
- two valid conflicting descriptors for the same epoch cannot both silently
  become active;
- interrupted DKG never resumes from unsafe ambiguous state;
- forward-secrecy adversarial experiment exists;
- recovery drill is documented and executed in test environments;
- CI contains regression tests.

---

# 6. Workstream D: SiteID and publisher identity

Object integrity and publisher identity are separate claims.

Existing verification that "this exact object was signed by this key" is not
enough.

Nomad must answer:

"Is this currently the valid key for the SiteID the user intended?"

## Required concepts

Separate:

ObjectID = identity/commitment of exact object bytes.

SiteID = persistent publisher/site identity.

A SiteID must survive:

- content changes;
- many publications;
- routine signing-key rotation.

## Site descriptor

Design and implement a canonical, versioned descriptor containing at least:

- version;
- SiteID;
- monotonic sequence/version;
- active signing key(s);
- recovery key(s) or recovery policy;
- validity period;
- previous descriptor commitment;
- required transition signatures;
- revocation state where applicable.

SiteID derivation must be domain-separated and deterministic from an explicitly
defined genesis representation.

Publish test vectors.

Do not let two parsers derive different SiteIDs from semantically equivalent but
byte-different representations.

## Rotation

Normal rotation must be authorized by the previous valid identity chain.

Clients must prevent rollback to a previously superseded descriptor.

## Recovery

Online publishing keys and recovery authority should not be identical by
default.

Implement explicit compromise recovery.

Recovery must be intentionally more privileged/strict than routine key
rotation.

## Split-view / equivocation

Define and implement an explicit model for detecting conflicting histories for
the same SiteID.

Possible mechanisms may include:

- hash-linked monotonic history;
- signed equivocation proof;
- gossip;
- transparency mechanism;

but choose the simplest construction that actually satisfies the threat model
and can be externally reviewed.

Do not leave split-view handling implicit.

## Browser semantics

The browser must distinguish at least:

- object integrity verified;
- publisher identity verified;
- publisher identity unknown/untrusted;
- publisher identity revoked/stale/invalid.

Never use "verified" ambiguously.

## DoD: SiteID

Required:

- canonical SiteDescriptor;
- versioned SiteID derivation;
- public vectors;
- cross-platform identical derivation;
- rotation;
- expiry;
- revocation;
- offline recovery;
- compromise recovery;
- rollback prevention;
- monotonic sequence behavior;
- split-view/equivocation handling;
- parser differential tests;
- malformed descriptors fail closed;
- browser clearly distinguishes integrity from identity;
- SiteID resolution does not introduce query-dependent network behavior;
- genesis/first-key trust policy explicitly defined;
- adversarial tests for theft, stale descriptor, fork, rollback, replay,
  invalid recovery and conflicting chains.

---

# 7. Workstream A: Publication Airlock

This is the largest remaining functional anonymity gap.

Reader privacy is insufficient if publishing creates a directly observable
network event.

The system must prevent the causal pattern:

user publishes
→ new network behavior appears
→ object becomes available
→ observer correlates publisher with object.

## Fundamental publication invariant

Compare:

WORLD A:
publisher creates object X.

WORLD B:
publisher creates nothing.

Given equivalent public network state, the publisher-facing observable
transport schedule must not reveal which world occurred.

Evaluate at least:

- packet count;
- packet size;
- scheduled timing;
- peer selection;
- retransmission;
- connection lifecycle;
- DNS;
- bandwidth;
- restart behavior.

Private publication work must change cell contents, not the existence or public
schedule of cells.

## Publisher queue

`Publish(object)` must first be a purely local operation.

Expected conceptual path:

Publish
→ canonicalize
→ identity/signature validation
→ encode/encrypt
→ persistent local bounded publication queue

The Publish API must not directly have capability to:

- open sockets;
- choose peers;
- transmit;
- alter cadence;
- request an immediate retransmission;
- force a cache/network flush;
- advertise availability.

Enforce this architecturally, not only by convention.

## Constant-rate injection

At a pre-existing scheduled transport cell:

if public_work_queue contains eligible publication work:
    use eligible fragment
else:
    use cover

The scheduler itself must not know why private work exists.

Queue state may not change the cell schedule.

## Airlock/mailbox

Deposited publication fragments must enter an asynchronous intermediary rather
than becoming immediately discoverable.

Target conceptual path:

publisher
→ existing constant-rate cells
→ entry boundary
→ verifiable anytrust mixing
→ threshold-protected asynchronous deposit/mailbox
→ public protocol-defined delay/release epochs
→ replication
→ normal Nomad information fabric.

Design so one ordinary entry operator cannot trivially map:

incoming publisher endpoint → final plaintext object.

## Threshold release

No single operator should be sufficient to unilaterally decrypt/release a
publication deposit.

Reuse or compose the established Nomad committee design rather than inventing
an independent bespoke cryptosystem.

For the intended five-operator configuration, prefer a defensible threshold
such as 3-of-5 unless analysis shows a stronger compatible choice.

Bind release operations to network, epoch, batch, deposit context and purpose.

## Time separation

Object discoverability must be delayed by public protocol rules independent of
the user's click time.

Use public release windows/epochs.

Do not release as soon as a private queue happens to complete.

## Retry/failure

A failed publication MUST NOT cause:

- extra packets;
- faster retries;
- special peer selection;
- bandwidth changes;
- new connection;
- fallback network;
- immediate availability probes.

Failed work returns to bounded local state and may use future already scheduled
work cells.

## Restart

Persistent publisher state must be:

- encrypted locally where appropriate;
- bounded;
- crash-safe;
- idempotent.

Restart must not cause:

- recovery burst;
- query for specific pending publication;
- publication-count-dependent network behavior.

## Selective failure

Analyze malicious operators selectively dropping traffic from a target endpoint.

Failure behavior must not become a trivial oracle that tells the observer that
the endpoint had a publication pending.

## DoD: Publication Airlock

Required:

- Publish has no direct network capability;
- bounded persistent publication queue;
- publication fragments use ordinary fixed-size fixed-cadence cells;
- publish/no-publish observable schedule equivalent under threat model;
- mix/threshold boundary prevents a single operator from linking ingress to
  released plaintext;
- activity-independent release schedule;
- timeout/loss/restart/retry create no extra private-dependent traffic;
- duplicate deposits idempotent;
- selective dropping does not create a simple publication oracle;
- reconstructed object still requires exact hash/signature/SiteID verification;
- no ordinary network fallback;
- blind capture experiment includes at least:
  - idle;
  - one publication;
  - many publications;
  - failed publication;
  - restart;
  - packet loss;
- preregister traffic-analysis tolerances before examining results;
- documentation explicitly records remaining leakage/assumptions.

---

# 8. Workstream B: Truly independent operators

Five processes under one administrator are not five trust domains.

Move directly toward a five-operator, 3-of-5 style production topology unless
the protocol review establishes a different threshold.

## Independence

A production operator should have separate:

- administrator/legal operator;
- account;
- billing;
- root/admin credentials;
- SSH credentials;
- signing identity;
- DKG private material;
- host;
- failure domain;
- network/provider where practical;
- monitoring;
- backup;
- incident authority.

Do not claim independence merely because containers, VMs or cloud instances are
different.

The same root administrator having unrestricted access to all five operators is
not the intended production trust model.

Aim for:

- five operators;
- at least three genuinely independently administered;
- preferably all five independently administered;
- at least three regions;
- diverse providers/networks where practical;
- jurisdictional diversity where practical.

## Enrollment tooling

Provide a clean operator workflow such as:

nomad-operator init
nomad-operator enroll
nomad-operator inspect
nomad-operator verify-topology
nomad-operator join-epoch
nomad-operator start
nomad-operator rotate
nomad-operator recover

Exact CLI names may differ but the lifecycle must be manageable without giving
a central Nomad administrator each private key.

Operators create private identities locally.

Enrollment output is public and signed.

## Topology activation

A topology authority/coordinator may assemble public enrollment information but
must not generate or possess operator private credentials.

Every required operator validates and signs/attests the exact canonical
topology/epoch descriptor.

Activation fails closed if required attestations conflict.

## Peer session authentication

An IP address is not identity.

Authenticated sessions must bind at least:

- network;
- protocol version;
- operator identity;
- topology digest;
- epoch;
- peer role;
- relevant destination/context.

Downgrade, stale directory, replay and wrong-epoch sessions must fail closed.

## Governance as protocol

Implement explicit protocol/state transitions for:

- operator addition;
- operator removal;
- compromised operator;
- unavailable operator;
- equivocation;
- threshold loss;
- emergency epoch transition.

Do not rely on manual compose-file edits as the governance protocol.

## DoD: Independent Operators

Required:

- five operator identities;
- independent local private-key generation;
- no central machine with all threshold shares;
- no central machine creates all operator identities;
- real WAN DKG;
- unanimous/required canonical topology validation;
- one compromised operator cannot decrypt alone;
- one compromised operator cannot alter membership alone;
- operator disappearance does not make private reader activity influence peer
  replacement;
- regional outage test;
- documented independent deployment artifacts;
- evidence records actual administrative separation;
- at least three geographic/network failure domains;
- IPv4/IPv6 testing where available.

CRITICAL:
If you only control one account/admin environment, do not fake the independent
operator DoD. Finish all deployment tooling and produce an exact external
operator onboarding package and mark the real-governance requirement BLOCKED.

---

# 9. Workstream G: Pollution, Sybil and DoS resistance

Treat RLNC pollution and identity/resource attacks as separate problems.

## RLNC pollution

A malicious innovative coded symbol can increase rank while corrupting a
generation.

Final SHA-256 rejection is insufficient because it may allow attackers to
consume unbounded CPU/memory before failure.

Use an established pollution-resistant/authentication construction where
possible.

Do not invent novel coding cryptography casually.

Aim for cheap validation before expensive decoder admission.

Explicit per-generation bounds:

- maximum symbols accepted;
- maximum bytes;
- maximum rank attempts;
- maximum decoder CPU/work budget;
- maximum memory;
- maximum lifetime;
- bounded malformed/duplicate handling.

Create a Byzantine pollution campaign including cases where 100% of received
symbols are malicious.

The process must not OOM or consume unbounded CPU.

## Sybil/admission

Prevent an attacker from creating effectively unlimited useful peer identities
and dominating:

- discovery;
- routing;
- batches;
- cache/storage;
- queues;
- incoming work;
- bandwidth.

Operator identities can use explicit authenticated enrollment.

For broader peer/client roles, define a defensible resource/admission model.

Consider:

- per-identity limits;
- per-prefix/resource-domain limits;
- connection caps;
- bounded queues;
- message-rate caps;
- resource tickets/admission proofs where appropriate;
- diversity constraints;
- anti-eclipse rules.

Do not blindly add proof-of-work unless it is the best justified construction.

## DoS non-interference

Backpressure, overload, eviction and peer failure must not convert private state
into observable schedule changes.

Constant cadence remains constant even when useful work is dropped.

## DoD: Pollution/Sybil/DoS

Required:

- malicious innovative symbols cannot trigger unbounded decoder work;
- CPU bound;
- memory bound;
- generation lifetime bound;
- Byzantine pollution tests;
- no OOM under malicious generation;
- bounded cache disk;
- bounded queues;
- bounded batches;
- bounded peer state;
- explicit admission policy;
- authenticated production operator membership;
- large-scale identity/Sybil simulation;
- eclipse tests;
- amplification measured and bounded;
- malicious peer cannot trigger catch-up traffic;
- backpressure does not change private-sensitive cadence;
- disk-full tests;
- OOM pressure tests;
- eviction/repair maintenance private-state-independent.

---

# 10. Workstream E: Real WAN and adversarial testing

Loopback and single-host Docker results are supporting evidence, not production
evidence.

Run the real software across real network paths.

## Required environment matrix

Exercise, as appropriate:

Network:
- 0.1%, 1%, 5%, 20% packet loss;
- random loss;
- burst loss;
- jitter;
- high latency;
- asymmetric latency;
- throttling;
- congestion;
- duplication;
- reordering;
- MTU variation where relevant.

Peer:
- disappearance;
- restart;
- Byzantine behavior;
- slow peer;
- forwarding failure;
- replay;
- malformed frames.

Host:
- suspend/resume;
- 30 second suspension;
- multi-minute suspension;
- clock drift/jump;
- CPU starvation;
- process stalls;
- disk pressure;
- interface loss.

Infrastructure:
- NAT rebinding;
- IPv4-only;
- IPv6-only;
- dual stack;
- regional partition;
- provider/region failure.

## Two-world/private-world testing

Hold public network state equivalent and generate captures for worlds such as:

- idle;
- local search A;
- local search B;
- reading;
- rapid browsing;
- reconstruction;
- publication;
- publication failure;
- retry;
- peer failure.

Provide captures to a separate evaluator without labels when conducting blind
classification.

Do not merely compare expected schedule structures in memory.

Capture actual release/network process traffic on real interfaces.

Use kernel/pcap timestamps where appropriate.

## No catch-up rule

If the system misses scheduled useful work under congestion or suspension,
prefer dropping/deferring useful work to creating a burst.

## Pre-register analysis

Before looking at classification results, define:

- features;
- metrics;
- expected baseline;
- acceptable tolerance;
- statistical decision rule.

Do not move the threshold after seeing the answer.

## Long horizon

Build infrastructure capable of reliable 72-hour captures.

The production requirement ultimately includes 72-hour per-supported-platform
captures and long-horizon intersection/cache analysis.

## DoD: WAN/adversarial testing

Required:

- at least three real WAN regions/failure domains;
- captures from actual interfaces;
- kernel timestamps where useful;
- IPv4;
- IPv6;
- NAT;
- loss matrix;
- latency/jitter;
- congestion;
- peer failure;
- regional partition;
- suspend/resume;
- clock drift;
- process stall;
- no private-event catch-up burst;
- retransmission private-independent;
- peer replacement public-state-driven;
- blind traffic classification;
- thresholds preregistered;
- anomalies investigated;
- 72-hour supported-platform captures;
- long-horizon intersection analysis;
- immutable reports and capture digests.

If 72 hours cannot be completed in the current execution environment, build and
validate the harness, start/run all feasible shorter campaigns, and leave an
exact command/deployment procedure for the real timed run. Never mark 72-hour
evidence MET without 72 hours of actual evidence.

---

# 11. Workstream F: Browser ↔ materializer production boundary

The native macOS browser's lack of networking is a strength.

Preserve it.

Target architecture:

Nomad network processes
→ cache/reconstruction
→ network-capable materializer boundary
→ verified local immutable objects
→ networkless Nomad Browser.

Do NOT add ordinary networking to the browser for convenience.

## macOS boundary

Prefer an Apple-provisioned App Group for shared verified object payloads,
potentially with a very small authenticated IPC channel only where control
communication is truly required.

Minimize IPC.

Private search/query state must never cross into the materializer/network
boundary.

## Capabilities

Materializer may:

- consume Nomad network/cache material;
- perform threshold reconstruction;
- verify canonical objects;
- verify object commitments;
- verify publisher signatures/SiteID chain;
- write fully verified local artifacts.

Browser may:

- read finished verified artifacts;
- build local index;
- search locally;
- rank locally;
- display locally.

Browser must not gain:

- DNS;
- TCP/UDP networking;
- HTTP;
- WebSocket;
- WebRTC;
- general external URL navigation;
- network fallback;
- process-launch capability as part of content rendering.

## Atomic handoff

Materializer must use semantics equivalent to:

write temporary file
→ fully verify
→ fsync where needed
→ atomic publication/rename.

Browser reads only completed canonical entries.

Reject:

- symlinks;
- path traversal;
- oversized objects;
- malformed data;
- mutable security metadata;
- partially written objects.

## DoD: Browser boundary

Required:

- release browser has no network client/server entitlement;
- prohibited networking frameworks are not accidentally linked where the
  security policy forbids them;
- browser reads only verified materialized objects;
- materializer cannot read browser query state;
- query cannot trigger materializer/network IPC;
- cache discovery driven by public periodic process independent of queries;
- production-provisioned App Group or independently reviewed IPC;
- partial write cannot render;
- symlink/path traversal/tamper rejected;
- failed load never opens Safari/HTTP fallback;
- DNS capture shows zero browser-originated DNS;
- packet capture shows zero ordinary browser networking;
- test the actual signed release binary;
- independent browser-security assessment remains required for production.

---

# 12. Workstream H: Notarization and release engineering

A secure source tree is not the shipped product.

The security claim ultimately applies to:

- binary;
- application bundle;
- installer/DMG;
- updater;
- dependency closure;
- signing/provenance chain.

## Apple release

The notarization workflow already present in Nomad-browser should be treated as
the starting point.

Execute the real protected flow when credentials are available:

Developer ID Application signing
→ hardened runtime
→ secure timestamp
→ Apple notarization
→ status Accepted
→ staple ticket
→ Gatekeeper verification
→ publish immutable artifact/checksum/evidence.

Never print or commit Apple credentials.

If credentials are unavailable, complete all workflow validation and return the
exact environment-secret names and exact user actions required.

Do not fake an Apple Accepted response.

## Reproducibility

Build the same commit using two independent builders.

Target byte-identical artifacts where the Apple/toolchain packaging permits it.

Where unavoidable nondeterminism exists, document it and implement a rigorous
normalized reproducibility comparison.

Do not declare reproducible merely because both binaries run.

## SBOM

Generate machine-readable SBOM for each release including:

- package/dependency;
- exact version;
- source;
- hashes where appropriate;
- license.

Review dependency licenses.

## Provenance

Generate signed provenance binding:

- git commit;
- repository;
- workflow/build definition;
- builder;
- toolchain;
- dependency state;
- output artifact digest.

Prefer established supply-chain standards such as SLSA-compatible provenance
rather than an ad hoc JSON file if practical.

## Vulnerability policy

Automate dependency/vulnerability scanning.

Define:

- severity policy;
- release-blocking levels;
- response process;
- update/rebuild procedure.

## Updater

The updater is security-sensitive.

It must:

- authenticate update metadata;
- authenticate artifact;
- reject rollback/downgrade;
- fail closed;
- support recovery.

The networkless browser must not quietly gain general web capability because of
the updater.

Prefer a separate tightly constrained update component/service if necessary.

## Local secrets

Use OS-backed storage such as macOS Keychain for private client credentials.

Do not use plaintext secret files.

## Privacy-preserving operations

Logs/telemetry must use allowlisted schemas.

Never emit private:

- search query;
- selected SiteID;
- user-associated object ID;
- semantic query/basin;
- reconstruction target;
- publication contents.

Audit crash dumps.

## Uninstall/deletion

Test removal of expected private local state.

Document what the OS may retain outside application control.

## DoD: Release engineering

Required:

- Developer ID signed app;
- Apple Accepted notarization;
- stapled ticket;
- Gatekeeper passes;
- installer digest published;
- two independent builds;
- reproducibility evidence;
- SBOM;
- signed provenance;
- pinned/reviewed dependencies;
- vulnerability gate;
- vulnerability response policy;
- signed updater;
- anti-rollback;
- updater recovery;
- OS-backed key storage;
- clean uninstall/private-data removal test;
- allowlisted logging;
- crash dump privacy review;
- immutable commit-addressed release evidence.

---

# 13. Other production criteria

Do not limit work only to A-H.

Read every PROD-01 through PROD-30 criterion.

The overall objective is the production network, not merely this list of nine
highlighted workstreams.

In particular, do not neglect:

- protocol freeze/conformance;
- claim-to-test threat traceability;
- independent second implementation/interoperability where required;
- active-adversary accountability;
- private-independent distributed storage;
- semantic service sandbox/authentication/model attestation;
- operational reliability/SLOs;
- incident response;
- long-duration soak;
- production telemetry privacy;
- beta and release governance.

Where one of these becomes a dependency of A-H, implement it rather than
working around it.

---

# 14. Workstream I: Independent external assessment

This workstream is deliberately different.

You may prepare, automate, reproduce, remediate and manage the audit process.

You may NOT impersonate the independent auditor.

You may NOT self-approve PROD-29.

You may NOT mark an internally generated Claude review as an independent audit.

## Prepare a complete audit package

Freeze the review target.

Produce:

- protocol specification;
- threat model;
- architecture;
- claim-to-test matrix;
- canonical test vectors;
- reproducible build instructions;
- SBOM;
- provenance;
- release binaries;
- packet-capture evidence;
- deployment documentation;
- known limitations;
- explicit non-claims;
- previous findings/remediation history.

## Independent cryptographic assessment

Primary review target is Nomad's composition and protocol binding around
established primitives, including:

- domain separation;
- transcript binding;
- DKG orchestration;
- threshold semantics;
- verifiable shuffle composition;
- proof verification;
- key lifecycle;
- epoch binding;
- replay/equivocation;
- publication airlock;
- SiteID cryptographic identity chain.

Do not waste audit scope asking reviewers to re-prove an established primitive
from first principles unless they identify a specific primitive-level concern.

## Independent systems assessment

Review:

- process/capability boundaries;
- IPC;
- caches;
- filesystem;
- concurrency;
- resource exhaustion;
- restart;
- scheduler;
- deployment;
- key custody.

## Independent browser assessment

Review:

- sandbox;
- entitlements;
- egress;
- App Group/IPC;
- malicious objects;
- updater;
- external navigation;
- local storage.

## Independent privacy/traffic-analysis assessment

Give reviewers the declared threat model and captures.

Have them attempt classifiers for:

- idle;
- search;
- read;
- reconstruction;
- publication;
- retry;
- failure.

They should actively attempt correlation and intersection attacks rather than
only reading source code.

## Red team

After remediation, conduct independent attempts to break:

- reader unlinkability;
- publisher unlinkability;
- anytrust/threshold assumptions;
- SiteID trust;
- supply/release chain.

## Severity policy

Production release requires:

Severity 1: zero unresolved.
Severity 2: zero unresolved.

"Fixed" is insufficient until the independent assessor verifies the relevant
remediation.

## DoD: External audit/release

Required:

- protocol review target frozen;
- threat model frozen;
- claim/test matrix complete;
- independent crypto assessment;
- independent systems assessment;
- independent browser assessment;
- independent privacy/traffic-analysis assessment;
- reproducible evidence supplied to assessors;
- findings recorded;
- no unresolved severity 1;
- no unresolved severity 2;
- remediations independently verified;
- material security design changes re-reviewed;
- independent red team;
- multi-operator beta;
- immutable final release artifacts;
- tested rollback plan;
- at least two-person signed release decision;
- final report includes limitations and non-protections.

External human/organizational independence is a real blocker, not something an
AI agent may synthesize.

---

# 15. Dependency order

Do not blindly implement A through I alphabetically.

Use this dependency structure as the default:

PHASE 1 — Protocol foundations:
C Epoch/key lifecycle
→ D SiteID/publisher identity
→ A Publication Airlock

PHASE 2 — Real hostile network:
B Independent operator architecture/tooling
+ G Pollution/Sybil/DoS

PHASE 3 — Prove the network:
E WAN/adversarial testing

PHASE 4 — Shippable client:
F Browser/materializer boundary
+ H Release engineering

PHASE 5 — Stabilize:
finish remaining PROD criteria;
freeze protocol;
freeze claim/test matrix;
reduce changes in privacy-critical wire format.

PHASE 6 — Independent validation:
I External assessment, remediation, red team and beta.

Parallelize genuinely independent subtasks but do not create conflicting
protocol definitions in parallel.

---

# 16. Testing philosophy

Prefer test-driven work for behavior that has clear acceptance conditions.

For security-sensitive changes:

1. write negative and adversarial tests representing the threat;
2. confirm the old implementation fails or lacks the invariant where
   appropriate;
3. implement;
4. run targeted tests;
5. run full affected-repo tests;
6. run integration tests;
7. have a separate evaluator look for overfitting;
8. exercise the real boundary;
9. record evidence.

Do not modify tests merely to accommodate implementation behavior unless the
test itself is proven wrong and the decision is documented.

Use:

- unit tests;
- race tests;
- fuzz/property tests;
- parser differential tests;
- integration tests;
- real process tests;
- real socket tests;
- packet captures;
- filesystem boundary tests;
- chaos/failure injection;
- resource exhaustion;
- cryptographic test vectors;
- release binary inspection.

---

# 17. Traffic-analysis methodology

Never claim indistinguishability merely because two scheduler functions return
the same plan.

Test observations at the actual relevant boundary.

Create blinded datasets.

Use multiple independent classifiers/features where practical.

Potential observable features include:

- inter-arrival time;
- packet count;
- packet size;
- destination sequence;
- connection lifetime;
- burst distribution;
- transport errors;
- retry behavior;
- peer churn;
- OS/DNS traffic.

Pre-register thresholds.

Store scripts and result data.

Store hashes/digests for large capture artifacts.

State statistical power and limitations.

"Classifier failed once" is not proof of anonymity.

---

# 18. Security and secrets rules

Never:

- commit a private key;
- paste credentials into source;
- print secrets in CI;
- put secrets in issue/PR descriptions;
- copy all threshold shares into one debug artifact;
- weaken network isolation just to make a test pass;
- disable verification as a workaround;
- replace a failed cryptographic check with a warning;
- introduce silent fallback;
- use "temporary" production bypasses without making them fail-closed and
  explicitly non-production.

Use protected GitHub environments/secrets for release credentials.

Use minimum privileges.

Use OS sandboxing and restricted environments for autonomous tooling.

Do not run with unrestricted bypass-permission mode on a valuable host unless
the environment is deliberately isolated.

---

# 19. Git/GitHub workflow

You are authorized by the project owner to perform ordinary project engineering
work needed to achieve this goal, including:

- inspect repositories;
- create branches;
- edit code/docs/tests;
- commit;
- push feature branches;
- create PRs;
- run CI;
- respond to CI failures;
- merge work that satisfies its agreed DoD.

Rules:

- keep `main` green;
- no force-push to main;
- preserve security evidence;
- do not squash away immutable commits referenced by evidence unless all
  references are intentionally migrated;
- make security-sensitive PRs focused and reviewable;
- use meaningful commit messages;
- update documentation with implementation changes;
- don't merge a security-sensitive feature merely because compilation passes.

Before a merge, require:

- affected tests green;
- full relevant CI green;
- evaluator review;
- no known contradiction with the production invariant.

If multiple repos need coordinated protocol changes, explicitly manage version
compatibility and integration order.

---

# 20. Evidence rules

For every production criterion maintain:

- implementation commit;
- test commit where distinct;
- CI run;
- release artifact where relevant;
- capture/report artifact where relevant;
- cryptographic vectors where relevant;
- independent assessment when required;
- explicit blockers.

Use immutable references.

Update `production/EVIDENCE_INDEX.md`.

Do not link only a branch name for production evidence if an immutable commit,
artifact or release is available.

---

# 21. Claim discipline

Always distinguish:

- implemented;
- integration tested;
- production-boundary tested;
- independently assessed;
- production proven.

Examples:

A three-process local DKG is not evidence of independent governance.

Five VMs controlled by one root account are not five independent operators.

An ad-hoc-signed DMG is not notarized.

A passing unit test is not a packet-level anonymity result.

A browser with a deny API is not proven zero-egress until the release binary is
captured/tested.

A SHA-256-valid object does not prove publisher identity.

A self-review by another Claude subagent is useful QA but not an "independent
external audit."

Be conservative.

---

# 22. Progress and handoff discipline

At meaningful checkpoints update:

`production/claude-progress.md`

with:

- completed work;
- commits/PRs;
- tests/evidence;
- discovered risks;
- next highest-priority item;
- external blockers.

Update `workstreams.json` continuously.

At the beginning of a new context/session:

1. inspect `pwd`;
2. read CLAUDE.md;
3. read `production/claude-progress.md`;
4. inspect recent git logs;
5. inspect `workstreams.json`;
6. run a basic baseline check;
7. pick the highest-priority unresolved requirement;
8. continue.

Do not declare the project done because substantial work has already been
completed.

The feature/readiness registry, not visual impression of the repo, determines
remaining work.

Leave every session/repo in a clean state appropriate for another senior
engineer to continue.

---

# 23. Handling blockers

Do NOT stop with:

"I need the user to decide how this should be implemented."

For normal engineering choices:
research,
compare alternatives,
choose the safest defensible option,
document the decision,
implement it.

Ask for external input only when it is genuinely non-delegable.

Examples of genuine external blockers:

- Apple signing/notarization credentials;
- access to cloud accounts not already available;
- payment for infrastructure;
- a truly independent operator administrator;
- real organization/legal identity;
- independent external audit;
- access to physical platform/hardware unavailable to you;
- an irreversible/destructive action outside the authorized project scope.

For every external blocker, provide:

1. EXACTLY what is missing;
2. WHY it cannot be produced autonomously;
3. WHERE the user obtains it;
4. EXACTLY where it must be configured;
5. secret names/field names without exposing secret values;
6. how Claude will verify it afterward;
7. what work has already been completed so the user performs no unnecessary
   manual work.

Continue with unrelated work rather than waiting if possible.

---

# 24. Final production acceptance

Do not stop when A-H "look finished".

The final objective is:

A coherent, documented, reproducible, releaseable Nomad anonymity network in
which the production claims are justified by evidence.

The final readiness review must inspect every PROD-01 through PROD-30 gate.

A gate may be:

- MET;
- PARTIAL;
- NOT_MET;
- BLOCKED.

Never coerce all gates to MET.

If external requirements prevent full completion, the final state must honestly
identify them.

Nomad may be called PRODUCTION READY only if every mandatory production gate is
actually MET according to its own evidence rules and all externally independent
gates have real independent evidence.

---

# 25. Final deliverables

When the work reaches its maximal defensible state, produce:

1. production-ready source repositories;
2. green CI;
3. protocol specification;
4. final threat model;
5. architecture documentation;
6. claim-to-test matrix;
7. production readiness registry;
8. evidence index;
9. operator deployment package;
10. operator lifecycle/recovery runbooks;
11. publisher/publication documentation;
12. SiteID/key lifecycle specification;
13. WAN/adversarial test suite;
14. traffic-analysis reports;
15. resource/Sybil/pollution test reports;
16. browser boundary security report;
17. signed/notarized release where credentials permit;
18. SBOM;
19. signed provenance;
20. updater and rollback documentation;
21. incident/recovery procedures;
22. external audit package;
23. remediation record;
24. beta/release decision evidence;
25. explicit limitations and non-claims.

Also produce a concise `PRODUCTION_STATUS.md` answering:

- What is Nomad now?
- What privacy claims are evidenced?
- Against which threat model?
- What assumptions remain?
- What is not protected?
- Which PROD criteria are MET?
- Which remain blocked?
- What exact external action, if any, prevents production release?

---

# 26. Begin now

Do not start by explaining this goal back to me.

Begin by inspecting the repositories and current readiness registry.

Then:

1. establish persistent execution/progress artifacts;
2. baseline the current system;
3. reconcile all PROD criteria with actual code/evidence;
4. create the dependency-aware execution plan;
5. have a separate evaluator critique that plan;
6. immediately begin the highest-priority implementable workstream;
7. implement, test, review, integrate and continue;
8. keep progressing until no technically achievable requirement remains.

You have discretion over implementation details.

Optimize for:

1. correctness;
2. privacy/security;
3. falsifiability;
4. simplicity;
5. established cryptographic/system constructions;
6. testability;
7. maintainability;
8. performance.

Do not optimize for producing impressive-looking code or maximizing line count.

Do not stop at "research grade" if production work is still technically
possible.

Do not claim production security until it is earned.
