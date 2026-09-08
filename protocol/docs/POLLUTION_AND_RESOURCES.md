# Pollution, resource bounds and admission (draft v1)

Status: DRAFT. Records what Workstream G implements, and — more
importantly — what it does not.

## The pollution problem

Nomad codes objects with random linear network coding over GF(2^8). A
malicious peer can send a symbol whose coefficient vector is well-formed and
*innovative* — it raises the decoder's rank — but whose data is wrong. The
symbol enters the basis. Nothing detects it until the finished object fails
its SHA-256 root and signature check, and in the meantime the attacker has
spent the decoder's CPU and memory.

Final object verification is therefore necessary but not sufficient: it
catches the wrong object, it does not bound what the attacker costs you.

## What is implemented

**Enforced per-generation budgets.** Symbols accepted, bytes ingested, rank
attempts, elimination work, basis memory, and wall-clock lifetime. Work
units count GF(2^8) row operations, the decoder's dominant cost, and are
deterministic: the same input always consumes the same units, so a budget
cannot be evaded by timing. Exceeding any budget terminates the generation
and releases the basis immediately, and a failed generation stays failed
without doing further work. Duplicate detection runs before all accounting,
so replaying one symbol drains no budget.

**Pre-admission verification of systematic symbols.** A systematic symbol
names exactly one source symbol, so a per-source-symbol commitment carried
in the signed descriptor settles it with one hash. Polluted systematic
symbols never enter the basis and cost one hash rather than an elimination
pass.

## What is NOT claimed

**A general coded symbol cannot be verified before admission.** A hash is
not homomorphic over the code's linear structure. The established
constructions that would allow it each require something Nomad does not
have:

- homomorphic hashing (Krohn-Freedman-Mazières) needs the code to live in a
  large prime field, not GF(2^8);
- homomorphic MACs (Agrawal-Boneh) need a shared secret, which a broadcast
  network whose relaying peers re-encode cannot have;
- homomorphic signatures (Boneh-Freeman-Katz-Waters) are pairing-based and
  substantially heavier.

Adopting any of them means changing the coding field or the re-encoding
model — a protocol change, and per the project's rules not one to make
casually or without review. Until that analysis is done, a polluted coded
symbol is detectable only at final object verification. The guarantee here
is narrower and precise: **it cannot cost more than the generation budget.**

**Bounds prevent resource exhaustion, not availability loss.** The Byzantine
campaign shows this directly. With 50% or more malicious symbols, the
generation terminates within budget but does *not* complete: malicious
innovative symbols fill the basis, honest symbols become non-innovative, and
the object never decodes. The attacker cannot exhaust the node, but can deny
that generation. Availability against a sustained injector requires either
per-symbol verification (above) or admission control that keeps such peers
out (below), and neither is solved by bounds alone.

## Admission and rate control

Operator identities are authenticated by signed enrollment and epoch
membership, so operator-sourced pollution is attributable: a generation that
fails final verification identifies which authenticated peers contributed,
which is the input to accountability (PROD-07).

A broader admission model for non-operator peer roles — per-identity and
per-prefix limits, connection caps, message-rate caps, diversity and
anti-eclipse constraints — is **not yet implemented**. G-05 through G-09
remain open, and no Sybil, eclipse or amplification claim should be made
until they are.

## Evidence

`nomad-rlnc` `TestByzantineCampaignStaysBounded` runs 50%, 90% and 100%
malicious campaigns and asserts every budget holds and heap growth stays
under a ceiling. `TestPollutedSystematicSymbolRejectedBeforeAdmission`,
`TestDuplicateSymbolsDrainNoBudget`, `TestGenerationLifetimeIsBounded` and
`TestTerminatedGenerationReleasesMemoryAndStaysFailed` cover the rest.

Not covered: whole-system load, disk-full and OOM behavior at the node
level (G-12), backpressure non-interference on the wire (G-11), and the
admission model above.
