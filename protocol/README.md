# Nomad protocol

Working specification for the Nomad networking experiments.

Nomad explores one architectural question: can private content selection be separated from externally observable network activity strongly enough that reading an object does not create a reader-to-object traffic event?

This repository contains **only** the shared architecture, terminology, threat model and protocol constraints. Executable code lives in the component repositories. Nothing here is a proof of anonymity or a deployable wire standard.

## Component repositories

- `nomad-constant-rate-fabric` — fixed-size, fixed-cadence traffic scheduling.
- `nomad-anytrust-mix-sim` — payload-preserving Kyber Neff shuffle integration for the research profile.
- `nomad-rlnc` — GF(2^8) random linear network coding.
- `nomad-semantic-basins` — local vector-to-basin experiments.
- `nomad-local-reconstruction` — local ranking, decoding orchestration and exact verification.
- `nomad-selection-firewall` — public network emission planning with no private-selection input.
- `Nomad-browser` — browser-independent client composition.
- `nomad-testnet` — cross-component integration and packet-level experiments.
- `firefox-nomad`, `chromium-nomad` — browser-engine integration work.

## Current architectural constraints

1. A traffic class fixes cell size and cadence independently of reader activity.
2. Private search, ranking and reconstruction state must not be an input to the network scheduler.
3. Network coding is transport coding, not encryption or authentication.
4. Basin identifiers are similarity metadata and must be treated as potentially revealing.
5. The research mix uses an established verifiable shuffle, but the project has
   no threshold committee key protocol, accountability layer or independent
   review and therefore makes no deployable mixnet claim.
6. Reconstructed objects are accepted only after exact commitment/signature verification.
7. Publisher unlinkability before first deposit is a separate and harder problem than reader-side non-interference.

Read `docs/DEFINITION_OF_DONE.md` and `docs/IMPLEMENTATION_STATUS.md` first,
then `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md` and
`docs/SECURITY_PROPERTIES.md` before making claims about the system.
