# Licences of the vendored components

`components/*` are byte-for-byte snapshots of separate repositories, so each
carries the licence its upstream carries. When that differs from this
repository's own licence, the difference has to be written down here or
`supplychain/licence_test.go` fails: a licence changing under a vendored tree
is exactly the kind of thing that arrives in a snapshot diff nobody reads.

This file records what is true. It does not resolve anything, and nothing in
it should be read as legal advice or as a decision that has been made.

## This repository

`LICENSE`: MIT.

## Mismatches

| Component | Its licence | Status |
|---|---|---|
| `nomad-constant-rate-fabric` | `NOMAD RESTRICTED SOURCE LICENSE 1.0` | **UNRESOLVED — needs the project owner** |

### nomad-constant-rate-fabric

Upstream adopted the Nomad Restricted Source License 1.0 on its `main`
(`8b00852`, merged in `e0d8301`) on 2026-08-27. This repository vendors that
tree and is itself MIT, so an MIT-licensed repository now ships code under a
more restrictive licence.

The snapshot carries the upstream licence deliberately. `COMPONENTS.sha256`
pins the vendored tree by content and `supplychain/snapshot_test.go` fails when
the snapshot and its upstream disagree, so replacing the vendored `LICENSE`
with this repository's own would make the manifest describe a tree that does
not exist upstream. Vendoring faithfully and recording the conflict is the
honest option; hiding it inside the snapshot is not.

Two of the nine repositories carry the restricted licence (`Nomad-browser` and
`nomad-constant-rate-fabric`) and seven carry MIT. Which licence applies where,
and what an MIT repository may do with restricted-source code it vendors, is a
decision for the project owner rather than for whoever last ran the vendoring
script. Recorded as EB-10 in `nomad-protocol production/EXTERNAL_BLOCKERS.md`.
