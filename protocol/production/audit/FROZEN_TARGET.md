# Frozen review target

Filled in at handover, so that it always names real commits rather than
placeholders. Until then this file records the procedure only.

## Procedure

1. Freeze `claude/nomad-production-ready-dxv4ql` in every repository listed
   below: no further pushes until the assessment concludes or the assessors
   agree to a re-freeze.
2. Record the exact commit for each repository in the table.
3. Record the SHA-256 of each published artifact handed to assessors.
4. Record the date and the assessors' identities.
5. Any change to the target during assessment invalidates findings against
   the old target; re-freeze and tell the assessors rather than patching
   quietly.

## Repositories in scope

| Repository | Commit | Role |
|---|---|---|
| nomad-protocol | _pending freeze_ | specifications, threat model, registry |
| nomad-testnet | _pending freeze_ | integration root, epoch lifecycle, publication queue, uplink |
| nomad-local-reconstruction | _pending freeze_ | object verification, publisher identity |
| nomad-anytrust-mix-sim | _pending freeze_ | mix, shuffle proofs, DKG, threshold |
| nomad-rlnc | _pending freeze_ | network coding and resource bounds |
| nomad-constant-rate-fabric | _pending freeze_ | cadence and transport |
| nomad-selection-firewall | _pending freeze_ | public emission planner |
| nomad-semantic-basins | _pending freeze_ | local embedding and basins |
| Nomad-browser | _pending freeze_ | browser core and release pipeline |
| firefox-nomad, chromium-nomad | _pending freeze_ | integration contracts only |

## Artifacts

| Artifact | SHA-256 | Notes |
|---|---|---|
| _pending_ | | |
