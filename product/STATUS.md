# Evaluation status — 7 September 2026

This page describes the consolidated package. Historical READMEs inside imported
snapshots describe their original context and can contain older prose. The
pinned machine-readable registry and cited implementation take precedence
when assessing current claims.

| Claim | Evidence available here | Limit |
| --- | --- | --- |
| Signed content and append-only proof verification | `sdk/nomad-local-reconstruction/reconstruct/`, `site/transparency/` and their tests | Library behaviour; no operated production log or independent audit |
| Conflicting-history and stale-view handling | Transparency monitor and witness tests | Depends on trust policy, observation and witnesses; no global visibility guarantee |
| Local signed-document reader | `browser/cmd/nomad-browser/`, `objectstore/`, capability tests and macOS source | Local documents; lexical baseline; no conventional web engine |
| Network reference implementation | Root `cmd/`, `live/`, `deploy/` | Testnet; one host does not establish independent operators |
| Core-source completeness | `PACKAGING.lock.json`, `./nomad check` | Snapshots remain pinned; duplicate integration versions are intentional |

## Whole-network readiness

`protocol/production/readiness.json` records **2 MET, 27 PARTIAL, 1 BLOCKED**.
`./nomad status` reads the values directly. These are the project's own criterion
labels. Consolidation promotes no criterion.

Material gaps include independent external assessment, evidence from independently
administered operators, longer operational/availability evidence, remaining
process-boundary integration and production release/key governance. See
`protocol/production/EXTERNAL_BLOCKERS.md` and each criterion's blockers.

Timing evidence is mixed. Development history records fixes and passing runs;
the 7 September campaign below failed on a CPU-starvation control-versus-control
comparison. That is an unresolved measurement result, neither a clean overall
timing gate nor by itself proof of a new private-activity leak.

- [Timing campaign 34124405426](https://github.com/Jtensetti/nomad-testnet/actions/runs/34124405426)
- [Original runtime CI 34124405471](https://github.com/Jtensetti/nomad-testnet/actions/runs/34124405471)
- [Original reader CI 34124401464](https://github.com/Jtensetti/Nomad-browser/actions/runs/34124401464)

These describe upstream revisions. This packaging's checks are recorded
separately in [VALIDATION.md](VALIDATION.md).

## Consolidation boundary

SDK snapshots expose complete library repositories. Runtime and browser retain
their original vendored versions and local module replacements. No cryptographic
implementation, wire format, trust check or scheduling behaviour was changed.
A newer SDK being present does not mean the runtime or reader integrates it.

Imported workflows are source history: GitHub executes only the top-level
`.github/workflows/`. The package workflow checks snapshots and demonstrations;
it does not replace runtime gates or the original macOS release pipeline.

This is one evaluation/handover repository. Old repositories have not been
retired, and this is not a one-command production privacy-network deployment.
