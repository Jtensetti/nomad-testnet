# Nomad engineering rules

Persistent rules for all agents working on Nomad. The complete production goal
is `production/GOAL.md`. The authoritative readiness registry is
`production/readiness.json` + `docs/PRODUCTION_DEFINITION_OF_DONE.md`.

## Repositories and roles

| Repo | Role |
|---|---|
| nomad-protocol | Specs, threat model, readiness registry, execution artifacts. No code. |
| nomad-constant-rate-fabric | Fixed-cadence cell scheduler + UDP transport (Go). |
| nomad-anytrust-mix-sim | ElGamal batch + Kyber Neff sequence shuffle + Pedersen DKG (Go). |
| nomad-rlnc | GF(2^8) RLNC coding/decoding (Go). |
| nomad-semantic-basins | Local embedding + basin quantization (Go). |
| nomad-local-reconstruction | Signed manifest + exact object verification (Go). |
| nomad-selection-firewall | Public emission planner; private/network capability split (Go). |
| nomad-testnet | Integration root: live fabric, topology, DKG, shares, materializer (Go). |
| Nomad-browser | Networkless macOS browser core + release pipeline (Go + Swift). |
| firefox-nomad / chromium-nomad | Engine forks; integration contracts only so far. |

## Skills

Skills are progressive-disclosure instructions. **Do not load all skill bodies at
session start.** Read only the skill(s) triggered by the current task so the
skills themselves do not become context overhead.

- `.claude/skills/agent-efficient-ci` — always read before committing/pushing,
  after CI failure, or when changing workflows. Cheapest-check ladder and
  failure classification.
- `.claude/skills/headroom` — read when logs/tool output/search results/code
  context are large. Compress input before reasoning; preserve exact failures.
- `.claude/skills/systematic-debugging` — read for every bug, build/test failure
  or unexpected behavior before proposing a fix. Root cause before patching;
  stop after three failed fix attempts and question assumptions/architecture.
- `.claude/skills/pre-commit` — read before meaningful pushes and when local
  checks/hooks are involved. Catch deterministic failures locally first.
- `.claude/skills/gh-fix-ci` — read for red GitHub Actions. Inspect bounded
  actionable failure snippets instead of whole logs, classify, reproduce
  locally, then fix.
- `.claude/skills/tldr-code` — read when exploring or tracing unfamiliar code.
  Structure/symbol/search/slices before whole-file reads; use `tldr` if already
  installed, otherwise apply the same hierarchy with native tools.

For a CI failure, the normal chain is:
`headroom -> gh-fix-ci -> systematic-debugging -> agent-efficient-ci -> pre-commit`.
Do not repeatedly push speculative fixes. `tldr-code` joins only when codebase
navigation is needed.

## Build/test commands

Every Go repo: `go build ./...`, `go vet ./...`, `go test -race ./...`.
nomad-testnet also has Compose live gates (`deploy/compose.yaml`, CI workflows)
and Selection Firewall dependency checks. nomad-protocol:
`python3 scripts/check_docs.py` (CI-enforced doc/registry consistency).

## Core privacy invariant

Private user activity must never create, remove, alter, reschedule,
accelerate, delay, retry, reroute, or otherwise modulate an externally
observable network event. Prefer losing/deferring work over emitting a
private-dependent signal. Never add catch-up traffic that depends on private
state. Never add ordinary-network fallback. Public planner APIs must not
accept private inputs (query, basin, object, reconstruction, publication
state).

## Evidence and claim rules

- Never set a readiness criterion to MET because code exists. MET requires:
  production-path implementation, positive+negative+adversarial tests at the
  named boundary, immutable evidence (commit/CI run/artifact digest), no
  unresolved Sev1/Sev2, and genuinely independent evidence where required.
- Never fabricate external independence, credentials, audits, or evidence.
  PROD-04 and PROD-29 cannot be self-approved.
- Distinguish: implemented / integration tested / production-boundary tested /
  independently assessed / production proven.
- Record evidence in `production/EVIDENCE_INDEX.md` with immutable refs.
- A subagent review is QA, not an independent external audit.

## Git conventions

- Work on branch `claude/nomad-production-ready-dxv4ql` in every repo.
- Keep `main` green; never force-push `main`; never rewrite published history
  that evidence references.
- Meaningful commit messages; security-sensitive changes in focused commits.
- Do not merge security-sensitive work on compilation alone: affected tests
  green, relevant CI green, evaluator review first.

## Security rules

- Never commit credentials or private keys; never print secrets in CI or
  docs; never copy all threshold shares into one artifact.
- Never disable or downgrade a cryptographic check as a workaround; a failed
  check fails closed, never becomes a warning.
- No silent fallback paths. Non-production bypasses must be fail-closed and
  explicitly marked non-production.

## Process

- Planner / implementer / evaluator separation for security-sensitive work:
  the implementer is never the only judge of its own change.
- Update `production/claude-progress.md` at checkpoints and
  `production/workstreams.json` continuously.
- New session: read this file, `production/claude-progress.md`,
  `production/workstreams.json`, recent git logs; run a baseline; continue
  the highest-priority unresolved requirement.
