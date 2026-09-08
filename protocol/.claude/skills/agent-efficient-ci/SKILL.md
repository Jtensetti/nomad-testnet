---
name: agent-efficient-ci
description: Verify changes cheaply and locally before spending remote CI, tokens or maintainer attention. Use when about to commit or push, when a GitHub Actions run has failed, when deciding which tests to run, or when adding or changing a workflow. Covers the local escalation ladder, failure classification, the fast-failure rule, push discipline and CI trigger design.
---

# Agent-efficient CI

CI is a verification system, not a debugger. A red run is not progress.

The rule everything else follows from: **run the cheapest check that could
prove this candidate is already wrong, and only escalate when it passes.**

Agent reasoning, CI minutes and maintainer attention are all finite. Spending
them to rediscover a missing file or a YAML typo is waste that compounds — the
same log gets read, the same conclusion redrawn, and the notification volume
stops meaning anything.

## The ladder

Climb in order. Do not skip upward past a layer that would have caught the
failure; do not run a layer that cannot tell you anything new.

**1. Static sanity — seconds.** Syntax, formatting, linting, workflow and
config validity, referenced paths exist, required commands exist, it compiles.
Never push a failure from this layer.

**2. Targeted tests — seconds to a minute.** The smallest test set that covers
the change: the affected package, the changed component's unit tests, the
regression test for the bug in hand.

**3. Local integration — minutes.** Build the affected component, run its
integration tests, check generated artifacts, and reproduce the CI commands
that matter when it is practical to do so.

**4. Remote CI.** Answers *does a candidate that passed locally also pass in the
canonical environment?* It must not routinely answer *what basic mistake did I
just make?*

**5. Full-system suites.** Merge and release candidates, protocol changes,
security-sensitive changes, shared-library changes with wide blast radius,
dependency or build-system changes, anything crossing components. Not every
intermediate commit.

**6. Expensive and adversarial.** Performance, fuzzing, soak, multi-node
simulation, privacy and timing campaigns. Explicit checkpoints and affected
changes only. These are gates, not feedback loops.

## Cheapest check, by what changed

In these repositories, from the repository root:

| Changed | Cheapest check that can disprove it |
|---|---|
| Any Go file | `gofmt -l <dirs>` then `go build ./...` then `go vet ./<pkg>/` |
| One Go package | `go test ./live/<pkg>/` — not `./...` |
| Security-sensitive Go | add `-race` to the targeted package before widening |
| Shell script | `bash -n script.sh` |
| Python script | `python3 -c "import ast,sys; ast.parse(open('f.py').read())"` |
| GitHub workflow | `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` |
| Any nomad-protocol doc or registry | `python3 scripts/check_docs.py` |
| Vendored `components/` | `python3 scripts/repin-components.py` then `go test ./supplychain/` |
| Conformance vectors | `go run ./cmd/nomad-conformance -check conformance/wire-vectors.json` |
| Wire format, either side | `python3 conformance/reference/crosscheck.py conformance/wire-vectors.json` |

`go test -race ./...` in nomad-testnet takes minutes and runs wall-clock
campaigns. It is a layer-5 check. Run it before a push that matters, not
between edits.

## Classify before fixing

Name the failure before touching anything:

**CONFIG** workflow/YAML/config · **ENVIRONMENT** dependency, toolchain,
runner, permission, secret, quota · **BUILD** compile, link, package, type ·
**TEST** deterministic, caused by code · **FLAKY** nondeterministic or
timing-dependent · **INTEGRATION** cross-component or interface ·
**SECURITY/PROTOCOL** invariant, privacy, cryptographic · **INFRASTRUCTURE**
external service or platform.

Do not touch production code until the category makes that a reasonable
response. A CONFIG failure must never trigger a speculative protocol change.

**FLAKY is a claim, not a shrug.** "Flake" needs evidence: the same failure
reproduces identically on one re-run of an unrelated service, or the job died
before any test body ran, or it passed earlier on this exact commit. Otherwise
it is TEST. Never skip, disable or quarantine a test to get green.

## The fast-failure rule

A substantial job that fails in seconds did not run. Before reading it as a
defect, check: invalid workflow syntax, a path that does not exist, a missing
file or executable, dependency setup, permissions, the wrong working
directory, malformed arguments, config that failed to load.

A two-second failure is evidence about the harness, not the implementation.

## Push discipline

Prefer: inspect → reason → edit → local check → targeted test → consolidate →
push → CI confirms.

Not: edit → push → fail → read log → edit → push → fail.

Intermediate commits are fine as checkpoints. Remote CI is not a REPL.

One early failure generates many downstream ones. Fix the first meaningful
root cause and re-check; do not walk the list.

## Workflow design

- **Cancel superseded runs.** `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }` unless historical parallel runs are genuinely wanted.
- **Filter by path.** A documentation change must not launch a multi-node simulation.
- **Split fast from full.** Per-push checks stay minutes; expensive suites are merge-gated, scheduled or dispatched.
- **Separate informational from blocking**, so a candidate failure is distinguishable from development noise.

## The safety exception

Efficiency never removes a required gate. Skipping redundant intermediate work
is the point; skipping final verification is not.

Security, cryptographic, anonymity, privacy, protocol and release-critical
changes pass every applicable gate before they are called done — including the
expensive ones, including when it is inconvenient, including when the cheap
checks were all green. Cheap evidence first does not mean cheap evidence only.

## Doing it right looks like

Obvious failures caught before push. Local targeted validation before remote
CI. CI verifying credible candidates. Obsolete runs cancelled. Expensive
suites run when justified. Failures classified before fixes. Root causes
before symptoms. Notification volume tracking real defects rather than
iteration count. And no gate weakened to get there.
