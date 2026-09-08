# External test report: gate integrity, 2026-08-24

The evidence rule (PRODUCTION_DEFINITION_OF_DONE, item 4) accepts "the relevant
GitHub Actions **or external test report**". This is the external form: the
suites and gates the workflows run, executed directly, with complete logs
digested in `SHA256SUMS`.

It exists because this session's work was mostly about gates that were not
gating, and a claim that they now do should be evidenced by running them rather
than by describing them.

## What ran

**Per Go repository** (log = `<repo>.log`), at the recorded commit with a
clean working tree: `go build ./...`, `go vet ./...`, `gofmt -l`,
`go test -race -count=1 ./...`, and `govulncheck ./...`.

**`nomad-testnet-gates.log`** additionally covers: every vendored component
module built, vetted, race-tested and scanned; the deposit-path experiments on
the dedicated non-race step; the conformance corpus against its encoders on
amd64 and on 386; the 386 package suites; all six supported build targets; the
traffic-analysis self-tests; the campaign-verdict self-tests; and the full
preregistered rule applied to the publication campaign's seven worlds.

**`nomad-protocol.log`**: `scripts/check_docs.py`.

**`engine-forks.log`**: the egress-inventory verifiers. Recorded for
completeness; per DEC-013 the forks are parked.

## Result

**Every check passed.** 55 recorded `exit=0` lines, no non-zero exit, no
`FAIL` line, and every log terminates in an exit line — the last of those
checked because an incomplete report that reads as clean is exactly the failure
mode this session spent its time on.

Notably green for the first time: `go test -race ./...` in nomad-testnet,
which had been timing out at Go's ten-minute package default, and
`govulncheck` in all nine repositories, which previously ran in one and failed
there.

## Toolchain

`GOTOOLCHAIN=go1.25.13` throughout. The Go version is itself part of what this
report evidences: every repository pinned 1.23 until today, which had stopped
receiving backported security fixes.

## Commits under test

Branch `claude/nomad-production-ready-dxv4ql`, clean working trees.

| Repo | Commit |
|---|---|
| nomad-constant-rate-fabric | 8c79820 |
| nomad-anytrust-mix-sim | 9391eab |
| nomad-rlnc | 8491ae3 |
| nomad-semantic-basins | 29e2d97 |
| nomad-local-reconstruction | 3f87f8f |
| nomad-selection-firewall | f45a5f9 |
| nomad-testnet | eece3e5 |
| Nomad-browser | 41631ae |
| nomad-protocol | c7275c0 |

Full 40-character hashes appear in each log's header.

## What this report does not establish

It is a run of this project's own gates by this project, on one host. It is not
independent assessment (PROD-04, PROD-29), not WAN evidence, and not a
production proving run. Every limitation recorded against an individual
criterion in `readiness.json` still stands.
