# External test report: full-suite run, 2026-08-21

Produced because GitHub Actions has assigned no runner to any repository since
2026-08-20T18:21Z, and the evidence rule (PRODUCTION_DEFINITION_OF_DONE, item
4) accepts "the relevant GitHub Actions **or external test report**". This
report is the external form: the same suites the workflows run, executed
directly, with the exact commits and complete logs recorded and digested in
`SHA256SUMS`.

**What ran, per Go repository** (log = `<repo>.log`): `go build ./...`,
`go vet ./...`, `go test -race -count=1 ./...` at the recorded commit.
For nomad-testnet additionally: every vendored component module built, vetted
and race-tested; the conformance corpus checked against its encoders
(`nomad-conformance -check`); the traffic-analysis self-tests; the campaign
verdict self-tests. For Nomad-browser additionally: the pinned-snapshot digest
lock verified and every snapshot module race-tested. For nomad-protocol:
`scripts/check_docs.py`.

**Result: every suite passed.** No FAIL line appears in any log.

**Commits under test** (branch `claude/nomad-production-ready-dxv4ql`,
clean working trees):

| Repo | Commit |
|---|---|
| nomad-constant-rate-fabric | 8ed80c2 |
| nomad-anytrust-mix-sim | 6e3aea4 |
| nomad-rlnc | d7c017c |
| nomad-semantic-basins | b5f8d59 |
| nomad-local-reconstruction | ff25433 |
| nomad-selection-firewall | fb4eef1 |
| nomad-testnet | 19b1d6c |
| Nomad-browser | 1485b34 |

Full 40-character hashes are in each log's header, together with `go version`
and the dirty-file count (0 everywhere).

**Environment.** Linux 6.18 x86_64, Go 1.25.0, single machine. This is a
maintainer-produced report: it is valid rule-4 evidence by the rule's own
text, and it is not independent review, not a multi-platform result, and not
a substitute for any gate that names independence.

**Boundary.** Suites that require live infrastructure (Compose live gates,
the timing campaign, WAN campaigns) are not part of this report; the WAN
campaign has its own evidence entry with its own digests.
