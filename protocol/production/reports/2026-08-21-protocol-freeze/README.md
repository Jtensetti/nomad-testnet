# External test report: protocol freeze groundwork, 2026-08-21

Third external report. See `2026-08-21-full-suite/` for why these exist: the
evidence rule accepts "GitHub Actions **or external test report**", and Actions
has assigned no runner since 2026-08-20T18:21Z.

Produced for the PROD-01, PROD-16, PROD-19, PROD-20 and PROD-27 work.

**Result: every suite passed.** No FAIL line appears in any log.

| Repo | Commit |
|---|---|
| nomad-constant-rate-fabric | ca40d5b |
| nomad-anytrust-mix-sim | 7f7d7ad |
| nomad-rlnc | 70fc47c |
| nomad-semantic-basins | 179c752 |
| nomad-local-reconstruction | 04b9445 |
| nomad-selection-firewall | fea6344 |
| nomad-testnet | ca37a90 |
| Nomad-browser | f929466 |

**Gates in this report**, beyond build/vet/race-test in every repository:

- Every vendored component module and every pinned browser snapshot, built,
  vetted and race-tested; the browser's digest lock verified.
- The conformance corpus checked against its encoders on **linux/amd64 and
  linux/386**, producing the identical digest `44f69ea7544f156feb773f9da9041de6c4c2b049292de9e371151cc09a1f0c45`
  on both, with 17 packages green under 386. A vector that depended on host
  word size would diverge here.
- All six supported build targets compile: linux amd64/386/arm64/arm and
  darwin amd64/arm64. windows/amd64 does not and is not supported.
- `gofmt` clean in every repository, vendored trees included.
- The traffic-analysis and campaign-verdict self-tests.
- nomad-protocol's documentation checks, which now also verify that
  PRODUCTION_STATUS.md's headline count and status breakdown match the
  readiness registry.

**Environment.** Single machine, Linux 6.18 x86_64, Go 1.25.0,
maintainer-produced. Valid rule-4 evidence by the rule's own text; not
independent review, and not a substitute for any gate naming independence.
