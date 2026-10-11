# External test report: pollution resistance, 2026-08-21

Second external report (see `2026-08-21-full-suite/` for the first and for why
these exist: the evidence rule accepts "GitHub Actions **or external test
report**", and Actions has assigned no runner since 2026-08-20T18:21Z).

Produced for PROD-12. Covers the same suites as the first report at newer
commits, plus the work that closes PROD-12's named evidence: the authenticated
coding design, the fuzz/property tests and the Byzantine pollution campaign.

**Result: every suite passed.** No FAIL line appears in any log.

**Commits under test** (branch `claude/nomad-production-ready-dxv4ql`, clean
trees, Go 1.25.0, Linux 6.18 x86_64):

| Repo | Commit |
|---|---|
| nomad-constant-rate-fabric | ca40d5b |
| nomad-anytrust-mix-sim | 7f7d7ad |
| nomad-rlnc | 70fc47c |
| nomad-semantic-basins | 179c752 |
| nomad-local-reconstruction | 04b9445 |
| nomad-selection-firewall | fea6344 |
| nomad-testnet | 99a80c1 |
| Nomad-browser | f929466 |

**Additional gates in this report**

- Every vendored component module in nomad-testnet built, vetted, race-tested.
- Every pinned snapshot in Nomad-browser digest-checked and race-tested.
- Conformance corpus checked against its encoders.
- Traffic-analysis and campaign-verdict self-tests.
- `gofmt` clean in every repository, vendored trees included.
- Two fuzz targets, 90 seconds each: `FuzzBoundedDecoderStaysWithinBudget`
  (134,125 executions, 78 new interesting inputs) and
  `FuzzHonestGenerationDecodesExactly`. Both pass. Corpora are not committed;
  the seeds are in the targets.

**Environment.** Single machine, maintainer-produced. Valid rule-4 evidence by
the rule's own text; not independent review, not multi-platform, and not a
substitute for any gate that names independence.
