# Packaging validation — 8 September 2026

Scope: consolidation and local evaluation entry points built from the source
commits in `PACKAGING.lock.json`. No readiness criterion was promoted.

| Check performed locally | Result |
| --- | --- |
| SHA-256 and executable-mode verification of 412 imported files across eight repositories | PASS |
| Deliberate source modification rejected by the snapshot checker, then original restored | PASS |
| Seven named verification demonstration scenarios | PASS |
| Reader demonstration with a pinned publisher key | PASS: one verified object and one lexical search match |
| Complete verification module tests with race detector and vet | PASS: all four packages |
| Runtime build, vet and supply-chain tests with race detector | PASS |
| Browser and all six complete SDK snapshots build and vet | PASS |
| Protocol documentation consistency checker | PASS |
| New shell, Python and workflow syntax | PASS |

Environment: Linux amd64, Go 1.25.14 downloaded from go.dev and verified against
its published SHA-256. The demos disable toolchain/module downloads. Broader
runtime builds used the declared third-party Go modules.

This is not a fresh full-system acceptance campaign. Docker and macOS were not
available in the local environment; no multi-host deployment, notarization,
independent audit, paid infrastructure or long-duration soak was performed.
The existing upstream timing-campaign failure remains described in STATUS.md.

The new `evaluation-package` workflow repeats source checks, demos, verification
tests, SDK builds and the clean-commit source export. Existing runtime workflows
remain intact. Remote results must be assessed on the actual published commit;
this local report does not represent them as already passed.
