# Internal security review — 2026-08-27

Scope: PROD-02 threat model / claim traceability and PROD-27 operational-output privacy boundary.

Reviewer role: second-party evaluator. This review is deliberately **not** presented as the independent cryptographic/systems/browser/privacy assessment required by PROD-04 or PROD-29.

## PROD-02 — PASS

Reviewed `docs/THREAT_MODEL.md` together with `production/CLAIM_TEST_MATRIX.md` against the PROD-02 criterion.

The threat model explicitly addresses every named capability: global passive observation, malicious peers, compromised minority mixers, replay, delay/drop, injection, Sybil pressure, endpoint fallbacks and long-horizon correlation. Assumptions and exclusions are stated rather than implied, including majority committee compromise, sustained-loss availability, fair allocation under Sybil pressure and long-horizon intersection. The matrix maps claims to actual test boundaries and records `none` or `CONTRADICTED` where evidence does not exist rather than promoting implementation code into evidence.

During review, stale future-state wording around publication, SiteID and browser isolation was found and corrected in commit `9e1070dc824c5e4116a2d61976672594a3599a14`. The exact-head docs workflow passed after that correction.

**Review conclusion:** the minimum acceptance evidence for PROD-02 — a reviewed threat model with explicit assumptions, exclusions and claim-to-test traceability — is satisfied. This review creates no broader anonymity claim and does not resolve any independent-review criterion.

## PROD-27 — NOT YET PASS

The process-level instrumentation is well designed:

- telemetry field names are a fail-closed allowlist and every allowed field carries a written rationale;
- known private fields such as query, basin, object ID, publication occupancy, deposit/session identifiers, plaintext and secret material are explicitly forbidden as regression traps;
- emitted values are independently scanned for the exact secrets used in the run in raw, hex, upper-hex, base64, base64url and raw-base64 encodings;
- the scanner is rehearsed against the secrets before a clean result is trusted;
- crash-output behavior is measured using a separately built crashing process, with a positive control proving that goroutine frame arguments are printed without the deployment control;
- Compose enforces `GOTRACEBACK=none`, including the YAML merge case where a service-local environment mapping would otherwise silently remove the inherited setting.

One production-boundary finding remains: the operator runbook requires `LimitCORE=0` and host coredump retention controls, but the project explicitly says it cannot verify those operator-host settings. A whole-process core file contains the complete address space and therefore can contain private keys regardless of the application telemetry schema. Until the shipping deployment or operator evidence enforces/verifies that control, the exact PROD-27 statement that crash data *cannot contain* secret keys is not fully demonstrated at the operator-host boundary.

**Review conclusion:** retain PROD-27 as PARTIAL. Closing it requires an enforceable/verifiable no-core-dump deployment control (or equivalent host evidence) plus a final privacy re-review. Do not remove the blocker merely because the application-level tests are green.

## Claim discipline

This review is evidence only for the two scopes above. It does not constitute independent audit evidence, red-team evidence, operator independence, WAN evidence or production approval.
