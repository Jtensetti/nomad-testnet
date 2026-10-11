# Gate triage: what stands between here and 30/30

Written 2026-08-20 against `production/readiness.json` and the evidence rule in
`docs/PRODUCTION_DEFINITION_OF_DONE.md`. It answers one question per gate: what
is actually missing, and who can supply it.

## The binding constraint right now

The evidence rule permits `MET` only when, among other things:

> 4. the relevant GitHub Actions or external test report is successful

GitHub Actions has assigned **no runner** to `nomad-testnet` since
2026-08-20T18:21Z: every workflow, on every branch, fails in two to three
seconds with no logs and `runner_id: 0`. The usual cause is an Actions
spending or minutes cap.

**Correction (2026-08-21).** The rule reads "GitHub Actions **or external
test report**", so the outage does not cap promotions: a complete, digested
external run of the same suites satisfies item 4. The first such report is
`production/reports/2026-08-21-full-suite/`, and PROD-08 was promoted on it.
Restoring Actions remains worthwhile -- a hosted run is cheaper to audit than
a maintainer-produced log -- but it no longer gates every promotion.

## Class A — evidence complete, waiting only on rule 4

Nothing here needs more engineering. Each satisfies rules 1, 2, 3 and 5 and
flips to MET on a green run.

| Gate | Evidence | Note |
|---|---|---|
| PROD-08 | epoch lifecycle: membership, rotation, forward secrecy, erasure, 5-operator recovery drill, all with adversarial tests, on the production path, with published vectors | staged; spec is now normative v1 |

Candidates that still need an evidence audit before being listed here:
PROD-02 (the claim/test matrix now supplies the traceability its blocker
named), PROD-09 (dependency gates plus the shaper process boundary), and
PROD-12 (the Byzantine pollution campaign).

## Class B — real work still to do, and I can do it

| Gate | What is missing |
|---|---|
| PROD-01 | conformance schema, remaining golden vectors, compatibility matrix, signed spec tag |
| PROD-07 | active-adversary fault injection; signed blame reports (the shuffle receipts already make a faulty mixer identifiable) |
| PROD-15 | site recovery drill; the SiteID spec is still DRAFT |
| PROD-16 | cross-platform vectors; mutation, truncation, rollback and parser-differential tests |
| PROD-17 | the correlation experiment exists in-process; needs the distributed deposit path (A-15) |
| PROD-19 | downgrade, replay and stale-directory tests |
| PROD-20 | a documented admission and rate-control model; saturation and eclipse tests |
| PROD-24 | semantic service sandbox, authenticated IPC, model hash attestation, attempted-egress capture |
| PROD-27 | metrics/log schema allowlist, log-scraping tests, retention controls |

## Class C — needs a second party, and must never be self-approved

These cannot be closed by this project's own agents or maintainers. The
project's own rules say so, and fabricating any of them is explicitly
forbidden.

| Gate | Needs | Blocker |
|---|---|---|
| PROD-03 | an implementation built by someone else, without sharing protocol code | EB-5 |
| PROD-04 | independent cryptographic review; no maintainer may self-approve | EB-4 |
| PROD-05 | five **independently administered** nodes — five machines on one cloud account is one trust domain, not five | EB-2 |
| PROD-21 | three independent **operators** (the *regions* half is unblocked by cloud infrastructure; the operators half is not) | EB-2 |
| PROD-25 | **two independent builders** producing matching artifacts | external |
| PROD-29 | independent assessments with publicly identifiable reports | EB-4 |
| PROD-30 | a documented **two-person** release decision, plus a release red team | EB-6 |

## Class D — needs infrastructure, hardware or elapsed time

Reachable without a second party, but not with what this session has.

| Gate | Needs |
|---|---|
| PROD-10, PROD-11, PROD-13 | multi-region WAN hosts; PROD-11 additionally wants 72 hours of capture **per supported platform** |
| PROD-22, PROD-23, PROD-26 | a macOS build and release binary; PROD-26 additionally needs Apple Developer ID credentials (EB-1) |
| PROD-28 | a **30-day soak**, a disaster-recovery exercise and an incident drill |

## What the ceiling actually is

Without a second party, seven gates (Class C) can never be MET. That caps the
achievable score at **23/30**, and reaching even that requires Apple
credentials, a macOS builder, multi-region hosts, and working CI.

**PROD-28 requires a 30-day soak.** Whatever else happens, 30/30 is at
minimum thirty days of wall-clock time away, and that clock cannot start until
the infrastructure exists. Any plan that promises it sooner is wrong.

## Suggested order

1. Restore GitHub Actions. Nothing else can be banked until then.
2. Add `SCW_PROJECT_ID` as a repository secret — the one WAN run that executed
   failed on exactly this, and no instance has ever been provisioned.
3. Merge the WAN tooling stranded on `agent/scaleway-wan`.
4. Work Class B in parallel; it needs none of the above.
