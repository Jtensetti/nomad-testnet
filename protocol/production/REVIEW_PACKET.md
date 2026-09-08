# Second-party review packet: PROD-02 and PROD-27

Two criteria are held by one thing each, and it is not engineering.

| Criterion | What it asks for | What is missing |
|---|---|---|
| PROD-02 | "Reviewed threat model with explicit assumptions, exclusions and claim-to-test traceability." | The word *reviewed*. The artifacts are complete; their author must not be the one who judges them adequate. |
| PROD-27 | "Schema allowlist, log-scraping tests, retention controls and **privacy review**." | The review. The allowlist, the scanner and the crash control were all authored here. |

Neither needs external independence. PROD-04 and PROD-29 are the criteria that
do, and nothing in this packet touches them. What these two need is a second
party: any maintainer who did not write the artifacts under review. Completing
this packet closes PROD-02 and one of PROD-27's two blockers.

**This packet does not contain a verdict, and must not be completed by the
author of the artifacts it reviews.** The verdict blocks at the end are empty
on purpose. A packet returned with them filled in by the same session that
wrote the artifacts would be a fabricated review, which the project's rules
forbid in as many words.

## The same packet, as a worksheet

<https://claude.ai/code/artifact/e370b9f5-f705-4bf4-954d-4ea680c74bf5>

Every question below, with a mark and a note field per item, a progress
counter, and a button that assembles the verdict block for pasting back into
this repository. Marks live in the reviewer's browser and nothing is sent
anywhere; the page cannot write to the repository, which is why the last step
is still a paste.

Use either. This file is the reference and the worksheet is the convenience,
and if they ever disagree, this file is right.

## How to use this

Each item is a question with a locatable answer, not an invitation to form an
impression. Answer it from the artifact, mark it, and move on. An item you
cannot answer is a finding, and findings are what this is for.

Marks: **OK** (checked, and it holds) / **GAP** (checked, and it does not) /
**UNCLEAR** (the artifact does not let you decide).

Budget: roughly 45 minutes for PROD-02 and 30 for PROD-27, reading
`docs/THREAT_MODEL.md` (157 lines) and `production/CLAIM_TEST_MATRIX.md` (250
lines).

---

## PROD-02: the threat model

The criterion names ten adversary capabilities. `docs/THREAT_MODEL.md` has a
row for each under **Where each capability stands**. For every row, the
question is the same three-part one, so it is stated once here rather than
thirty times:

1. Does the row state a **position** — targeted, bounded, or not defended?
2. Does it state what is **excluded**, in words that could disappoint someone
   who wanted the broader claim?
3. Does its **evidence** pointer resolve to a row in
   `production/CLAIM_TEST_MATRIX.md` that is not `none`? A capability claimed
   as targeted whose matrix row says `none` is the defect this check exists
   to find.

| # | Capability | Position / exclusion stated? | Evidence pointer resolves? | Mark |
|---|---|---|---|---|
| 1 | Global passive observation | | | |
| 2 | Malicious peers | | | |
| 3 | Compromised minority mixers | | | |
| 4 | Replay | | | |
| 5 | Delay and drop | | | |
| 6 | Injection | | | |
| 7 | Sybil pressure | | | |
| 8 | Endpoint fallbacks | | | |
| 9 | Long-horizon correlation | | | |
| 10 | Endpoint boundary (`## Endpoint boundary`) | | | |

Then five questions about the document as a whole:

| # | Question | Where to look | Mark |
|---|---|---|---|
| 11 | Is any capability marked **targeted** whose matrix rows are all `none`? The threat model says this must not happen; check it rather than trust it. | both files |  |
| 12 | The **long-horizon correlation** row says *not defended, and not claimed*. Is that consistent with every other claim in the document, or does some other row quietly assume repeated observations are safe? | THREAT_MODEL.md |  |
| 13 | The **global passive observation** row says cell timing is **not** independent of private activity and calls the matrix row CONTRADICTED. Is that stated plainly enough that a reader cannot come away believing timing is defended? | THREAT_MODEL.md, EVIDENCE_INDEX E-08 |  |
| 14 | Does `## Work required before deployment claims` list anything already claimed as done elsewhere in the registry? A "still required" item that is also cited as evidence is a contradiction. | THREAT_MODEL.md, readiness.json |  |
| 15 | Does `## Bounded v0.1 evidence` describe the *current* bound, or a bound that has since moved? | THREAT_MODEL.md, EVIDENCE_INDEX |  |

### PROD-02 verdict

- Reviewer (name, and how you are not the author): 
- Date: 
- Items marked GAP or UNCLEAR: 
- Verdict (**reviewed and adequate** / **reviewed with findings, listed above** / **not adequate**): 

Record the outcome in `production/readiness.json` under PROD-02 and add an
entry to `production/EVIDENCE_INDEX.md` naming the reviewer and the date. A
verdict of *reviewed with findings* still closes the blocker if the findings
are recorded — the criterion asks for a review, not for a clean one.

---

## PROD-27: operational output and privacy

The criterion names four things. Three are built; the fourth is this review.

| # | Question | Where to look | Mark |
|---|---|---|---|
| 1 | The allowlist fails closed on any field without a written public rationale. Pick three counters at random from `live/telemetry` and read their rationales. Does each say why the field is safe, or only what it counts? | `nomad-testnet` `live/telemetry` |  |
| 2 | Fourteen counters are named **forbidden** with a reason each. Is any of them forbidden for a reason that would also forbid a counter currently allowed? | `live/telemetry` |  |
| 3 | The log scraper searches raw, hex, upper hex and three base64 forms, and is rehearsed against all five secrets before it is trusted. Does the rehearsal actually fail when a secret is absent from the corpus — that is, is the instrument checked, or only run? | `live/telemetry` tests |  |
| 4 | `GOTRACEBACK=none` is set on every compose service, and a test fails any service that declares its own environment without repeating it. Read that test. Would it catch a service added tomorrow? | `deploy/compose.yaml`, its test |  |
| 5 | Retention: output is bounded rather than accumulating. Is there any file a long-running operator writes that grows without bound? | `deploy/`, `live/node` health output |  |
| 6 | The second blocker on PROD-27 says operator host settings — journald, core dumps — cannot be verified from here. Is that a genuine limit of this project's scope, or work that has simply not been done? Your answer decides whether PROD-27 can reach MET on the review alone. | `deploy/OPERATOR_ONBOARDING.md` |  |

Question 6 is the one that needs a second party most. It is a scope judgement,
and the author of a scope statement is the worst person to judge whether it is
a limit or an excuse.

### PROD-27 verdict

- Reviewer (name, and how you are not the author): 
- Date: 
- Items marked GAP or UNCLEAR: 
- On question 6, is the operator-host blocker a genuine scope limit? (yes / no / needs work): 
- Verdict (**reviewed and adequate** / **reviewed with findings, listed above** / **not adequate**): 

---

## What completing this does not do

It does not make the threat model externally reviewed. PROD-04 (independent
cryptographic review) and PROD-29 (independent assessors) require someone
outside this project, and no amount of internal review substitutes for them —
they are recorded in `production/EXTERNAL_BLOCKERS.md` as EB-4.

It does not change any measurement. If a review finds that a claim outruns its
evidence, the fix is to narrow the claim or run the measurement, not to record
the review as adequate.
