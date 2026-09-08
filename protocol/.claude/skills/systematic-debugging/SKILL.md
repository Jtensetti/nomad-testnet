---
name: systematic-debugging
description: Root-cause-first debugging for bugs, test failures, build failures and unexpected behavior. Use before proposing a fix after any deterministic failure, especially after CI failure or when a previous fix did not work.
---

# Systematic debugging

Random patching burns tokens and creates misleading CI churn. Find the cause before changing production code.

## Iron rule

**No fix before root-cause investigation.**

## Phase 1 - Investigate

1. Read the first meaningful error completely.
2. Reproduce with the smallest local command that can trigger it.
3. Check the diff/recent commits that could explain it.
4. Identify which component boundary first becomes wrong.
5. Classify the failure using `agent-efficient-ci`: CONFIG, ENVIRONMENT, BUILD, TEST, FLAKY, INTEGRATION, SECURITY/PROTOCOL or INFRASTRUCTURE.

If it cannot be reproduced, gather evidence. Do not guess.

## Phase 2 - Compare

Find a nearby working example or known-good path. Compare broken and working behavior explicitly. List concrete differences before deciding which one matters.

For cross-repo Nomad failures, compare the interface contract at both sides rather than assuming which repository is wrong.

## Phase 3 - Hypothesis

State one falsifiable hypothesis:

`I think X is the root cause because Y; command/test Z will distinguish it.`

Test it with the smallest possible experiment. Change one variable at a time.

If disproved, discard the hypothesis instead of stacking another speculative fix on top.

## Phase 4 - Fix and verify

1. Add or identify a test that fails for the root cause when practical.
2. Make one focused fix.
3. Run the cheapest targeted check.
4. Widen validation only after it passes.
5. Confirm the original failure is gone and no required invariant was weakened.

## Three-attempt stop

After three failed fix attempts for the same root failure, **stop editing**. Re-open the investigation and question the architecture or assumptions. Do not attempt fix #4 as another guess.

This is especially important for protocol/security work where repeated patches can accidentally weaken an invariant.

## Multi-component tracing

When failure appears downstream:

`observable symptom <- consumer <- interface <- producer <- original state`

Trace backward until the first incorrect state or violated contract. Fix there, not at the final symptom.

## CI interaction

A red CI run is evidence, not a command to patch. Pair this skill with `gh-fix-ci` to extract the root snippet and `agent-efficient-ci` to decide the cheapest local reproduction.

## Upstream

Adapted for Nomad from `obra/superpowers` `systematic-debugging` (MIT). The root-cause, hypothesis/testing and three-failed-fixes stop rules are preserved.
