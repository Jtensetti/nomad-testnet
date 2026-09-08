---
name: headroom
description: Reduce agent token use by compressing large logs, search results, JSON/tool output and code context before reasoning over them. Use when tool output is large, CI logs are noisy, searches return many matches, or context is growing. Preserve every error and enough surrounding context to diagnose the root cause.
---

# Headroom

Token cost is mostly driven by what the agent reads repeatedly, not by how short its final prose is. Reduce input before spending reasoning on it.

## Core rule

**Do not feed a large raw tool result into the next reasoning step when a smaller lossless-for-the-task representation will do.**

If output is small (roughly <200 tokens), leave it alone.

## Compression order

For logs, tool output, JSON and search results, preserve in this order:

1. every error, failure, panic, assertion, stack trace and non-zero exit;
2. the first meaningful failure and its immediate setup/context;
3. lines/items directly relevant to the current hypothesis;
4. state transitions and anomalies;
5. a small first/last sample when ordering matters;
6. discard repetitive success noise and duplicate downstream failures.

Never summarize away the exact error text needed to reproduce or search for the failure.

## CI/log rule

Do not read an entire CI log by default.

Start with:

- job conclusion and duration;
- failed step name;
- first meaningful error;
- 20-40 lines of surrounding context;
- only then widen if the root cause is still ambiguous.

If ten jobs fail from the same setup error, diagnose one representative root failure before reading the other nine logs.

## Search/code rule

Prefer this hierarchy:

`tree/symbols -> targeted search -> narrow slices -> whole file only if necessary`

Do not open a dozen complete files to answer a question that can be resolved from two symbols and their call sites.

For repeated patterns, read representative instances first. Expand only when evidence shows meaningful variation.

## Tool-output discipline

- Request only fields needed for the decision.
- Use limits, filters, paths and line ranges whenever the tool supports them.
- Do not repeat a tool result in prose unless the repetition adds information.
- Do not re-read unchanged output merely because a new reasoning turn began.
- Keep references (path, line, run id, commit) so raw evidence can be retrieved later.

## Context discipline

When context is becoming large:

- retain current goal, invariants, unresolved hypotheses and recent evidence;
- retain exact security/protocol constraints;
- replace old verbose tool output with compact factual notes plus retrievable references;
- drop obsolete investigation branches before current evidence;
- never discard a still-unresolved failure merely to save tokens.

## Output discipline

For routine engineering turns, prefer conclusions, changed paths, test results and next action. Do not narrate obvious tool calls or restate code the agent just read.

## Safety

Compression may remove redundancy, never evidence required by a production gate. Security, cryptographic, anonymity and privacy failures must retain exact relevant evidence.

## Upstream

Adapted for Nomad from `romangalaxys10-spec/headroom-skill` (portable Headroom techniques; Apache-2.0 upstream attribution in that project). This project-local version intentionally has no helper-script dependency.
