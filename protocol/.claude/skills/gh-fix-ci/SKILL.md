---
name: gh-fix-ci
description: Diagnose failing GitHub Actions with minimal log/context consumption. Use when a PR or branch check is red. Extract the first actionable failure, classify it, reproduce locally when practical, and avoid reading duplicate or downstream logs.
---

# GitHub CI failure triage

The goal is not to read CI. The goal is to identify the smallest piece of CI evidence that reveals the root cause.

## Workflow

1. Identify failing checks for the current commit/PR.
2. Record workflow/job name, run id, event, head SHA, duration and failed step.
3. Fetch only the failed step/log tail or a bounded failure snippet first.
4. Preserve the exact first meaningful error plus ~20-40 surrounding lines.
5. Classify the failure using `agent-efficient-ci`.
6. Use `systematic-debugging` before changing code.
7. Reproduce locally with the cheapest equivalent command when practical.
8. Fix the root cause once, validate locally, then push a credible candidate.
9. Recheck the relevant CI status; do not automatically read every green log.

## Log budget

Default to a bounded snippet. Widen only when the first snippet cannot distinguish competing hypotheses.

Never ingest a complete multi-thousand-line Actions log merely because it is available.

If multiple jobs show the same setup/build error, treat later failures as duplicates until evidence proves otherwise.

## Fast-failure handling

For jobs that fail in seconds, inspect setup/config first:

- workflow syntax;
- missing path/file;
- working directory;
- unavailable command/dependency;
- permission/secret/quota;
- malformed arguments.

Do not read a two-second failure as a protocol implementation failure without evidence.

## Autonomous Nomad adaptation

The upstream OpenAI skill pauses for explicit user approval before implementation. Nomad's autonomous engineering workflow does not require a human checkpoint for routine CI repairs. Continue automatically after a root cause is established **unless** the change would:

- weaken a security/privacy/cryptographic invariant;
- disable or skip a required gate;
- require credentials or external approval;
- make an architectural change after three failed fixes.

Those cases stop and surface the blocker instead of forcing green.

## External checks

For non-GitHub Actions providers, inspect only enough metadata to identify the external system. Do not burn context reverse-engineering a provider that is not available from the current environment.

## Upstream

Adapted for Nomad from OpenAI `skills/.curated/gh-fix-ci`. This version keeps the actionable-snippet workflow but removes its mandatory per-fix approval pause for autonomous Nomad work.
