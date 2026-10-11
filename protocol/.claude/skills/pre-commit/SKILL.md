---
name: pre-commit
description: Catch cheap deterministic failures before push. Use before committing/pushing meaningful changes, when introducing local checks, or when repeated CI failures could have been detected locally.
---

# Pre-commit

Move cheap feedback left. A remote runner should not be the first place that discovers formatting, syntax, lint, build or obvious unit-test failures.

## Before every meaningful push

Run only the checks relevant to the changed files, in cheapest-first order:

1. syntax/config validation;
2. formatter check;
3. lint/vet/type check;
4. targeted compile/build;
5. targeted unit/regression tests;
6. wider local integration only when the change justifies it.

Follow `.claude/skills/agent-efficient-ci/SKILL.md` for the Nomad-specific ladder.

## Repository-native first

Before adding tooling, look for existing:

- `.pre-commit-config.yaml`;
- Makefile/task runner targets;
- package scripts;
- Go/Python/Shell validation scripts;
- documented commands in `CLAUDE.md` or the repository README.

Use existing checks rather than creating duplicate frameworks.

## Hook policy

A local pre-commit hook is useful only for fast deterministic checks. Keep hooks short enough that agents do not bypass them.

Good hook candidates:

- formatting;
- syntax/YAML validation;
- `go vet`/targeted lint;
- shell syntax;
- repository consistency scripts.

Do not put multi-node, soak, fuzz, privacy campaigns or full `go test -race ./...` suites in a commit hook.

## Failure behavior

If a local check fails:

- do not push to ask CI the same question;
- fix/classify locally;
- rerun only the failed/affected check first;
- widen after green.

Never bypass a hook or disable a test merely to get a commit through.

## Changes to CI/workflows

Validate workflow/config syntax locally before push. Verify referenced paths and commands exist. A workflow that cannot start is a local configuration defect, not a reason to spend remote CI cycles.

## Upstream

Adapted for Nomad from `julianobarbosa/claude-code-skills` `pre-commit` (MIT). This version deliberately stays dependency-free and uses each Nomad repository's native checks.
