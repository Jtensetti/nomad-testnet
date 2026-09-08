---
name: tldr-code
description: Token-efficient codebase exploration. Use when understanding unfamiliar code, tracing calls across files, locating impact, or when raw full-file reads would be large. Prefer structure, symbols, searches and slices before whole files.
---

# TLDR-code

Use code navigation to decide **what deserves to be read** before spending tokens reading it.

## Availability

If a `tldr` CLI is already installed, prefer it for structural navigation. Do not install new tooling merely to satisfy this skill during an active debugging loop.

Useful commands when available:

- `tldr tree <path>` - compact tree;
- `tldr structure <path>` - signatures/structure;
- `tldr search "<pattern>" <path>` - targeted search;
- `tldr calls <path>` - call relationships;
- `tldr impact <symbol> <path>` - reverse callers/impact;
- `tldr context <symbol>` - focused context;
- `tldr cfg <file> <symbol>` - control flow;
- `tldr dfg <file> <symbol>` - data flow;
- `tldr slice <file> <symbol> <line>` - dependency slice.

If `tldr` is unavailable, apply the same hierarchy with repository-native search/read tools (`rg`, language server/symbol search, `git grep`, line-range reads).

## Exploration ladder

1. tree/directories;
2. filenames and symbols;
3. exact search matches;
4. callers/callees/imports;
5. narrow line ranges around relevant code;
6. complete file only when control/data flow genuinely requires it;
7. multiple whole files only after the dependency graph shows they matter.

## Cross-repo Nomad rule

For an interface failure, first identify:

`producer symbol -> serialized/API contract -> consumer symbol -> test`

Read those four points before scanning either repository broadly.

For privacy/protocol changes, also locate the invariant/test that constrains the path before editing it.

## Impact before edit

Before changing a shared function/type/protocol field, find its callers/users. Token savings that omit blast-radius analysis are false economy.

## What not to do

- Do not dump repository trees with vendor/build/generated directories unless relevant.
- Do not open all search hits; rank by relevance and inspect a few first.
- Do not re-read unchanged whole files after a small edit; read the diff and affected symbols.
- Do not use compact structural output as proof that implementation behavior is correct; tests still decide that.

## Upstream

Adapted for Nomad from `parcadei/Continuous-Claude-v3` `tldr-code`. The original integrates a five-layer AST/call-graph/CFG/DFG/PDG analyzer; this project version retains its token-efficient navigation strategy and uses the CLI only when already available.
