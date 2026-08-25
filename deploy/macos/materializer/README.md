# macOS reader process boundary

This package turns the existing `nomad-materializer` binary into a sandboxed macOS application boundary for the reader path.

The security goal is not merely "different packages". It is that private browser work and network scheduling do not share a process or a writable storage domain.

```text
network/fetch domain
  network entitlement: yes
  App Group: <TeamID>.nomad.fabric-cache
          |
          | raw cache + public topology/partials
          v
Nomad Materializer
  network entitlement: NO
  App Groups:
    <TeamID>.nomad.fabric-cache
    <TeamID>.nomad.browser-cache
          |
          | verified .nomadobject output only
          v
Nomad Browser
  network entitlement: NO
  App Group: <TeamID>.nomad.browser-cache
```

The browser is never a member of `nomad.fabric-cache`. The network/fetch domain is never a member of `nomad.browser-cache`. The materializer is the only process allowed to see both domains, and its signed sandbox has no network client/server entitlement.

This matters even if the browser later contains a bug: App Group membership itself is read/write, so a single group shared directly between browser and network process would create a potential browser-to-network signalling surface. Two groups make that direct storage path absent at the OS entitlement boundary.

## What CI proves

`macos-materializer.yml` builds the exact Go materializer as a universal arm64+x86_64 app, signs it with App Sandbox, injects two Team-ID-scoped App Groups, verifies that no network entitlement is present, launches the signed executable, and uploads the effective entitlement set and binary hash.

Ordinary CI uses the harmless test Team ID `N0MADTEST1`. A Developer ID build must supply the real `APPLE_TEAM_ID`; the build script refuses to sign a release identity with the test group.

Apple documents the `<TeamID>.<group-name>` App Group form specifically for macOS and checks group access against the signing developer team. This avoids requiring a separately registered `group.*` identifier for this macOS-only boundary.

## What remains before issue #7 can close

This package establishes the process/storage shape only. It does not yet prove host-level traffic independence. The remaining experiment must run release-shaped browser, materializer and network processes simultaneously, drive browser CPU/disk/UI/search workloads, capture packets at the host/kernel boundary and apply the unchanged preregistered 2% rule. A deliberately colocated positive-control build must still be detected.

The future publisher uplink needs the same rule: private publication preparation cannot share the fixed-rate sender's runtime or a browser-writable scheduling input.
