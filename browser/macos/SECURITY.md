# Native macOS client security contract

This contract defines what the downloadable native Nomad Browser alpha must
prove. It covers the private reader interface and its local verified cache. It
does not claim that the live, multi-operator anonymity network or anonymous
publication path is complete.

## Threat boundary

The query and selected result are private state. They remain in SwiftUI memory
and may read the local Nomad cache, but they cannot invoke a network planner,
resolver, socket, web view, external URL handler, telemetry or crash uploader.
The shipped alpha has no network client/server entitlement and intentionally
contains no fabric transport. A separately sandboxed Nomad materializer writes
verified objects into the cache. The browser discovers them on a public
five-second local timer that is independent of the query and selected document.

Only canonical payload bytes whose SHA-256 commitment and Ed25519 signature
verify under `nomad-object-v1 || SHA256(payload)` are eligible for decoding.
The signing key must also match a pinned trust anchor. The native renderer
accepts only bounded UTF-8 plain-text documents; it does not interpret HTML,
JavaScript, URL schemes or active media.

## Alpha client Definition of Done

| ID | Requirement | Automated evidence | Status |
|---|---|---|---|
| MAC-01 | There is no address field or general URL navigation. | Native SwiftUI source review; external `openURL` action is discarded. | MET |
| MAC-02 | A private query cannot call networking code. | Source capability gate plus App Sandbox without network entitlements. | MET |
| MAC-03 | No web engine or ordinary network framework is present in the release binary. | `otool` gate rejects WebKit, CFNetwork and Network. | MET |
| MAC-04 | Search reads only already-local objects. | Local search test and absence of any network callback/API. | MET |
| MAC-05 | Object identity is exact, not semantic. | SHA-256 commitment and domain-separated Ed25519 tests. | MET |
| MAC-06 | Unknown publisher identities fail closed. | Valid-signature/untrusted-key negative test. | MET |
| MAC-07 | Active or ambiguous content cannot reach a renderer. | Exact plain-text media type and native `Text` rendering only. | MET |
| MAC-08 | Malformed, mutated, unsigned, untrusted and oversized input fails closed. | Negative verification tests and explicit input limits. | MET |
| MAC-09 | Query, cache and searchable content work are bounded. | Limits on query, object count, envelope, fields and indexed body text. | MET |
| MAC-10 | The distributed artifact supports Apple Silicon and Intel Macs. | CI rejects a release binary lacking arm64 or x86_64. | MET |
| MAC-11 | The app bundle and disk image pass platform integrity checks. | `codesign --verify` and `hdiutil verify` in release CI. | MET |
| MAC-12 | Every artifact is commit-addressed and has a SHA-256 checksum. | Immutable Actions artifact and GitHub prerelease assets. | MET |
| MAC-13 | Live cache discovery is periodic, local and independent of search; one malformed entry cannot suppress valid entries. | Injected-directory reload test and source capability gate. | MET |

All thirteen alpha client gates must pass in the same macOS CI run that
produces the DMG. A source-only pass is not release evidence.

## Credentialed distribution gates

| ID | Requirement | Automated evidence | Status |
|---|---|---|---|
| MAC-DIST-01 | The application and DMG are signed by the expected Developer ID Application team with hardened runtime and secure timestamps. | Ephemeral-keychain identity, TeamIdentifier, runtime and timestamp checks. | NOT_MET |
| MAC-DIST-02 | Apple accepts the exact DMG submitted for notarization and the ticket is stapled and validates. | Immutable `notarytool` result/log plus `stapler validate`. | NOT_MET |
| MAC-DIST-03 | Gatekeeper accepts both the stapled disk image and the contained application before publication. | `spctl` assessments and post-mount signature verification. | NOT_MET |
| MAC-DIST-04 | Release credentials are scoped to a protected environment, never stored in source/artifacts and removed from the runner after use. | Environment protection review and cleanup-path inspection. | NOT_MET |

These gates become `MET` only from one successful credentialed release run
and its commit-addressed artifacts. The fail-closed implementation and secret
handoff are documented in
[`NOTARIZATION.md`](NOTARIZATION.md).

## Deliberately unclaimed production gates

- packet/DNS capture across supported macOS versions and failure modes;
- a provisioned Apple App Group or equivalent reviewed production IPC boundary
  between independently signed fabric and browser applications;
- multiple independent Nomad operators and WAN adversarial testing;
- independent browser, systems, cryptographic and privacy review;
- successful credentialed Developer ID/notarization evidence and a signed,
  rollback-resistant updater;
- authenticated SiteID/key discovery, rotation and revocation;
- publication airlock and anonymous publishing.

Until those system gates pass, this artifact is a security-bounded reader
alpha, not a production-ready anonymity-network claim.
