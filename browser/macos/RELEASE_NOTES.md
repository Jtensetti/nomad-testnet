# Nomad Browser for macOS — alpha

This build adds live, query-independent cache discovery: the browser reloads
its local verified object directory every five seconds, never as a consequence
of search or document selection. Malformed cache entries are rejected
individually and can no longer suppress valid objects materialized by the live
Nomad fabric.

This build has no address field and no ordinary web renderer. It searches only
the verified local Nomad object cache and renders signed plain-text documents
with native SwiftUI controls.

Security controls in this artifact:

- macOS App Sandbox is enabled;
- network client and server entitlements are absent;
- the release binary is rejected if it links WebKit, CFNetwork or Network;
- no URLSession, socket, external-URL or web-view API is permitted in source;
- every displayed object must pass SHA-256 and Ed25519 verification over
  `nomad-object-v1 || SHA256(payload)`;
- a valid self-signature is insufficient: the publisher key must match a
  pinned local trust anchor;
- only `text/plain; charset=utf-8` is rendered;
- malformed, oversized, mutated, unsigned or untrusted objects fail closed;
- object count, encoded size, decoded fields, query length and indexed body
  text are bounded, and search is entirely local.

The protected distribution workflow publishes this release only after
Developer ID signing with hardened runtime and a secure timestamp, an Apple
notarization result of `Accepted`, successful ticket stapling and Gatekeeper
assessment of both the DMG and contained application. Independent review,
production IPC/update controls and the independently operated Nomad network
remain production gates.
