# Implementation status

Last reviewed: 2026-08-19.

| Area | Current artifact | Status | What is actually established |
|---|---|---|---|
| Cell representation | nomad-constant-rate-fabric | implemented experiment | Go types and UDP writes are exactly 1200 bytes in the v0.1 profile |
| Wall-clock cadence | nomad-constant-rate-fabric | implemented experiment | absolute-deadline scheduler emits one cell per interval and rejects catch-up bursts |
| UDP transport | nomad-testnet | implemented live testnet | three authenticated operator nodes exchange exact fixed-size datagrams on a dedicated IPv4 bridge using locally derived X25519+HKDF hop keys; a documented multi-host deployment is available, but no WAN/NAT/IPv6 claim is made |
| Public emission plan | nomad-selection-firewall | implemented experiment | count, size, cadence index, offset and peer slot depend only on public inputs |
| Operator topology and DKG ceremony | nomad-testnet | implemented live-testnet ceremony | each operator creates separate Ed25519, X25519 and prime-subgroup DKG secrets; signed topology consensus and a TLS multi-process DKG bind membership, epoch and threshold, while production peer discovery/session negotiation remain unimplemented |
| Payload-preserving mix | nomad-anytrust-mix-sim | implemented research integration | ElGamal ciphertext batches preserve 504-byte payloads through Kyber Neff sequence shuffles |
| Shuffle verification | nomad-anytrust-mix-sim | implemented research integration | each round has a checked non-interactive proof and fresh representation |
| Anytrust committee protocol | nomad-testnet | implemented live testnet | Kyber v4 Pedersen DKG runs in three separate TLS operator processes, requires full QUAL plus a unanimous signed activation certificate, and creates distinct private shares consumed by isolated share services and the networkless materializer; independent administration, rotation and review remain open |
| RLNC | nomad-rlnc | implemented experiment | GF(2^8) systematic/random coding, re-encoding, fixed packets and incremental decoding |
| Coded-symbol pollution resistance | none | missing | contradictions are detected when dependent, but innovative pollution is rejected only after object verification |
| Local lexical embedding | nomad-semantic-basins | implemented baseline | deterministic lexical vector only, not semantic understanding |
| Local model adapter | nomad-semantic-basins | implemented adapter | literal-loopback-only HTTP endpoint, no proxy and no redirects |
| Basin quantization | nomad-semantic-basins | implemented experiment | seeded 64-bit random-hyperplane signature |
| Basin privacy | none | missing production gate | inversion and membership leakage are not solved |
| Signed object manifest | nomad-local-reconstruction | implemented experiment | length, basin, generation, root, key and object signature are bound by Ed25519 |
| Exact object verification | nomad-local-reconstruction | implemented experiment | SHA-256 plus Ed25519 over the domain-separated object hash |
| Selection dependency boundary | nomad-testnet and Nomad-browser | implemented structural and process gate | CI inspects dependency graphs; the materializer has no socket imports or network namespace and the browser build has no network entitlement |
| Reader packet-trace comparison | nomad-testnet | implemented live-testnet experiment | a strict dedicated-bridge capture verifies exact 1200-byte cells, public cadence and signed ring destinations; WAN failures and blind supported-platform two-world captures remain |
| Distributed raw cache | nomad-testnet | implemented live-testnet baseline | each operator maintains a bounded immutable ciphertext cache with atomic writes and equivocation detection; multi-region durability, repair and partition behavior remain unproven |
| Browser verified-resource core | Nomad-browser | implemented native alpha and release pipeline | signed bundles, immutable verified cache, periodic query-independent disk reload, local-only adapter and deny-all egress contract; a protected fail-closed Developer ID/notary workflow exists, but no credentialed notarized artifact has been produced |
| Browser-engine isolation | Firefox/Chromium forks | missing production gate | integration notes only; engines do not yet enforce the core contract |
| Publisher deposit/airlock | none | missing production gate | architecture/threat-model concept only |
| SiteID/key discovery | none | missing production gate | embedded-key signatures do not establish a human-facing publisher identity |

“Implemented experiment” means runnable code with tests. It does not mean
independently reviewed, production-ready or secure against the full threat
model. The exact v0.1 completion boundary is in DEFINITION_OF_DONE.md.
