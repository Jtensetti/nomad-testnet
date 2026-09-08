# Rights and source provenance

The top-level `LICENSE` is the Nomad Restricted Source License 1.0 already
adopted on this repository's `main` on 2026-08-27. It does not replace licences
or permissions attached to imported or previously published code.

The integration code was also published under MIT at the development commit
in `PACKAGING.lock.json`. Its exact notice is retained in
`LICENSES/nomad-testnet-MIT-before-consolidation.txt`. This packaging does not
claim to withdraw those permissions. Newly added packaging material follows
the top-level licence, subject to pre-existing and third-party rights.

| Scope | Licence in the pinned source |
| --- | --- |
| `browser/` | NOMAD RESTRICTED SOURCE LICENSE 1.0; nested components retain their licences |
| `protocol/` | MIT License; embedded skills retain recorded upstream attribution |
| `sdk/nomad-constant-rate-fabric/` | NOMAD RESTRICTED SOURCE LICENSE 1.0 |
| `sdk/nomad-anytrust-mix-sim/` | MIT License |
| `sdk/nomad-local-reconstruction/` | MIT License |
| `sdk/nomad-rlnc/` | MIT License |
| `sdk/nomad-selection-firewall/` | MIT License |
| `sdk/nomad-semantic-basins/` | MIT License |
| `components/nomad-constant-rate-fabric/` | NOMAD RESTRICTED SOURCE LICENSE 1.0 |
| Other integration snapshots: nomad-anytrust-mix-sim, nomad-local-reconstruction, nomad-rlnc, nomad-selection-firewall, nomad-semantic-basins | MIT License |
| `browser/components/` | MIT License, as recorded in each component's LICENSE |

Every snapshot includes its original LICENSE, unchanged. Exact revisions and
file digests are in `PACKAGING.lock.json`; integration dependency pins remain
in the existing `COMPONENTS.lock` and `COMPONENTS.sha256` files. External Go
dependencies such as Kyber, fixbuf and Go extended libraries retain their own
licences. This package does not claim ownership of them.

## What a commercial agreement can cover

- Permission to use owner-controlled restricted portions for an agreed purpose.
- A defined handover of architecture, evidence, source history and stewardship.
- Newly commissioned adaptation, if a delivery team and funding are agreed.
- Transfer of owner-controlled rights, subject to contributor/provenance review.

The MIT verification library can already be used under MIT. Payment is not
required merely to exercise those rights. An offer involving it must identify
the additional handover, future work or other assets being purchased.

No exclusive ownership of all included software is represented. Before a rights
transfer, identify the exact files and rights, check contributor ownership and
distinguish current branch licences from earlier versions. The historical
licensing blocker in `protocol/production/EXTERNAL_BLOCKERS.md` is retained as
evidence, not silently marked resolved by this inventory.

The Darkbloom/Eigen Labs, Firefox, Chromium, Nym and other reference forks are
not incorporated. Their presence elsewhere in the account does not make them
Nomad-owned commercial assets.
