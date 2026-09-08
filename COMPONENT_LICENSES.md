# Rights and source provenance

The top-level `LICENSE` is the Nomad Restricted Source License 1.0 already
adopted on this repository's `main` on 2026-08-27. The owner states that the MIT
texts were introduced while the repositories were private and that the intended
public offering was protected by the restricted licence.

That history matters: a MIT text in git history does not by itself establish
when a copy was furnished to an external recipient, on what terms, or whether
a particular recipient acquired permissions. An earlier version of this
packaging incorrectly stated prior public MIT distribution as an established
fact. That statement is withdrawn.

The development snapshot named in `PACKAGING.lock.json` still contains a MIT
text. Its exact notice is retained in
`LICENSES/nomad-testnet-MIT-before-consolidation.txt`. Other imported copies also
retain their original texts, listed below. GitHub currently marks the source
repositories public, but no historical visibility log or third-party receipt
has been verified here. This inventory records file contents and the owner's
account; it does not decide their legal effect or issue a new MIT grant.

New packaging material follows the top-level licence. Any valid pre-existing
permissions and third-party licences remain unaffected. Reconcile the retained
texts and the exact rights before commercial reuse or an exclusive transfer.

| Scope | Licence text retained in the pinned source |
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

Do not infer from this table alone either that the complete project was offered
to the public under MIT or that every included asset can be transferred
exclusively. A proposal must specify the rights the owner controls and account
for any permissions actually granted to recipients.

Before a rights transfer, identify the exact files and rights, check contributor
ownership and distinguish current branch texts, historical access and any
actual distribution terms. The historical
licensing blocker in `protocol/production/EXTERNAL_BLOCKERS.md` is retained as
evidence, not silently marked resolved by this inventory.

The Darkbloom/Eigen Labs, Firefox, Chromium, Nym and other reference forks are
not incorporated. Their presence elsewhere in the account does not make them
Nomad-owned commercial assets.
