# Architecture and blocker map

What owns what, what is actually blocked by code, what is blocked only by
people or hardware, and which external reference bears on each. Written
against `production/readiness.json` at 30 criteria (2 MET, 27 PARTIAL, 1
BLOCKED) with a clean baseline on every repository: build, vet and
`go test -race` green in all nine Go repositories, `nomad-testnet` run the way
CI splits it (`live/node` separately), 33 packages passing.

This is a navigation document. `production/readiness.json` and
`docs/PRODUCTION_DEFINITION_OF_DONE.md` remain the source of truth for status,
and nothing here promotes anything.

## Who owns which protocol function

| Function | Repository | Package |
|---|---|---|
| Fixed-cadence cell scheduling, UDP transport | nomad-constant-rate-fabric | `fabric` |
| Hop envelope, sealed cell v2 | nomad-testnet | `live/hop` |
| ElGamal batch, Neff sequence shuffle, Pedersen DKG | nomad-anytrust-mix-sim | `mix` |
| Threshold epoch keys, ceremony, shares | nomad-testnet | `live/dkg`, `live/ceremony`, `live/share` |
| Epoch lifecycle, chain lock | nomad-testnet | `live/epoch` |
| Signed topology, operator set, thresholds | nomad-testnet | `live/topology` |
| RLNC coding and bounded decode | nomad-rlnc | `rlnc` |
| Local embedding, basin quantisation | nomad-semantic-basins | `basin` |
| Signed manifest, exact object verification | nomad-local-reconstruction | `reconstruct` |
| SiteID, descriptor chain, publication resolution | nomad-local-reconstruction | `site` |
| Transparency log, monitor, witnesses | nomad-local-reconstruction | `site/transparency` |
| Public emission planning, capability split | nomad-selection-firewall | `firewall` |
| Publication airlock, deposit, uplink | nomad-testnet | `live/airlock`, `live/deposit`, `live/uplink` |
| Entry operator service: socket, session table, batch seal | nomad-testnet | `live/entry`, `cmd/nomad-entry` |
| Materialiser, cache, fetch planning | nomad-testnet | `live/materialize`, `live/rawcache` |
| Networkless browser core, release pipeline | Nomad-browser | `egress`, `update`, `objectstore` |
| Engine forks | firefox-nomad, chromium-nomad | integration contracts only (DEC-013) |
| Two-world marginal rule | nomad-testnet | `scripts/two-world-analysis.py` |
| Two-world classifier | nomad-testnet | `scripts/trafficlab.py`, `scripts/traffic-lab.py` |

## Criteria with code work available

These have a blocker a repository can act on. The external half of each is
listed too, because closing the code half does not close the criterion.

| Criterion | Code work | Also needs |
|---|---|---|
| PROD-05 | epoch rotation and compromise recovery | EB-2 operators |
| PROD-07 | mixers as separate processes; cross-round accumulation for selective failure | EB-3 hosts, governance |
| PROD-10 | blind two-world captures under failure and congestion | platform matrix |
| PROD-11 | clock drift, suspend/resume, congestion, process-stall campaigns | 72-hour WAN |
| PROD-13 | measured durability and repair targets | multi-region |
| PROD-14 | saturation, not only load | EB-3 |
| PROD-16 | cross-platform beyond one package on Windows | macOS runner |
| PROD-17 | cross-epoch correlation; side-information adversary; attacks on the shuffle proofs | independent review, EB-3 |
| PROD-18 | replication; prime-order group encoding; re-submission via the read path | EB-3 |
| PROD-20 | lateness budget under flood | economics, red team |
| PROD-24 | attempted escape of the service sandbox | inherent attestation limit |
| PROD-26 | secure updater and rollback prevention | Apple signing, macOS host |
| PROD-12 | MET; the goal names further Byzantine work (pollution authentication, malformed coefficients, campaigns) | — |
| PROD-15 | MET-blocking blocker is external, but witness cosigning was missing and a live freeze followed from it (F-36) | independent review |

## Criteria blocked only by people, keys or hardware

No code in any repository moves these. PROD-01 (release key, EB-7), PROD-02
(review of the current documents by a non-author), PROD-03 (a third-party
implementer, EB-5), PROD-04 (independent cryptographic review, cannot be
self-approved), PROD-06 (separately administered committee), PROD-09
(independent assessment, macOS runner), PROD-19 (third-party consumer, EB-5),
PROD-21 (WAN, NAT, IPv6 across a real network), PROD-22 (Apple App Group,
independent assessment), PROD-23 (macOS runner; engine paths parked by
DEC-013), PROD-25 (signing key, independent builder), PROD-27 (second-party
privacy review, operator host settings), PROD-28 (30-day soak, multi-region,
dedicated host), PROD-29 (BLOCKED on EB-4, cannot be self-approved), PROD-30
(beta users, release keys, custody, red team).

## External references, and where each bears

| Reference | Available | Bears on |
|---|---|---|
| go-tuf | fork cloned | SiteID rotation, offline recovery, revocation, expiry, rollback protection |
| Tessera | **no fork exists in this account** | transparency, equivocation, split-view detection |
| Katzenpost / Pigeonhole | fork cloned, AGPL-3.0, design study only | publication airlock, fixed-throughput distribution, publisher non-interference |
| Maybenot | fork cloned | traffic-analysis lab, two-world campaigns |
| Nym / nymsphinx | fork cloned, Apache-2.0 | packet geometry, unlinkable hop routing, padding, replay resistance |
| drand | fork cloned | DKG, resharing, membership change, recovery, epoch lifecycle |
| Kyber | fork in account, not cloned | established primitives in place of homemade construction |

Tessera has no fork here. The transparency and split-view work therefore
proceeds from the published transparency-log model rather than from that
codebase, and says so rather than citing a reference it does not have.

## What the comparison against go-tuf found

Nomad's descriptor chain already carries the TUF properties it was compared
against, and each was checked against the code rather than assumed: exact
successor sequence, absorbing revocation carried forward from every ancestor,
possession proof from every newly introduced key, a separate offline recovery
authority with its own threshold, recovery-set changes that only the recovery
threshold can authorise, disjoint signing and recovery sets, and a validity
window enforced at resolution. No TUF-class gap was found in the chain.

The gap was one layer out, in distribution, and it is recorded as F-36.

## What the comparisons against Katzenpost and Nym found

Both came back as "keep what is here", for different reasons, and both are
recorded rather than left implicit.

Katzenpost/Pigeonhole is AGPL-3.0, so it was read for design and no code was
copied. What it contributed was two questions rather than a construction: its
storage replicas sit outside the mixnet on their own schedule, and their
capacity is a consensus parameter set as deliberate over-provisioning for a
target population, never derived from measured demand. That is Nomad's
invariant from the other direction, and asking it of the replication sweep is
what produced F-37.

Nym/nymsphinx is Apache-2.0, so licence was not the constraint; the
construction was. Sphinx is a source-routed onion whose value is hiding the
route from the relays, and Nomad has no route to hide -- peer selection comes
from the signed topology's public plan because the invariant requires it to.
Adopting it would also cost on the first property the plan names: Nym runs five
packet sizes and Nomad runs one. Recorded as DEC-028, including why
cross-testing against Sphinx would not mean anything.
