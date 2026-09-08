# Nomad

**Verify content locally. Keep private reading separate from network activity.**

Nomad's verification library, local reader, network reference implementation
and supporting evidence are now assembled into **one evaluation repository**.
You do not need to collect nine repositories to assess the technology.

**Start with Nomad Verify:** a Go library for signed content, append-only
history, proof verification and detection of conflicting signed histories.
The broader Nomad network is an integration testnet with remaining production
requirements. This package is for technical evaluation and handover.

## See it work

Requires Git and Go 1.25 or newer. The demonstrations need no external Go
modules, account, API key, Docker, model download or paid infrastructure.

```bash
git clone --branch codex/nomad-product-package-20260907 https://github.com/Jtensetti/nomad-testnet.git nomad
cd nomad
./nomad demo
./nomad reader-demo
```

The first command exercises seven existing tests against the actual transparency
library: valid history, forged content, stale checkpoints, conflicting signed
histories and witness signatures. PASS means those scenarios passed locally.
The second opens a signed Swedish introduction to Nomad and searches it locally.
It explicitly pins the fixture's publisher key and uses the lexical baseline.
See the [evaluation guide](product/EVALUATION.md).

## What you can evaluate

| Part | Useful for | Included today |
| --- | --- | --- |
| **Nomad Verify** | Checking signed content and release/identity histories | Go source, inclusion/consistency proofs, Ed25519 checkpoints, freshness checks, witness policies, adversarial tests |
| **Nomad Reader** | Reading and searching an already supplied, verified collection | Linux CLI, macOS SwiftUI source, publisher trust checks, local cache and ranking |
| **Nomad Network** | Researching content distribution whose emission plan does not depend on private reading | Fixed-cadence cells, mix/DKG/RLNC components, live testnet and deployment harnesses |

The initial commercial conversation is **technology handover or a partner-owned
integration**, with the buyer's team responsible for operation and release review.
Read the [buyer brief](product/BUYER_BRIEF.md) and [handover scope](product/HANDOVER.md).

## One checkout, traceable sources

| Path | Contents |
| --- | --- |
| `sdk/` | Full pinned snapshots of all six core libraries, with tests and licences |
| `browser/` | Full pinned reader/client repository |
| `protocol/` | Specifications, threat model and readiness evidence |
| `cmd/`, `live/`, `deploy/` | Network integration implementation |
| `components/` | Exact library versions already used by the network integration |
| `product/` | Evaluation guide, buyer brief, handover and current scope |

Runtime and reader retain their existing component pins. Some copies are
intentionally duplicated: consolidation does not silently upgrade cryptographic
dependencies. [PACKAGING.lock.json](PACKAGING.lock.json) records every imported
file and full source commit. Original repositories remain available for history.
Browser-engine and unrelated upstream reference forks are outside this kit.

```bash
./nomad check          # verify imported sources; requires Python 3
./nomad status         # read the included readiness registry
./nomad test           # verification module, race detector and vet
./nomad test all       # every Go module; broader environment requirements
./nomad package        # source ZIP from a clean committed checkout
```

## Current boundary

The pinned production registry records **2 MET, 27 PARTIAL and 1 BLOCKED** out
of 30 requirements. These are development labels, not independent certification.
The [status page](product/STATUS.md) explains the evidence and remaining work.
No production anonymity guarantee, SLA, semantic model weights or turnkey web
browser are offered by this evaluation package.

## Rights and contact

The owner selected the Nomad Restricted Source License for commercial protection
and reports that MIT texts were introduced while the repositories were private.
The pinned source copies retain differing licence texts as provenance. Their
presence alone does not establish the history of permissions granted to others.
Read [COMPONENT_LICENSES.md](COMPONENT_LICENSES.md) before reuse. A commercial
agreement must identify the assets and rights, with any valid pre-existing and
third-party permissions respected.

Owner: **Jonatan Tensetti**, [Jtensetti on GitHub](https://github.com/Jtensetti).
For enquiries, [open an issue](https://github.com/Jtensetti/nomad-testnet/issues/new).
Network engineers can start with the [original integration guide](LEGACY_README.md).
