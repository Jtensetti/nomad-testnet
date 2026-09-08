# Handover inventory and responsibility

| Available deliverable | Location |
| --- | --- |
| One checkout for nine core repositories | Root runtime, `browser/`, `protocol/`, `sdk/` |
| Exact imported-file provenance | `PACKAGING.lock.json` and original GitHub commits |
| Runnable demonstrations | `./nomad demo`, `./nomad reader-demo` |
| Adversarial and integration tests | SDK, reader and runtime modules |
| Architecture, threat model and evidence | `protocol/`, `product/STATUS.md` |
| Licences and preserved notices | `COMPONENT_LICENSES.md`, `LICENSES/`, snapshot LICENSE files |
| Repeatable source export | `./nomad package` |

## Commercial scope

A transaction must define the exact revision, assets and rights; price and
payment event; any limited handover question period; acceptance criteria; and
who owns implementation, review and operation. No adaptation, response time,
exclusivity or perpetual support is implied by the source package.

Transferring owner-controlled rights does not extinguish existing MIT permissions.
Third-party code, trademarks and upstream project rights are excluded unless
their owners separately agree. Contributor/provenance review must settle the
precise rights before a binding assignment.

## Intended responsibilities

| Party | Role |
| --- | --- |
| Jonatan Tensetti | Accept or reject a commercial proposal and sign agreed rights transfers/licences |
| Buyer's team or a named delivery partner | Adaptation, human security review, deployment, maintenance and support |
| AI coding assistant within an agreed scope | Prepare code changes, reproducible evidence, documentation and technical answers |

AI assistance does not supply a contracting legal person, release authority,
independent security certification or ongoing service commitment. The owner is
not assumed to become a full-time operator or consultant.

## First evaluation

A buyer can inspect the demonstrations immediately. Its engineer can then name
one consumer boundary, release-event schema, trust/witness policy, persistence
requirements and refusal behaviour. That creates a bounded scope for a funded
team to estimate. It does not commit the owner to delivering a complete network.
