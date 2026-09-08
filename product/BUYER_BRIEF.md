# Nomad — technology for evaluation and handover

**Local verification and private content consumption, with inspectable evidence.**

A signature alone does not show every reader the same release history.
Nomad's verification library provides building blocks to check append-only
histories, reject unlogged content, expire stale views and retain evidence of
conflicting signed checkpoints. Witness policies let an integrator require
agreement beyond the log's own signature.

The commercial starting point is a bounded verification integration or technology
handover. The broader network and reader are included so a partner can assess
the architecture and take responsibility for its future direction.

## Review in one sitting

1. Clone this repository using the command in the [README](../README.md).
2. Run `./nomad demo` against the actual verification implementation.
3. Run `./nomad reader-demo` to read and search signed content locally.
4. Inspect [scope and evidence](STATUS.md), [rights](../COMPONENT_LICENSES.md)
   and the [handover inventory](HANDOVER.md).

All nine original core repositories are represented. Imported sources are
pinned to full commits and checked file by file. The local demonstrations
have no cloud service or model dependency.

## Integration opportunity

An initial integration could bind source/provenance references, artifact digests
and activation/deactivation events into an append-only release history. A
consumer would accept artifacts under an agreed signature, freshness and witness
policy. **That release-event adapter and its production deployment are proposed
work, not features represented as already delivered.**

Nomad does not claim to have invented transparency logs. Rekor and other
transparency systems are relevant alternatives. A buyer should compare reuse
of this Go implementation against extending its current stack. Value must come
from integration fit, a transferable code/evidence package and saved engineering
work, rather than a claim of unique cryptography.

## Commercial structure

The owner seeks a team that can take over implementation and operations.
Suitable structures are a bounded source/evidence handover; a separately agreed
commercial licence for restricted portions; or acquisition of owner-controlled
assets and stewardship. A buyer may fund an integration delivered and reviewed
by its own engineers or a named technical partner.

There is no assumed ongoing founder consulting, hosting obligation or SLA.
Scope, rights, acceptance and payment must be agreed in writing. The MIT library
is already available under MIT; existing rights are not sold as exclusive.

## Evidence and limitations

The source includes adversarial tests and recorded integration evidence. The
full network is not independently audited or production proven. The reader is
for local signed documents; included ranking uses a lexical baseline. There are
no bundled semantic model weights, customer references or promised operating
economics in this offer.

Development and packaging used AI assistance. Existing tests and agent review
are not an independent security audit. A partner's independent review and
production acceptance remain its own workstream.

Owner: **Jonatan Tensetti** — [GitHub](https://github.com/Jtensetti).
See [handover](HANDOVER.md) for deliverables and responsibilities.
