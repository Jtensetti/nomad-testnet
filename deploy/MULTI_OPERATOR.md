# Multi-operator deployment

The live binaries are deliberately deployable without Docker Compose. Compose
is the reproducible one-host acceptance profile; a real committee places each
operator on separately administered infrastructure.

## Trust and ownership split

Every operator receives only:

- the authority-signed `topology.json` and authority public key;
- its own `node-secrets.json`, containing only its Ed25519 identity and
  epoch-scoped X25519 private key;
- its own `threshold-share.json` from the epoch DKG;
- its own raw-cache and sequence-state volumes.

No operator receives another operator's secret volume. The reader/materializer
receives public configuration, one authenticated raw cache and public partial
proofs; it never receives a threshold secret share or node identity key.

Before bootstrap or content work, each administrator runs `nomad-operator
init` locally and sends only the resulting self-signed enrollment to the
topology coordinator. The coordinator creates one deterministic draft with
`nomad-topology draft`. Every administrator inspects that complete document and
returns `nomad-operator attest` output. The coordinator can finalize only with
one valid, same-draft attestation per listed member. Each node derives its
directed hop keys locally via X25519+HKDF; the coordinator never handles a
pairwise MAC key. Run `nomad-operator verify` against the final topology before
starting either process.

Each operator runs locally (example A):

```bash
install -d -m 0700 /var/lib/nomad/ceremony
nomad-operator init \
  --id=operator-a \
  --endpoint=203.0.113.10:4200 \
  --partial-endpoint=https://operator-a.example:4300 \
  --secret=/var/lib/nomad/ceremony/node-secrets.json \
  --enrollment=/var/lib/nomad/ceremony/enrollment.json
```

The coordinator collects only the public enrollment files and publishes the
draft:

```bash
nomad-topology draft \
  --network-id=nomad-live \
  --epoch=1 \
  --cell-interval-ms=50 \
  --enrollments=operator-a.json,operator-b.json,operator-c.json \
  --out=topology-draft.json
```

After independently comparing the draft digest and reviewing every field, each
operator returns an attestation:

```bash
nomad-operator attest \
  --secret=/var/lib/nomad/ceremony/node-secrets.json \
  --draft=topology-draft.json \
  --out=operator-a.attestation.json
```

The authority key is generated once per authority lifecycle with
`nomad-topology authority-init`. The coordinator then finalizes the epoch:

```bash
nomad-topology finalize \
  --draft=topology-draft.json \
  --attestations=operator-a.attestation.json,operator-b.attestation.json,operator-c.attestation.json \
  --authority-private=authority.key \
  --out=topology.json

nomad-operator verify \
  --secret=/var/lib/nomad/ceremony/node-secrets.json \
  --topology=topology.json \
  --authority-key=authority.pub
```

Compare the reported topology digest out of band before opening the epoch.

The bootstrap command in this repository is a ceremony harness. For a real
operator set, run the authenticated DKG as an independently witnessed epoch
ceremony, deliver each output share over that operator's administrative channel,
and erase the ceremony host. Do not copy the Compose bootstrap volume layout to
production.

## Network prerequisites

The signed topology must name stable UDP endpoints for port 4200 and stable
partial-proof endpoints for port 4300. The current proof service is plain HTTP;
run both services inside an operator-authenticated tunnel such as WireGuard.
The inner Nomad datagram HMAC remains mandatory because it binds topology,
epoch, receiver, sender, batch coordinate and sequence independently of the
tunnel.

Allow constant-rate UDP between the signed peers. Do not use an autoscaler,
proxy, retry layer or load balancer that bursts, coalesces, duplicates or
selects traffic in response to cache demand. Pin each signed endpoint to one
operator instance for the epoch.

## Per-operator processes

Operator A starts its node with only operator A's files:

```bash
nomad-node \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --secrets=/run/nomad/node-secrets.json \
  --listen=:4200 \
  --cache=/var/lib/nomad/raw \
  --state=/var/lib/nomad/sequence \
  --health=/run/nomad/health.json

nomad-share \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --descriptor=/etc/nomad/descriptor.json \
  --share=/run/nomad/threshold-share.json \
  --cache=/var/lib/nomad/raw \
  --out=/var/lib/nomad/partials \
  --interval=1s \
  --listen=:4300
```

Repeat with distinct secrets, storage and hosts for B and C. Run as an
unprivileged dedicated user with a read-only root filesystem, no Linux
capabilities, a private temporary directory, an explicit file allowlist and an
egress policy limited to the signed peers.

## Reader-side processes

The public fetch plan is authority signed and independent of browser activity.
On a reader host, run:

```bash
nomad-partial-fetch \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --plan=/etc/nomad/fetch-plan.json \
  --out=/var/lib/nomad/partials \
  --interval=1s

nomad-materializer \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --descriptor=/etc/nomad/descriptor.json \
  --cache=/var/lib/nomad/raw \
  --partials=/var/lib/nomad/partials \
  --out=/var/lib/nomad/verified \
  --interval=1s
```

The materializer imports no socket package and must have networking disabled at
the OS/container boundary. Sync or mount `/var/lib/nomad/verified` into the
Nomad Browser object cache. Cache refresh is periodic and must never be invoked
by a search event.

## Epoch change and recovery

Topology, hop keys, identity attestations, threshold shares and persistent
sequence state are one epoch. Rotate all of them together. Never restore old
sequence state under a current hop key. A lost sequence state requires a fresh
epoch; an equivocation, invalid share or unexplained drop alarm pauses that
operator rather than silently changing cadence or routing.

Before admitting an operator set, run the same commit's unit/race/vet checks,
the Compose end-to-end gate, packet-capture verifier and a WAN fault campaign.
Record the signed topology digest, image digest, evidence hashes and operator
sign-offs in the release record.
