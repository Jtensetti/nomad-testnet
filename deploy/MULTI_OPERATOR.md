# Multi-operator deployment

The live binaries are deliberately deployable without Docker Compose. Compose
is the reproducible one-host acceptance profile; a real committee places each
operator on separately administered infrastructure.

## Trust and ownership split

Every operator receives only:

- the authority-signed `topology.json` and authority public key;
- its own canonical `epoch-%020d.secrets.json` files, each containing its
  stable Ed25519 identity and only that epoch's X25519 and dedicated DKG
  private keys;
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
install -d -m 0700 /var/lib/nomad/ceremony/secrets
nomad-operator init \
  --id=operator-a \
  --endpoint=203.0.113.10:4200 \
  --partial-endpoint=https://operator-a.example:4300 \
  --dkg-endpoint=https://operator-a.example:4400 \
  --secret=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
  --enrollment=/var/lib/nomad/ceremony/epoch-1.enrollment.json
```

The coordinator collects only the public enrollment files and publishes the
draft:

```bash
nomad-topology draft \
  --network-id=nomad-live \
  --epoch=1 \
  --cell-interval-ms=50 \
  --dkg-start-delay=10m \
  --dkg-phase-duration=2m \
  --dkg-threshold=2 \
  --enrollments=operator-a.json,operator-b.json,operator-c.json \
  --out=topology-draft.json
```

After independently comparing the draft digest and reviewing every field, each
operator returns an attestation:

```bash
nomad-operator attest \
  --secret=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
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
  --secret=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
  --topology=topology.json \
  --authority-key=authority.pub
```

Compare the reported topology digest out of band before opening the epoch.

Before the signed DKG start time, every administrator starts exactly one local
ceremony process. The state directory must be empty and private; an interrupted
session is deliberately non-resumable and requires a newly attested topology
with a fresh session ID:

```bash
install -d -m 0700 /var/lib/nomad/dkg /run/nomad
nomad-dkg \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --secrets=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
  --listen=:4400 \
  --state=/var/lib/nomad/dkg \
  --share-out=/run/nomad/threshold-share.json \
  --certificate-out=/etc/nomad/dkg-certificate.json \
  --tls-certificate=/etc/nomad/tls/dkg.crt \
  --tls-private-key=/etc/nomad/tls/dkg.key
```

All configured members must land in QUAL and every member must sign the same
manifest before any certificate activates. Identical message retries are
idempotent; a different message from the same sender and phase is recorded as
equivocation and aborts the ceremony. Compare the reported certificate digest
out of band. No coordinator ever receives a threshold secret.

`nomad-fixture-publisher` exists only to connect this ceremony to the repository's
deterministic acceptance object. It reads all mixer identities on one
network-disabled test process and therefore is neither the production shuffle
administration model nor an anonymous publication airlock. Real deployment must
replace that fixture stage with separately administered shuffle rounds and the
future publication protocol before making an anonymity claim.

## Network prerequisites

The signed topology must name stable UDP endpoints for port 4200, stable
partial-proof endpoints for port 4300 and DKG endpoints for port 4400. The
automatic lifecycle service reserves the immediately following DKG TCP port
(4401 in this example) and uses the same scheme. Its client derives that
address from the signed topology; there is no discovery, redirect, proxy,
retry or fallback address. Production DKG/lifecycle endpoints use HTTPS. The
current partial-proof service is plain HTTP; run it inside an
operator-authenticated tunnel such as WireGuard.
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
  --epoch-chain=/var/lib/nomad/epoch-chain \
  --secrets=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
  --listen=:4200 \
  --cache=/var/lib/nomad/raw \
  --state=/var/lib/nomad/sequence \
  --health=/run/nomad/health.json

nomad-share \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --epoch-chain=/var/lib/nomad/epoch-chain \
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

## Automatic successor lifecycle

Before publishing the N+1 enrollment, every continuing operator creates a new
epoch file. Only the stable Ed25519 identity is retained; X25519 and DKG keys
are replaced. The old and new files coexist until N retires:

```bash
nomad-operator rotate \
  --from-secret=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000001.secrets.json \
  --endpoint=203.0.113.10:4200 \
  --partial-endpoint=https://operator-a.example:4300 \
  --dkg-endpoint=https://operator-a.example:4400 \
  --secret=/var/lib/nomad/ceremony/secrets/epoch-00000000000000000002.secrets.json \
  --enrollment=/var/lib/nomad/ceremony/epoch-2.enrollment.json
```

Every successor epoch requires this rotation. Retries inside one epoch must
reuse that epoch's keys; a transition reusing any earlier epoch's KEX or DKG
key, including after an intervening epoch, is invalid at every descriptor
verifier.

Pre-stage every independently attested retry topology at
`/etc/nomad/rotation/topologies/epoch-N/attempt-AA/topology.json`, using the
zero-padded names emitted by `nomad-lifecycle plan`. Run one controller per
operator; it replaces the standalone `nomad-dkg` process for successor epochs:

```bash
nomad-rotation-controller \
  --chain=/var/lib/nomad/epoch-chain \
  --revocations=/var/lib/nomad/revocations \
  --authority-key=/etc/nomad/authority.pub \
  --network=nomad-live --operator-id=operator-a \
  --topology-dir=/etc/nomad/rotation/topologies \
  --secrets-dir=/var/lib/nomad/ceremony/secrets \
  --listen=:4400 --control-listen=:4401 \
  --state=/var/lib/nomad/rotation/state \
  --share-dir=/var/lib/nomad/rotation/shares \
  --certificate-dir=/var/lib/nomad/rotation/certificates \
  --exchange=/var/lib/nomad/rotation/exchange \
  --signature-journal=/var/lib/nomad/rotation/signature-journal \
  --tls-certificate=/etc/nomad/tls/dkg.crt \
  --tls-private-key=/etc/nomad/tls/dkg.key \
  --prepare-lead=6h --retry-offsets=1h,2h \
  --escalate-after=3h --control-interval=30s
```

The controller holds a process lock across planning and DKG, refuses an
ambiguous interrupted attempt, destroys a failed-attempt share before the next
public attempt, and accepts only the exact attempt currently selected by the
public retry ladder. Retry topologies may change only the fresh session ID and
strictly later DKG start. It publishes local immutable artifacts, performs one
bounded GET per peer on each future UTC-aligned control tick, verifies every
artifact independently, requires the previous approval quorum plus all
incoming activations, and imports the assembled descriptor as READY.

There is deliberately no catch-up activation. If READY is not persisted before
the signed activation boundary, the controller stops and the outgoing epoch
retires. Run the epoch-N and epoch-N+1 node/share units from public
descriptor-derived service-manager timers. Use `Restart=on-failure`: the old
node and share service exit normally at retirement, and unconditional restart
would only loop a retired configuration. The node checks the same chain before
binding its UDP socket and refuses every send at or after its chain-derived
deadline; a verified emergency successor may only move that deadline earlier.

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
