# Multi-operator deployment

The live binaries are deliberately deployable without Docker Compose. Compose
is the reproducible one-host acceptance profile; a real committee places each
operator on separately administered infrastructure.

## Trust and ownership split

Every operator receives only:

- the authority-signed `topology.json` and authority public key;
- its own `node-secrets.json`, containing only its Ed25519 identity and
  epoch-scoped X25519 and dedicated DKG private keys;
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
  --dkg-endpoint=https://operator-a.example:4400 \
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

Before the signed DKG start time, every administrator starts exactly one local
ceremony process. The state directory must be empty and private; an interrupted
session is deliberately non-resumable and requires a newly attested topology
with a fresh session ID:

```bash
install -d -m 0700 /var/lib/nomad/dkg /run/nomad
nomad-dkg \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --secrets=/var/lib/nomad/ceremony/node-secrets.json \
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

## Supervising a node

A Nomad node does not stop when a local condition breaks its emission path.
A full disk, an exhausted socket buffer or a route that went away costs the
cell it interrupted and the schedule carries on, because a node that stops is
the loudest event a passive observer can see and those causes are local. The
consequence for you is that **"the process is running" no longer means the
node is emitting**. It can be up, on cadence, and dropping every cell.

So supervise what it emitted, not whether it is alive:

```bash
nomad-node --check-health=/run/nomad/health.json --max-silence=30s
```

It exits non-zero when the health file is stale (the node stopped reporting),
when the node has emitted nothing since it started, or when it last emitted
longer ago than `--max-silence`. It fails closed on a missing, empty or
unparseable file. Set `--max-silence` from your cell interval; anything from
a few hundred intervals upward distinguishes a stall from jitter.

As a systemd unit, that is a watchdog rather than a readiness probe:

```ini
# nomad-node-health.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/nomad-node --check-health=/run/nomad/health.json --max-silence=30s
ExecStopPost=/bin/sh -c '[ "$EXIT_STATUS" = 0 ] || systemctl restart nomad-node'

# nomad-node-health.timer
[Timer]
OnUnitActiveSec=30s
```

**Put the health file and the state directories on different filesystems, and
watch both.** The runbook below writes `--cache` and `--state` under
`/var/lib/nomad` and `--health` under `/run`, which is deliberate: a full
`/var/lib/nomad` then drops every cell while the health file keeps updating,
so the staleness check alone would not fire. `--check-health` catches it
through `last_sent_at`, which is why the check reads what was emitted rather
than only when the file was written.

**Alert on `send_dropped` in the health file.** On a healthy node it is zero.
A rising count is a local condition -- disk, socket buffers, a firewall rule
-- that is costing cells. A node that reaches a few thousand consecutive drops
stops on its own and says why, but that is the backstop, not the alarm.

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
