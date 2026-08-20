# Multi-operator deployment

This is the production-shaped deployment contract for the live binaries.
Docker Compose is only a one-host acceptance profile. A real committee places
each operator on separately administered infrastructure.

## Security boundary

Each operator receives only:

- the authority-signed topology and pinned authority public key;
- the activated `epoch-descriptor.json` and its own persistent epoch-chain;
- its own operator secret;
- its own DKG state and threshold share;
- its own raw cache, sequence state and partial output.

No operator receives another operator's private material. A coordinator may
collect public enrollments, attestations, topology documents, DKG certificates,
epoch descriptors and erasure statements. It must never receive an operator's
private keys or threshold share.

## 1. Enrollment and topology

Each administrator creates its identity locally:

```bash
nomad-operator init \
  --id=operator-a \
  --endpoint=203.0.113.10:4200 \
  --partial-endpoint=https://operator-a.example:4300 \
  --dkg-endpoint=https://operator-a.example:4400 \
  --secret=/etc/nomad/operator-secret.json \
  --enrollment=operator-a.enrollment.json
```

The coordinator builds a draft from public enrollments. Every operator reviews
and attests the exact draft. The authority can finalize only the attested
membership:

```bash
nomad-operator attest \
  --secret=/etc/nomad/operator-secret.json \
  --draft=topology-draft.json \
  --out=operator-a.attestation.json

nomad-operator verify \
  --secret=/etc/nomad/operator-secret.json \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub
```

Compare the topology digest out of band before starting the epoch.

## 2. Distributed DKG

Run one DKG process per operator before the signed DKG start boundary:

```bash
install -d -m 0700 /var/lib/nomad/dkg /run/nomad
nomad-dkg \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --secrets=/etc/nomad/operator-secret.json \
  --listen=:4400 \
  --state=/var/lib/nomad/dkg \
  --share-out=/run/nomad/threshold-share.json \
  --certificate-out=/etc/nomad/dkg-certificate.json \
  --tls-certificate=/etc/nomad/tls/dkg.crt \
  --tls-private-key=/etc/nomad/tls/dkg.key
```

Every configured operator must land in QUAL and attest the same DKG manifest.
An interrupted ceremony is not resumed. Wait for the next public retry offset
and start a fresh signed session.

## 3. Epoch activation is separate from topology validity

A signed topology is not by itself permission to serve threshold work. The
epoch descriptor binds:

- the exact signed topology;
- the exact all-operator-certified DKG certificate;
- a transition type (`genesis`, `scheduled`, or `emergency`);
- public `activate_at` and `retire_at` boundaries;
- required previous-epoch approvals for a successor;
- activation signatures from the new epoch's entire membership.

Each operator keeps a local writable chain, for example:

```text
/var/lib/nomad/epoch-chain/
```

Do not share this directory between operators. Distribute the public epoch
descriptor to every operator. A service may import the same descriptor again;
identical re-import is idempotent. Conflicting valid descriptors halt the chain.

## 4. Runtime processes

The network process and threshold-share process are separate security domains.
Use the current release's fixed-rate network sender boundary; do not insert an
autoscaler, proxy, demand-driven retry layer or load balancer in front of the
fixed-cadence path.

The share service must be started with the verified epoch chain:

```bash
nomad-share \
  --topology=/etc/nomad/topology.json \
  --authority-key=/etc/nomad/authority.pub \
  --epoch-descriptor=/etc/nomad/epoch-descriptor.json \
  --epoch-chain=/var/lib/nomad/epoch-chain \
  --descriptor=/etc/nomad/descriptor.json \
  --share=/run/nomad/threshold-share.json \
  --cache=/var/lib/nomad/raw \
  --out=/var/lib/nomad/partials \
  --interval=1s \
  --listen=:4300
```

`nomad-share` fails before opening its HTTP listener unless the exact topology
epoch is `ACTIVE` in the chain. Before every partial-decryption attempt and
before every HTTP response containing an already-generated partial, it refreshes
the persisted chain. A scheduled retirement, emergency successor, or persisted
halt therefore fails closed without a service restart.

Run each process as an unprivileged dedicated user with a read-only root
filesystem, dropped capabilities, private temporary directory and explicit
writable paths only for the state it owns.

## 5. Network prerequisites

The topology names stable public endpoints. The current proof service is plain
HTTP internally; put it inside an operator-authenticated tunnel such as
WireGuard when crossing untrusted networks. The Nomad cell authentication is
still mandatory because it binds sender, receiver, topology, epoch, sequence
and batch context independently of the tunnel.

Do not change cadence, routing or retries based on cache demand, publication
state, search activity or any other private state.

## 6. Reader side

The fetch plan is public and authority-signed. The materializer must have no
network capability at the OS/container boundary:

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

Mount or sync the verified output into the Nomad Browser cache on a public
schedule. Browser search must never trigger a refresh.

## 7. Rotation and emergency retirement

Prepare the next epoch only from the public rotation schedule. A scheduled
successor activates exactly at the predecessor's retirement boundary. An
emergency successor may activate earlier and immediately makes its predecessor
`RETIRED` in chain state.

The share service must use the same chain that receives successor descriptors.
Do not decide retirement from topology `NotAfter`: the topology envelope is not
the epoch serving window.

After retirement, erase the epoch-private share and DKG secret state:

```bash
nomad-operator erase \
  --secret=/etc/nomad/operator-secret.json \
  --chain=/var/lib/nomad/epoch-chain \
  --epoch=N \
  --authority-key=/etc/nomad/authority.pub \
  --network=nomad-live \
  --filesystem=ext4 \
  --out=/var/lib/nomad/evidence/erasure-N.json \
  /run/nomad/threshold-share-N.json \
  /var/lib/nomad/dkg-N/private-state.json
```

The command refuses `READY` or `ACTIVE` epochs and refuses to erase the chain,
operator identity, authority key or its own evidence output. It validates the
operator identity before destroying files and fsyncs affected directories
before returning a signed erasure statement.

The erasure claim is intentionally limited. Overwrite/unlink is not a physical
media guarantee on flash, journaling or copy-on-write filesystems and is defeated
by snapshots/backups. Use full-disk encryption and do not back up epoch-private
material.

## 8. Admission evidence

Before admitting a committee/release, record at least:

- source commit and binary/image digest;
- topology digest and DKG certificate digest;
- activated epoch descriptor digest;
- operator sign-offs;
- unit/race/vet results;
- Compose acceptance evidence;
- packet-capture evidence;
- WAN/fault-campaign evidence;
- erasure statements for retired epochs.

A three-host deployment controlled by one administrator is useful WAN evidence,
but it is **not** evidence of independent operator governance.
