# Nomad live testnet

Nomad's reader-side reference deployment. It runs three separately keyed
operator processes, emits authenticated 1200-byte UDP cells on a signed fixed
cadence, stores only valid encrypted work, obtains public threshold partials on
an independent fixed schedule, and materializes a signed object for Nomad
Browser without any query-triggered network action. The epoch committee is
created by three networked Kyber Pedersen DKG processes; the live descriptor is
accepted only with the resulting all-operator activation certificate.

This repository now contains two harnesses:

- `go run ./cmd/nomad-testnet` is the deterministic protocol integration test.
- `deploy/compose.yaml` is the live fabric-to-cache deployment and release gate.

It also ships `nomad-operator` and `nomad-topology` for an offline
multi-administrator topology ceremony. Each operator generates separate
Ed25519, X25519 and DKG secrets, publishes only a self-signed enrollment, signs
the same complete topology draft and locally derives directed hop keys. The
authority sees no operator private key and distributes no pairwise MAC or
threshold secret.

```bash
nomad-operator init --id=operator-a --endpoint=host-a:4200 \
  --partial-endpoint=https://host-a:4300 \
  --dkg-endpoint=https://host-a:4400 \
  --secret=secrets/epoch-00000000000000000001.secrets.json \
  --enrollment=epoch-1.enrollment.json

nomad-topology draft --network-id=nomad-live --epoch=1 \
  --dkg-start-delay=10m --dkg-phase-duration=2m --dkg-threshold=2 \
  --enrollments=a.json,b.json,c.json --out=topology-draft.json

nomad-operator attest \
  --secret=secrets/epoch-00000000000000000001.secrets.json \
  --draft=topology-draft.json --out=operator-a.attestation.json
```

Normal post-genesis rotation is automatic. `nomad-rotation-controller` runs
the public retry ladder, re-verifies a completed DKG, exchanges immutable
certificate/approval/activation artifacts over a read-only lifecycle service,
assembles one descriptor and imports it as READY before the signed activation
boundary. The lifecycle service is the signed DKG endpoint's TCP port plus
one (for example `https://operator-a.example:4400` implies
`https://operator-a.example:4401`). It has GET endpoints only, follows no
redirect, uses no proxy, performs one request per operator per aligned control
round and has no fallback or catch-up path. Retry attempts may change only the
fresh DKG session and later public start time; membership and every other
public field remain fixed.

KEX and DKG identities are private to one epoch. Before staging N+1, each
continuing operator runs `nomad-operator rotate` from its N secret into a new
`epoch-%020d.secrets.json` file. The stable Ed25519 operator identity is the
only retained key. Descriptor validation rejects any N+1 topology that reuses
any earlier epoch's KEX or DKG public key, even after an intervening epoch or
under another operator ID, and the
controller loads the exact file for each epoch from `--secrets-dir`. A retained
canonical live DKG deal is an adversarial test fixture: the retired identity
decrypts its addressed ciphertext as a control, while the complete later-epoch
secret file cannot decrypt it or join the old DKG membership.

If the descriptor is not READY by `activate_at`, the outgoing epoch retires
and the controller refuses a late import that would become ACTIVE
immediately. This availability loss is intentional. See
`deploy/MULTI_OPERATOR.md` for the complete command and storage layout; the
manual `nomad-lifecycle descriptor-*` commands remain inspection/recovery
tools, not the normal rotation transport.

After collecting exactly one attestation from every member, the authority uses
`nomad-topology finalize`; every operator runs `nomad-operator verify` before
starting its node. Every operator then runs `nomad-dkg` before the signed start
time. The command exchanges only signed public ceremony traffic and writes one
operator-local threshold share plus the identical all-operator-certified public
committee certificate. The complete runbook is in `deploy/MULTI_OPERATOR.md`.

## Run the live network

Docker Compose supplies the reproducible single-administrator deployment:

```bash
./scripts/compose-e2e.sh
```

The script builds the locked-down image, bootstraps a signed epoch, runs three
TLS DKG processes, compares their certified public result, starts three UDP
nodes using three distinct distributed shares, three threshold-share servers,
one public-cadence partial fetcher and one networkless materializer. It waits for
the exact verified browser object,
checks every process and container boundary, records packet/process/health
evidence from the dedicated fabric bridge, and rejects a capture whose cells
are not 1200 bytes or whose cadence/topology is wrong. Bootstrap and the
materializer run with Docker networking disabled.

To feed a locally installed Nomad Browser directly, set its existing object
cache as the materializer destination before starting Compose:

```bash
export NOMAD_VERIFIED_CACHE="$HOME/Library/Containers/io.nomad.browser/Data/Library/Application Support/NomadBrowser/objects"
docker compose -f deploy/compose.yaml up --build
```

Docker Desktop must be allowed to mount that directory. The browser performs
only local cache reads and signature verification; it has no network
entitlement. See `deploy/MULTI_OPERATOR.md` for deployment across independently
controlled hosts.

## What the deterministic harness does

1. Creates canonical content and a signed object manifest.
2. Produces fixed 504-byte RLNC generation packets over GF(2^8).
3. Encrypts them and performs two independently randomized, verified Neff
   sequence shuffles through Kyber v4.
4. Serializes each ciphertext as an exact 1200-byte wire cell.
5. Emits 16 cells at a 20 ms cadence through the fixed-rate scheduler to four
   UDP loopback peers selected by the public Selection Firewall plan.
6. Captures real datagrams on the receiver side and checks size, destination,
   count, cadence and public-plan conformance.
7. Runs the same stream in an idle reader world and a concurrent private-query
   world, then compares normalized observer traces.
8. Parses, decrypts and RLNC-decodes only the captured cells, then verifies the
   exact SHA-256 commitment and Ed25519 signatures locally.

The workflow also inspects Go's dependency graph: network-domain modules may
not import semantic selection/reconstruction modules, and private-domain
modules may not import the fabric, planner or mix.

## Reproducible private-module composition

The component repositories are private, so a repository-scoped Actions token
cannot check them out. `components/` is a generated source snapshot used only
for integration CI. `COMPONENTS.lock` records the exact source commit for every
snapshot. Component changes must update both the snapshot and lock entry.

## Live security status

**Live testnet software, not yet an audited production anonymity network.** The
live path uses networked authenticated Pedersen DKG output, unanimous committee
activation, 2-of-3 proved threshold decryption and one verified Neff shuffle per
operator. Its one-host Compose profile demonstrates process, key and cache
separation; it cannot prove that three organizations independently administer
the operators. The exact release gate and remaining external production
requirements are in `LIVE_DOD.md` and `DKG_DOD.md`.

The lexical hashing embedder is an offline development baseline, not a semantic
model. A real embedding model must remain local.

```bash
go test -race ./...
go vet ./...
./scripts/compose-e2e.sh
```
