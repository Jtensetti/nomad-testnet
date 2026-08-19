# Nomad live testnet

Nomad's reader-side reference deployment. It runs three separately keyed
operator processes, emits authenticated 1200-byte UDP cells on a signed fixed
cadence, stores only valid encrypted work, obtains public threshold partials on
an independent fixed schedule, and materializes a signed object for Nomad
Browser without any query-triggered network action.

This repository now contains two harnesses:

- `go run ./cmd/nomad-testnet` is the deterministic protocol integration test.
- `deploy/compose.yaml` is the live fabric-to-cache deployment and release gate.

## Run the live network

Docker Compose supplies the reproducible single-administrator deployment:

```bash
./scripts/compose-e2e.sh
```

The script builds the locked-down image, bootstraps a signed epoch, starts three
UDP nodes, three threshold-share servers, one public-cadence partial fetcher and
one networkless materializer. It waits for the exact verified browser object,
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
live path uses authenticated Pedersen DKG output, 2-of-3 proved threshold
decryption and one verified Neff shuffle per operator. Its one-host Compose
profile demonstrates process, key and cache separation; it cannot prove that
three organizations independently administer the operators. The exact release
gate and remaining external production requirements are in `LIVE_DOD.md`.

The lexical hashing embedder is an offline development baseline, not a semantic
model. A real embedding model must remain local.

```bash
go test -race ./...
go vet ./...
./scripts/compose-e2e.sh
```
