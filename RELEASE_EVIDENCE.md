# Live testnet release evidence

Baseline commit: `9b246eff2228237cc0ab2950c7c85d6e2bb15330`

GitHub Actions run: <https://github.com/Jtensetti/nomad-testnet/actions/runs/32288962907>

Artifact: `live-fabric-evidence`, API artifact ID `9378791978`, archive digest
`sha256:8d108d3c045831b009b56811aac6b63d9cd78064545b521fc80462c67521cb9c`.

## Wire evidence

The dedicated Docker fabric bridge recorded 102 datagrams from each of three
distinct sources. Every UDP payload was 1200 bytes and every source used one
destination from the signed ring plan.

| Sender | Cells | Mean | Median | Minimum | Maximum |
|---|---:|---:|---:|---:|---:|
| `172.18.0.2:4200` | 102 | 49.993 ms | 49.976 ms | 46.516 ms | 53.398 ms |
| `172.18.0.3:4200` | 102 | 49.994 ms | 49.979 ms | 42.292 ms | 56.923 ms |
| `172.18.0.4:4200` | 102 | 49.993 ms | 49.965 ms | 48.883 ms | 51.748 ms |

Capture SHA-256:
`630286a8740c6c39df7e9c580f5d4721901b47b0636d9b2c5cc96baaa80bb9e6`.

## Process and object evidence

- All eight long-running services were alive under UID/GID 65532 with a
  read-only root filesystem, all Linux capabilities dropped, no-new-privileges
  and a 128-PID ceiling.
- Bootstrap completed with exit code zero and no network namespace.
- The materializer had no network namespace.
- All three operators reported the same topology digest and zero wrong-size,
  unknown-peer, authentication, replay and cache-rejection counters.
- The browser object was materialized as
  `1f5863a9defd07015bcf20956b50369adc6ad62c8464e9da114a56c42a1d343c.nomadobject`.
- Materialized envelope SHA-256:
  `e3d49edcf2c3840e1be80db008116367f2e35c2ff5d582d63ee7ddd68fe8b965`.

The release workflow repeats these gates on the release commit and attaches
the resulting evidence archive alongside the operator binaries and checksums.

## Independent operator ceremony and local hop-key derivation

Hardening commit: `2f3da0c47bf0586b10a5aa58f7b6c448b4540a9a`

GitHub Actions run: <https://github.com/Jtensetti/nomad-testnet/actions/runs/32293112716>

The run passed formatting/module checks, Selection Firewall dependency checks,
the full race suite, vet, the offline three-operator ceremony and the live
Compose/pcap gate. Its immutable artifacts are:

- `operator-ceremony-evidence`, API artifact ID `9380245643`, archive digest
  `sha256:b23a90b9f59a118e42b0b3f0ef57368b5b870050f3533bcb5d66f1a63251dd8a`;
- `live-fabric-evidence`, API artifact ID `9380298465`, archive digest
  `sha256:54a9f50cb666032eebdeadde46141d339ec7b4e184ea3dba4216164fe9720222`.

The ceremony used three independently generated operator secret files and
self-signed public enrollments. Every operator attested draft digest
`f2b4610f59034802d256a8830619d64414e1fa494fbd937f701cd4506b3eb68a`,
then independently verified topology digest
`8cab13bbac214f405ff6b8f4a6380e454ded714d6308a1b2489d5042b118f6fe`.
Each derived exactly one inbound and one outbound directed hop key. The secret
schema contains an Ed25519 identity and an X25519 epoch key, and the live gate
rejects any reintroduction of serialized `inbound_keys` or `outbound_keys`.

This proves software-level private-key separation and ceremony agreement. It
does not prove that three independent legal administrators performed the
ceremony or operated the measured containers.
