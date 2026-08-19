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
