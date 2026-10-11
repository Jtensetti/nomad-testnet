# nomad-rlnc

A dependency-free Go implementation of random linear network coding over GF(2^8), used by the Nomad experiments.

## Implemented

- fixed-size source symbols,
- systematic and random coded symbols,
- in-network linear re-encoding,
- incremental reduced-row-echelon decoding,
- rank-deficiency detection,
- contradiction detection for dependent symbols,
- self-describing 504-byte generation packets with randomized padding,
- fixed packet metadata preserved during in-network re-encoding,
- rejection of useless zero-span re-encoding.

The implementation is intentionally small and readable. It is not tuned for high-throughput networking and has not received independent review.

## Security boundary

RLNC is **not encryption or authentication**. A malicious peer can inject an
innovative polluted symbol that only the reconstructed object's commitment will
detect. Packet generation identifiers and dimensions are public routing data,
not proof of identity. Replay handling and pollution-resistant coding remain
outside this package.

The 504-byte packet is sized to fit the cleartext capacity of the reference
verifiable-mix cell. Encryption and the mix layer expand it to the protocol's
1200-byte wire cell.

```bash
go test -race ./...
go vet ./...
```
