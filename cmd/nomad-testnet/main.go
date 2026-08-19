package main

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/Jtensetti/nomad-testnet/testnet"
)

func main() {
	content := []byte("Nomad testnet: exact content survives RLNC coding, permutation and local verified reconstruction.")
	r, err := testnet.Run(context.Background(), content, "distributed privacy network coding", "privacy network reconstruction")
	if err != nil {
		panic(err)
	}
	fmt.Printf("hash=%s\n", hex.EncodeToString(r.ContentHash[:]))
	fmt.Printf("query_basin=%016x object_basin=%016x distance=%d\n", r.QueryBasin, r.ObjectBasin, r.HammingDistance)
	fmt.Printf("symbols=%d mixed=%d reconstructed=%v\n", r.SymbolsGenerated, r.MixedBatch, r.Reconstructed)
	fmt.Printf("reader_trace_identical=%v bytes_per_epoch=%d\n", r.ReaderTraceIdentical, r.ConstantBytesPerEpoch)
}
