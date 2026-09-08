package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func main() {
	pub, priv, err := mix.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	cells := make([]mix.PlainCell, 8)
	for i := range cells {
		digest := sha256.Sum256([]byte(fmt.Sprintf("cell-%d", i)))
		for j := range cells[i] {
			cells[i][j] = digest[j%len(digest)]
		}
	}
	encrypted, err := mix.Encrypt(pub, cells)
	if err != nil {
		log.Fatal(err)
	}
	mixed, rounds, err := mix.CommitteeMix(pub, encrypted, 2)
	if err != nil {
		log.Fatal(err)
	}
	recovered, err := mix.Decrypt(priv, mixed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("cells=%d rounds=%d recovered=%d plain-bytes-per-cell=%d wire-bytes-per-cell=%d\n",
		len(cells), len(rounds), len(recovered), mix.PlainCellSize, mix.WireCellSize)
}
