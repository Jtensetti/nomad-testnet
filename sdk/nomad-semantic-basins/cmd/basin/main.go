package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/Jtensetti/nomad-semantic-basins/basin"
)

func main() {
	text := flag.String("text", "", "text to basinize")
	flag.Parse()
	if *text == "" {
		log.Fatal("-text is required")
	}
	e := basin.LexicalHashEmbedder{Dims: 512}
	v, err := e.Embed(context.Background(), *text)
	if err != nil {
		log.Fatal(err)
	}
	id, err := (basin.Quantizer{}).Basin(v)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%016x\n", id)
}
