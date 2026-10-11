package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
)

func main() {
	epochs := flag.Int("epochs", 1000, "number of accounting epochs")
	cells := flag.Int("cells", 16, "cells per epoch")
	epoch := flag.Duration("epoch", 100*time.Millisecond, "epoch duration")
	flag.Parse()

	cfg := fabric.Config{Epoch: *epoch, CellsPerEpoch: *cells}
	trace, err := fabric.EpochTrace(cfg, *epochs)
	if err != nil {
		log.Fatal(err)
	}

	w := csv.NewWriter(os.Stdout)
	if err := w.Write([]string{"epoch", "bytes", "cells", "cell_interval_ns"}); err != nil {
		log.Fatal(err)
	}
	for i, n := range trace {
		if err := w.Write([]string{strconv.Itoa(i), strconv.Itoa(n), strconv.Itoa(*cells), strconv.FormatInt(cfg.CellInterval().Nanoseconds(), 10)}); err != nil {
			log.Fatal(err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "planned %d epochs; one cell every %s\n", len(trace), cfg.CellInterval())
}
