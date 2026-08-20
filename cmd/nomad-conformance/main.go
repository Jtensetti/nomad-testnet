// Command nomad-conformance emits or verifies the golden-vector corpus for
// the frozen wire protocol.
//
// Emitting and verifying are the same code path in opposite directions, so a
// corpus committed to the repository cannot drift from the encoders that
// produced it without CI noticing.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/Jtensetti/nomad-testnet/live/conformance"
)

func main() {
	output := flag.String("out", "", "write the corpus to this path")
	check := flag.String("check", "", "verify that this path matches the generated corpus")
	flag.Parse()

	vectors, err := conformance.All()
	if err != nil {
		fail(err)
	}
	corpus, err := conformance.Build(vectors)
	if err != nil {
		fail(err)
	}
	encoded, err := conformance.Encode(corpus)
	if err != nil {
		fail(err)
	}

	switch {
	case *check != "":
		committed, err := os.ReadFile(*check)
		if err != nil {
			fail(err)
		}
		if !bytes.Equal(committed, encoded) {
			fmt.Fprintf(os.Stderr,
				"%s does not match the encoders that produced it.\n"+
					"Regenerate with: go run ./cmd/nomad-conformance -out %s\n"+
					"If the change is intended, it is a wire-protocol change and needs a "+
					"specification version bump.\n", *check, *check)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "corpus matches: %d vectors, digest %s\n",
			len(corpus.Vectors), corpus.Digest)
	case *output != "":
		if err := os.WriteFile(*output, encoded, 0o644); err != nil {
			fail(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d vectors, digest %s\n", len(corpus.Vectors), corpus.Digest)
	default:
		if _, err := os.Stdout.Write(encoded); err != nil {
			fail(err)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "conformance:", err)
	os.Exit(1)
}
