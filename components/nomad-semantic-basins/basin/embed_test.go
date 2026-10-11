package basin

import (
	"context"
	"crypto/sha256"
	"math"
	"testing"
)

func TestLexicalHashEmbedderDeterministic(t *testing.T) {
	e := LexicalHashEmbedder{Dims: 256}
	a, err := e.Embed(context.Background(), "Iran military systems")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Embed(context.Background(), "Iran military systems")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatal("length mismatch")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d", i)
		}
	}
}

func TestHyperplaneQuantizerIdenticalAndOppositeVectors(t *testing.T) {
	q := Quantizer{Seed: sha256.Sum256([]byte("test-seed"))}
	v := []float32{0.3, -0.7, 0.2, 0.6}
	opposite := []float32{-0.3, 0.7, -0.2, -0.6}
	a, err := q.Basin(v)
	if err != nil {
		t.Fatal(err)
	}
	again, err := q.Basin(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Basin(opposite)
	if err != nil {
		t.Fatal(err)
	}
	if a != again {
		t.Fatal("same vector and seed produced different basin")
	}
	if got := HammingDistance(a, b); got != 64 {
		t.Fatalf("opposite vectors differed in %d bits, want 64", got)
	}
}

func TestHyperplaneDistanceTracksAngularDistanceAcrossSeeds(t *testing.T) {
	nearA := []float32{1, 0, 0, 0}
	nearB := []float32{0.98, 0.2, 0, 0}
	orthogonal := []float32{0, 1, 0, 0}
	var nearTotal, orthogonalTotal int
	const seeds = 64
	for i := 0; i < seeds; i++ {
		seed := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		q := Quantizer{Seed: seed}
		a, err := q.Basin(nearA)
		if err != nil {
			t.Fatal(err)
		}
		b, err := q.Basin(nearB)
		if err != nil {
			t.Fatal(err)
		}
		c, err := q.Basin(orthogonal)
		if err != nil {
			t.Fatal(err)
		}
		nearTotal += HammingDistance(a, b)
		orthogonalTotal += HammingDistance(a, c)
	}
	if nearTotal >= orthogonalTotal/2 {
		t.Fatalf("nearby vectors were not materially closer: near=%d orthogonal=%d", nearTotal, orthogonalTotal)
	}
}

func TestQuantizerRejectsNonFiniteVector(t *testing.T) {
	if _, err := (Quantizer{}).Basin([]float32{1, float32(math.NaN())}); err == nil {
		t.Fatal("expected NaN to be rejected")
	}
}

func TestEmbeddersRejectOversizedInputsAndDimensions(t *testing.T) {
	if _, err := (LexicalHashEmbedder{Dims: HardMaxEmbeddingDims + 1}).Embed(context.Background(), "query"); err == nil {
		t.Fatal("lexical embedder accepted excessive dimensions")
	}
	if _, err := (LexicalHashEmbedder{Dims: 8, MaxInputBytes: 4}).Embed(context.Background(), "private query"); err == nil {
		t.Fatal("lexical embedder accepted oversized input")
	}
	// The loopback embedder honours the same bounds through the exported
	// BoundedInt; its half of this test lives with it, in basin/loopback.
}
