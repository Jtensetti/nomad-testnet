package conformance

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// A corpus that is not reproducible is not a conformance corpus: a second
// implementation cannot check itself against a moving target, and CI cannot
// diff it. Every vector must therefore come out byte-identical on every run.
func TestCorpusIsReproducible(t *testing.T) {
	first, err := All()
	if err != nil {
		t.Fatal(err)
	}
	second, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("vector counts differ: %d vs %d", len(first), len(second))
	}
	for index := range first {
		if !reflect.DeepEqual(first[index], second[index]) {
			t.Errorf("vector %q is not reproducible across runs", first[index].Name)
		}
	}

	left, err := Build(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Build(second)
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest != right.Digest {
		t.Errorf("corpus digest is not stable: %s vs %s", left.Digest, right.Digest)
	}
	encodedLeft, err := Encode(left)
	if err != nil {
		t.Fatal(err)
	}
	encodedRight, err := Encode(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodedLeft, encodedRight) {
		t.Error("the encoded corpus differs between runs")
	}
}

// Every vector must carry usable bytes and a digest over exactly those bytes.
func TestEveryVectorIsWellFormed(t *testing.T) {
	vectors, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("the corpus is empty")
	}
	for _, vector := range vectors {
		if vector.Message == "" || vector.Name == "" || vector.Description == "" {
			t.Errorf("vector %q is missing identifying fields", vector.Name)
		}
		raw, err := hex.DecodeString(vector.Bytes)
		if err != nil {
			t.Errorf("vector %q has unparsable bytes: %v", vector.Name, err)
			continue
		}
		if len(raw) != vector.Length {
			t.Errorf("vector %q claims %d bytes and carries %d", vector.Name, vector.Length, len(raw))
		}
		rebuilt := NewVector(vector.Message, vector.Name, vector.Description, raw, vector.Fields)
		if rebuilt.Digest != vector.Digest {
			t.Errorf("vector %q digest does not cover its bytes", vector.Name)
		}
	}
}

func TestBuildRejectsDuplicateVectors(t *testing.T) {
	one := NewVector("m", "n", "d", []byte{1}, nil)
	if _, err := Build([]Vector{one, one}); err == nil {
		t.Error("Build accepted a duplicate vector name")
	}
}

// Deterministic helpers must be deterministic, since every vector rests on
// them.
func TestDeterministicHelpersAreStable(t *testing.T) {
	if !bytes.Equal(DeterministicBytes("x", 100), DeterministicBytes("x", 100)) {
		t.Error("DeterministicBytes is not stable")
	}
	if bytes.Equal(DeterministicBytes("x", 32), DeterministicBytes("y", 32)) {
		t.Error("different labels produced the same bytes")
	}
	if len(DeterministicBytes("x", 37)) != 37 {
		t.Error("DeterministicBytes ignored its length")
	}
	if !bytes.Equal(DeterministicKey("a"), DeterministicKey("a")) {
		t.Error("DeterministicKey is not stable")
	}
	if bytes.Equal(DeterministicKey("a"), DeterministicKey("b")) {
		t.Error("different labels produced the same key")
	}
}
