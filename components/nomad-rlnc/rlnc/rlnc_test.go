package rlnc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGFInverse(t *testing.T) {
	for i := 1; i < 256; i++ {
		if mul(byte(i), inv(byte(i))) != 1 {
			t.Fatalf("bad inverse for %d", i)
		}
	}
}

func TestSystematicRoundTrip(t *testing.T) {
	data := make([]byte, 8193)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncoder(data, 512)
	if err != nil {
		t.Fatal(err)
	}
	syms := make([]Symbol, enc.K())
	for i := range syms {
		syms[i], err = enc.Systematic(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := Decode(syms, enc.K(), enc.OriginalSize())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round-trip mismatch")
	}
}

func TestRandomCodedRoundTrip(t *testing.T) {
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncoder(data, 256)
	if err != nil {
		t.Fatal(err)
	}
	syms := make([]Symbol, 0, enc.K()*4)
	for attempts := 0; attempts < enc.K()*20; attempts++ {
		s, err := enc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		syms = append(syms, s)
		if len(syms) >= enc.K() {
			got, err := Decode(syms, enc.K(), enc.OriginalSize())
			if err == nil {
				if !bytes.Equal(got, data) {
					t.Fatal("round-trip mismatch")
				}
				return
			}
		}
	}
	t.Fatal("failed to obtain full rank")
}

func TestReEncodePreservesSpan(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog; network coding test")
	enc, err := NewEncoder(data, 16)
	if err != nil {
		t.Fatal(err)
	}
	base := make([]Symbol, enc.K())
	for i := range base {
		base[i], err = enc.Systematic(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	mixed := make([]Symbol, 0, enc.K()*3)
	for i := 0; i < enc.K()*3; i++ {
		s, err := ReEncode(base)
		if err != nil {
			t.Fatal(err)
		}
		mixed = append(mixed, s)
	}
	got, err := Decode(mixed, enc.K(), enc.OriginalSize())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("re-encoded round-trip mismatch")
	}
}

func TestReEncodeRejectsZeroSpan(t *testing.T) {
	_, err := ReEncode([]Symbol{{Coeff: []byte{0, 0}, Data: []byte{0, 0}}})
	if err == nil {
		t.Fatal("expected zero-span error")
	}
}

func TestReEncodeNeverReturnsZeroCoefficientVector(t *testing.T) {
	enc, err := NewEncoder([]byte("non-zero re-encoding test"), 8)
	if err != nil {
		t.Fatal(err)
	}
	base := make([]Symbol, enc.K())
	for i := range base {
		base[i], err = enc.Systematic(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1000; i++ {
		s, err := ReEncode(base)
		if err != nil {
			t.Fatal(err)
		}
		if !anyNonZero(s.Coeff) {
			t.Fatal("re-encoder emitted zero coefficient vector")
		}
	}
}

func TestDecodeRejectsRankDeficientSet(t *testing.T) {
	enc, err := NewEncoder([]byte("rank deficiency"), 4)
	if err != nil {
		t.Fatal(err)
	}
	one, err := enc.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	syms := make([]Symbol, enc.K())
	for i := range syms {
		syms[i] = one
	}
	if _, err := Decode(syms, enc.K(), enc.OriginalSize()); err == nil {
		t.Fatal("expected rank-deficiency error")
	}
}
