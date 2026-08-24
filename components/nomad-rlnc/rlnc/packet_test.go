package rlnc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestPacketHasFixedSizeAndRoundTrips(t *testing.T) {
	enc, err := NewEncoder([]byte("fixed-size RLNC packet carried by a Nomad mix cell"), 32)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := enc.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	var generation GenerationID
	copy(generation[:], []byte("generation-one"))
	packet, err := NewPacket(generation, enc.K(), enc.SymbolSize(), enc.OriginalSize(), symbol)
	if err != nil {
		t.Fatal(err)
	}
	wireA, err := packet.MarshalBinaryFrom(bytes.NewReader(bytes.Repeat([]byte{0xaa}, PacketSize)))
	if err != nil {
		t.Fatal(err)
	}
	wireB, err := packet.MarshalBinaryFrom(bytes.NewReader(bytes.Repeat([]byte{0xbb}, PacketSize)))
	if err != nil {
		t.Fatal(err)
	}
	if len(wireA) != PacketSize || len(wireB) != PacketSize {
		t.Fatalf("wire sizes = %d and %d", len(wireA), len(wireB))
	}
	if bytes.Equal(wireA, wireB) {
		t.Fatal("random padding did not replace the packet representation")
	}
	got, err := ParsePacket(wireA)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != packet.Generation || got.K != packet.K ||
		got.SymbolSize != packet.SymbolSize || got.OriginalSize != packet.OriginalSize ||
		!bytes.Equal(got.Symbol.Coeff, packet.Symbol.Coeff) || !bytes.Equal(got.Symbol.Data, packet.Symbol.Data) {
		t.Fatal("parsed packet differs from input")
	}
}

func TestPacketRejectsMalformedDimensions(t *testing.T) {
	if _, err := ParsePacket(make([]byte, PacketSize-1)); err == nil {
		t.Fatal("expected fixed-size error")
	}
	bad := make([]byte, PacketSize)
	copy(bad[:4], packetMagic[:])
	bad[20], bad[21] = 0xff, 0xff
	bad[22], bad[23] = 0xff, 0xff
	if _, err := ParsePacket(bad); err == nil {
		t.Fatal("expected dimensions error")
	}
}

func TestIncrementalDecoderIgnoresDuplicatesAndDetectsContradiction(t *testing.T) {
	data := make([]byte, 900)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncoder(data, 100)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewDecoder(enc.K(), enc.SymbolSize(), enc.OriginalSize())
	if err != nil {
		t.Fatal(err)
	}
	first, err := enc.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	innovative, err := decoder.Add(first)
	if err != nil || !innovative {
		t.Fatalf("first add = %v, %v", innovative, err)
	}
	innovative, err = decoder.Add(first)
	if err != nil || innovative {
		t.Fatalf("duplicate add = %v, %v", innovative, err)
	}
	contradiction := Symbol{
		Coeff: append([]byte(nil), first.Coeff...),
		Data:  append([]byte(nil), first.Data...),
	}
	contradiction.Data[0] ^= 1
	if _, err := decoder.Add(contradiction); !errors.Is(err, ErrInconsistentSymbol) {
		t.Fatalf("contradiction error = %v", err)
	}

	for i := 1; i < enc.K(); i++ {
		symbol, err := enc.Systematic(i)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Add(symbol); err != nil {
			t.Fatal(err)
		}
	}
	got, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("incremental reconstruction mismatch")
	}
}

func TestReEncodePacketsPreservesGeneration(t *testing.T) {
	data := []byte("store, re-code, and forward without reconstructing the object")
	enc, err := NewEncoder(data, 16)
	if err != nil {
		t.Fatal(err)
	}
	var generation GenerationID
	copy(generation[:], []byte("generation-two"))
	packets := make([]Packet, enc.K())
	for i := range packets {
		symbol, err := enc.Systematic(i)
		if err != nil {
			t.Fatal(err)
		}
		packets[i], err = NewPacket(generation, enc.K(), enc.SymbolSize(), enc.OriginalSize(), symbol)
		if err != nil {
			t.Fatal(err)
		}
	}
	mixed, err := ReEncodePackets(packets)
	if err != nil {
		t.Fatal(err)
	}
	if mixed.Generation != generation || !anyNonZero(mixed.Symbol.Coeff) {
		t.Fatal("re-encoded packet lost generation metadata or rank potential")
	}
}
