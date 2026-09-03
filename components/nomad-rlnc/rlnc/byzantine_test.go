package rlnc

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Byzantine inputs, and the guards that refuse them.
//
// Every refusal below already worked when this file was written. What did not
// exist was anything holding them: mutating each guard in turn -- neutralising
// the refusal and running the suite -- left eleven of fifteen green. The
// guards are load-bearing at the boundary, measured by feeding each
// adversarial input through the public API before writing a line of this; what
// was missing is the test that fails when one is deleted.
//
// That distinction matters for PROD-12, which is MET. Nothing here changes the
// implementation's behaviour, and nothing here should be read as having found
// it wrong. What it changes is whether a future edit can quietly remove a
// Byzantine defence.
//
// One item on the plan's list is deliberately absent: that an attack must not
// produce private-state-dependent repair traffic. This package has no network
// and cannot emit anything, so the property does not live here -- it lives in
// the node's fixed cadence and fair relay queue, where the two-world campaigns
// measure it.

const (
	testK          = 4
	testSymbolSize = 8
	testOriginal   = 32
)

func testSources(t *testing.T) [][]byte {
	t.Helper()
	sources := make([][]byte, testK)
	for index := range sources {
		sources[index] = make([]byte, testSymbolSize)
		sources[index][0] = byte(index + 1)
	}
	return sources
}

func zeroSymbol() Symbol {
	return Symbol{Coeff: make([]byte, testK), Data: make([]byte, testSymbolSize)}
}

func unitSymbol(index byte) Symbol {
	symbol := Symbol{Coeff: make([]byte, testK), Data: make([]byte, testSymbolSize)}
	symbol.Coeff[index] = 1
	symbol.Data[0] = index + 1
	return symbol
}

func newTestBounded(t *testing.T, limits Limits) *BoundedDecoder {
	t.Helper()
	bounded, err := NewBoundedDecoder(testK, testSymbolSize, testOriginal, limits,
		CommitSource(testSources(t)), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return bounded
}

// A zero coefficient vector carries no information about any source symbol. It
// is free to produce and it consumes an elimination pass, so a peer that could
// feed them in would spend a decoder's rank budget for nothing -- pollution in
// its cheapest form.
func TestAZeroCoefficientVectorIsRefusedEverywhere(t *testing.T) {
	decoder, err := NewDecoder(testK, testSymbolSize, testOriginal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Add(zeroSymbol()); err == nil {
		t.Fatal("the raw decoder accepted a zero coefficient vector")
	} else if !strings.Contains(err.Error(), "zero coefficient") {
		t.Fatalf("refused for some other reason: %v", err)
	}

	bounded := newTestBounded(t, DefaultLimits(testK, testSymbolSize))
	if _, err := bounded.Add(zeroSymbol(), time.Unix(0, 0)); err == nil {
		t.Fatal("the bounded decoder accepted a zero coefficient vector")
	}

	if _, err := NewPacket(GenerationID{1}, testK, testSymbolSize, testOriginal,
		zeroSymbol()); err == nil {
		t.Fatal("a packet was built around a zero coefficient vector")
	}

	if _, err := ReEncode([]Symbol{zeroSymbol(), zeroSymbol()}); err == nil {
		t.Fatal("re-encoding symbols that span only the zero vector produced a symbol")
	}

	// Vacuity: a real symbol is accepted by each of them, so the refusals
	// above are about the zero vector and not about the fixtures.
	fresh, err := NewDecoder(testK, testSymbolSize, testOriginal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Add(unitSymbol(0)); err != nil {
		t.Fatalf("the decoder refused an honest symbol: %v", err)
	}
	if _, err := NewPacket(GenerationID{1}, testK, testSymbolSize, testOriginal,
		unitSymbol(0)); err != nil {
		t.Fatalf("a packet could not be built around an honest symbol: %v", err)
	}
}

// Malformed dimensions are the other half of pollution: a peer that could
// declare a generation larger than the packet carries, or an original size
// beyond what the generation can hold, would make a receiver allocate or copy
// against numbers the sender chose.
func TestMalformedDimensionsAreRefused(t *testing.T) {
	// sized builds a symbol that matches the dimensions being declared, so a
	// refusal is about the dimensions rather than about a symbol that does not
	// fit them. Without this the interesting case below is caught by the
	// dimension-match check and the guard it is aimed at never runs.
	sized := func(k, symbolSize int) Symbol {
		symbol := Symbol{Coeff: make([]byte, k), Data: make([]byte, symbolSize)}
		if k > 0 {
			symbol.Coeff[0] = 1
		}
		return symbol
	}
	for _, scenario := range []struct {
		name         string
		k            int
		symbolSize   int
		originalSize int
	}{
		{"an original size beyond the generation's capacity", testK, testSymbolSize,
			testK*testSymbolSize + 1},
		{"a zero generation", 0, testSymbolSize, testOriginal},
		{"a zero symbol size", testK, 0, testOriginal},
		{"a negative original size", testK, testSymbolSize, -1},
		{"a generation wider than the wire fields", 1 << 20, testSymbolSize, testOriginal},
		// Each dimension fits its wire field and the pair does not fit the
		// fixed cell. This is the case the wire-field bound does not cover:
		// K and SymbolSize are both well inside uint16, and
		// PacketHeaderSize + K + SymbolSize is over PacketSize, so a peer
		// declaring them would have a receiver read a coded symbol past the
		// end of the cell that carried it.
		{"dimensions that fit their fields but not the cell together",
			PacketSize / 2, PacketSize / 2, testOriginal},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := NewPacket(GenerationID{1}, scenario.k, scenario.symbolSize,
				scenario.originalSize, sized(scenario.k, scenario.symbolSize)); err == nil {
				t.Fatalf("%s was accepted", scenario.name)
			}
		})
	}
}

// A packet's magic and version decide how the rest of its bytes are read. A
// parser that skipped them would interpret another format's bytes as
// coefficients and data.
func TestTheWireFormatIsRefusedRatherThanReinterpreted(t *testing.T) {
	packet, err := NewPacket(GenerationID{1}, testK, testSymbolSize, testOriginal, unitSymbol(0))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Vacuity: the unmodified wire form parses, so each refusal below is about
	// the byte that was changed.
	if _, err := ParsePacket(wire); err != nil {
		t.Fatalf("an honest packet did not parse: %v", err)
	}

	for _, scenario := range []struct {
		name  string
		build func() []byte
	}{
		{"a corrupted magic byte", func() []byte {
			bad := append([]byte(nil), wire...)
			bad[0] ^= 0xff
			return bad
		}},
		{"a truncated packet", func() []byte { return wire[:len(wire)-1] }},
		{"an oversized packet", func() []byte { return append(append([]byte(nil), wire...), 0) }},
		{"an empty packet", func() []byte { return nil }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := ParsePacket(scenario.build()); err == nil {
				t.Fatalf("%s parsed", scenario.name)
			}
		})
	}
}

// Combining packets from two generations would mix coefficients that refer to
// different source symbols, producing a symbol that decodes to nothing while
// looking well formed.
func TestPacketsFromDifferentGenerationsAreNotCombined(t *testing.T) {
	first, err := NewPacket(GenerationID{1}, testK, testSymbolSize, testOriginal, unitSymbol(0))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPacket(GenerationID{2}, testK, testSymbolSize, testOriginal, unitSymbol(1))
	if err != nil {
		t.Fatal(err)
	}
	// Vacuity: two packets of the same generation do combine.
	sameGeneration, err := NewPacket(GenerationID{1}, testK, testSymbolSize, testOriginal,
		unitSymbol(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReEncodePackets([]Packet{first, sameGeneration}); err != nil {
		t.Fatalf("two packets of one generation would not combine: %v", err)
	}

	if _, err := ReEncodePackets([]Packet{first, second}); err == nil {
		t.Fatal("packets from two generations were combined")
	}
	if _, err := ReEncodePackets(nil); err == nil {
		t.Fatal("re-encoding no packets produced a packet")
	}
}

// Every budget is a separate refusal, and each must fail closed on its own.
// A budget that was never reached because another one always fired first would
// be decoration, so each is driven with the others left generous.
func TestEachResourceBudgetFailsClosedOnItsOwn(t *testing.T) {
	generous := DefaultLimits(testK, testSymbolSize)
	generous.MaxSymbols = 1 << 20
	generous.MaxBytes = 1 << 40
	generous.MaxRankAttempts = 1 << 20
	generous.MaxWorkUnits = 1 << 40
	generous.MaxMemoryBytes = 1 << 30

	for _, scenario := range []struct {
		name  string
		limit func(Limits) Limits
	}{
		{"symbol count", func(l Limits) Limits { l.MaxSymbols = 1; return l }},
		{"byte count", func(l Limits) Limits { l.MaxBytes = 1; return l }},
		{"rank attempts", func(l Limits) Limits { l.MaxRankAttempts = 1; return l }},
		{"elimination work", func(l Limits) Limits { l.MaxWorkUnits = 1; return l }},
		{"basis memory", func(l Limits) Limits { l.MaxMemoryBytes = 1; return l }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			bounded := newTestBounded(t, scenario.limit(generous))
			var last error
			for index := 0; index < testK+4; index++ {
				if _, err := bounded.Add(unitSymbol(byte(index%testK)), time.Unix(0, 0)); err != nil {
					last = err
					break
				}
			}
			if last == nil {
				t.Fatalf("a decoder with a %s budget of one accepted every symbol", scenario.name)
			}
			if !errors.Is(last, ErrBudgetExhausted) {
				t.Fatalf("the %s budget failed for some other reason: %v", scenario.name, last)
			}
			if !strings.Contains(last.Error(), scenario.name) {
				t.Fatalf("the refusal does not name the %s budget: %v", scenario.name, last)
			}

			// Deterministic failure: once a decoder has failed it stays
			// failed, and says so, rather than accepting the next symbol as
			// though nothing happened.
			if bounded.Failed() == nil {
				t.Fatal("the decoder reports no failure after exhausting a budget")
			}
			if _, err := bounded.Add(unitSymbol(0), time.Unix(0, 0)); err == nil {
				t.Fatal("a failed decoder accepted another symbol")
			}
			if _, err := bounded.Decode(); err == nil {
				t.Fatal("a failed decoder produced a decode")
			}
		})
	}

	// Vacuity: with every budget generous, an honest generation decodes, so
	// the refusals above are about the budget that was tightened.
	bounded := newTestBounded(t, generous)
	for index := 0; index < testK; index++ {
		if _, err := bounded.Add(unitSymbol(byte(index)), time.Unix(0, 0)); err != nil {
			t.Fatalf("an honest symbol was refused under generous budgets: %v", err)
		}
	}
	if !bounded.Ready() {
		t.Fatalf("an honest generation did not reach full rank: %d of %d",
			bounded.Rank(), testK)
	}
	if _, err := bounded.Decode(); err != nil {
		t.Fatalf("an honest generation did not decode: %v", err)
	}
}

// A decoder that has not reached full rank must refuse to produce bytes rather
// than return whatever its partial basis holds. Silent partial output is worse
// than a refusal: the caller cannot tell it apart from a decode.
func TestARankDeficientDecoderRefusesRatherThanGuessing(t *testing.T) {
	decoder, err := NewDecoder(testK, testSymbolSize, testOriginal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(); err == nil {
		t.Fatal("an empty decoder produced bytes")
	}
	for index := 0; index < testK-1; index++ {
		if _, err := decoder.Add(unitSymbol(byte(index))); err != nil {
			t.Fatal(err)
		}
	}
	if decoder.Ready() {
		t.Fatal("the decoder claims to be ready one symbol short")
	}
	if _, err := decoder.Decode(); err == nil {
		t.Fatal("a decoder one symbol short of full rank produced bytes")
	}
	// And with the last one it does decode, so the refusal is about the rank.
	if _, err := decoder.Add(unitSymbol(byte(testK - 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(); err != nil {
		t.Fatalf("a full-rank decoder refused to decode: %v", err)
	}
}

// The source commitments are what make pollution detectable rather than merely
// wasteful: they are covered by the descriptor signature, so a peer cannot
// substitute its own. A decoder built with commitments that do not cover the
// generation could not check anything it decoded.
func TestCommitmentsMustCoverEverySourceSymbol(t *testing.T) {
	limits := DefaultLimits(testK, testSymbolSize)
	short := CommitSource(testSources(t)[:testK-1])
	if _, err := NewBoundedDecoder(testK, testSymbolSize, testOriginal, limits, short,
		time.Unix(0, 0)); err == nil {
		t.Fatal("a decoder was built with commitments covering fewer symbols than the generation")
	}
	// Nil is a documented mode, not an oversight: a decoder without
	// commitments verifies nothing before admission and only the budgets
	// apply. It is a weaker decoder reached by passing Go's zero value, so
	// what keeps it out of production is a check in another package --
	// live/batch refuses a descriptor whose commitment count is not exactly
	// K, and the materializer builds every decoder from a verified
	// descriptor. That invariant is asserted there, in the package that
	// depends on it, rather than assumed here.
	unverified, err := NewBoundedDecoder(testK, testSymbolSize, testOriginal, limits, nil,
		time.Unix(0, 0))
	if err != nil {
		t.Fatalf("the documented no-commitment mode was refused: %v", err)
	}
	if _, err := unverified.Add(unitSymbol(0), time.Unix(0, 0)); err != nil {
		t.Fatalf("the no-commitment decoder refused an honest symbol: %v", err)
	}

	longer := append(CommitSource(testSources(t)), [32]byte{})
	if _, err := NewBoundedDecoder(testK, testSymbolSize, testOriginal, limits, longer,
		time.Unix(0, 0)); err == nil {
		t.Fatal("a decoder was built with more commitments than the generation has symbols")
	}
	// Vacuity: the full commitment vector is accepted.
	if _, err := NewBoundedDecoder(testK, testSymbolSize, testOriginal, limits,
		CommitSource(testSources(t)), time.Unix(0, 0)); err != nil {
		t.Fatalf("a decoder could not be built with full commitments: %v", err)
	}
}
