package rlnc

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

// symbolStream is a deterministic adversary driven by a fuzzer seed.
type symbolStream struct {
	state uint32
}

func (s *symbolStream) next() uint32 {
	s.state ^= s.state << 13
	s.state ^= s.state >> 17
	s.state ^= s.state << 5
	return s.state
}

// FuzzBoundedDecoderStaysWithinBudget drives the decoder with an arbitrary
// mixture of honest, dense-hostile and tampered-systematic symbols.
//
// The property is deliberately not "the decode is correct". A dense coded
// symbol with wrong data cannot be checked before admission -- see the note at
// the top of bounded.go -- so an attacker can always corrupt or deny a
// generation, and this fuzzer finds such cases within seconds. What must hold
// regardless of input is that the cost stays inside the accounted budget, that
// a tampered systematic symbol never reaches the basis, and that a successful
// Decode returns exactly the declared object length rather than something a
// caller would mis-slice.
func FuzzBoundedDecoderStaysWithinBudget(f *testing.F) {
	f.Add([]byte("nomad"), uint8(4), uint8(16), uint16(0))
	f.Add([]byte("a longer object that spans several source symbols"), uint8(3), uint8(8), uint16(7))
	f.Add(bytes.Repeat([]byte{0xA5}, 300), uint8(6), uint8(32), uint16(4919))

	f.Fuzz(func(t *testing.T, object []byte, symbolCount uint8, symbolSize uint8, seed uint16) {
		if len(object) == 0 || len(object) > 4096 || symbolSize == 0 {
			t.Skip()
		}
		encoder, err := NewEncoder(object, int(symbolSize))
		if err != nil {
			t.Skip()
		}
		k := encoder.K()
		if k > 64 {
			t.Skip()
		}
		limits := DefaultLimits(k, encoder.SymbolSize())
		start := time.Unix(1_700_000_000, 0)
		decoder, err := NewBoundedDecoder(k, encoder.SymbolSize(), encoder.OriginalSize(),
			limits, encoder.SourceCommitments(), start)
		if err != nil {
			t.Fatal(err)
		}

		stream := &symbolStream{state: uint32(seed) | 1}
		tamperedAdmitted := 0
		for attempt := 0; attempt < int(symbolCount)*8+16; attempt++ {
			var symbol Symbol
			tampered := false
			switch stream.next() % 4 {
			case 0:
				symbol, err = encoder.Systematic(int(stream.next()) % k)
			case 1:
				symbol, err = encoder.Encode()
			case 2:
				coeff := make([]byte, k)
				data := make([]byte, encoder.SymbolSize())
				for i := range coeff {
					coeff[i] = byte(stream.next())
				}
				for i := range data {
					data[i] = byte(stream.next())
				}
				coeff[int(stream.next())%k] |= 1
				symbol = Symbol{Coeff: coeff, Data: data}
			default:
				symbol, err = encoder.Systematic(int(stream.next()) % k)
				if err == nil {
					symbol.Data[int(stream.next())%len(symbol.Data)] ^= byte(stream.next() | 1)
					tampered = true
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			innovative, addErr := decoder.Add(symbol, start)
			if tampered && innovative {
				tamperedAdmitted++
			}
			if addErr != nil && decoder.Failed() != nil {
				break
			}
		}

		if tamperedAdmitted != 0 {
			t.Fatalf("%d tampered systematic symbol(s) entered the basis", tamperedAdmitted)
		}
		stats := decoder.Stats()
		if stats.Symbols > limits.MaxSymbols || stats.Bytes > limits.MaxBytes ||
			stats.Attempts > limits.MaxRankAttempts || stats.WorkUnits > limits.MaxWorkUnits ||
			stats.MemoryUsed > limits.MaxMemoryBytes {
			t.Fatalf("budget exceeded: %+v against %+v", stats, limits)
		}
		if !decoder.Ready() {
			return
		}
		decoded, err := decoder.Decode()
		if err != nil {
			return
		}
		if len(decoded) != encoder.OriginalSize() {
			t.Fatalf("decode returned %d bytes, declared %d", len(decoded), encoder.OriginalSize())
		}
	})
}

// FuzzHonestGenerationDecodesExactly is the other half: given only symbols the
// publisher actually produced, in any order and quantity, a successful decode
// must reproduce the object byte for byte. This is where the wrong-decode
// defect fixed in decoder.go would reappear.
func FuzzHonestGenerationDecodesExactly(f *testing.F) {
	f.Add([]byte("nomad"), uint8(16), uint16(1))
	f.Add(bytes.Repeat([]byte{0x5A}, 700), uint8(64), uint16(31337))

	f.Fuzz(func(t *testing.T, object []byte, symbolSize uint8, seed uint16) {
		if len(object) == 0 || len(object) > 4096 || symbolSize == 0 {
			t.Skip()
		}
		encoder, err := NewEncoder(object, int(symbolSize))
		if err != nil {
			t.Skip()
		}
		k := encoder.K()
		if k > 64 {
			t.Skip()
		}
		start := time.Unix(1_700_000_000, 0)
		decoder, err := NewBoundedDecoder(k, encoder.SymbolSize(), encoder.OriginalSize(),
			DefaultLimits(k, encoder.SymbolSize()), encoder.SourceCommitments(), start)
		if err != nil {
			t.Fatal(err)
		}
		stream := &symbolStream{state: uint32(seed) | 1}
		for attempt := 0; attempt < k*4 && !decoder.Ready(); attempt++ {
			var symbol Symbol
			if stream.next()%2 == 0 {
				symbol, err = encoder.Systematic(int(stream.next()) % k)
			} else {
				symbol, err = encoder.Encode()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decoder.Add(symbol, start); err != nil && decoder.Failed() != nil {
				return
			}
		}
		if !decoder.Ready() {
			return
		}
		decoded, err := decoder.Decode()
		if err != nil {
			t.Fatalf("honest generation failed to decode: %v", err)
		}
		if sha256.Sum256(decoded) != sha256.Sum256(object) {
			t.Fatalf("honest generation decoded to different bytes (%d vs %d)",
				len(decoded), len(object))
		}
	})
}
