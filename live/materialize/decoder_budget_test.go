package materialize

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/Jtensetti/nomad-rlnc/rlnc"
	"github.com/Jtensetti/nomad-testnet/live/batch"
)

// The decoder behind the materializer must be the budgeted one. A fragment
// that raises the rank has already passed the committee and the shuffle
// proofs, but its data can still be garbage that only the final envelope
// check rejects; without admission budgets such fragments spend the
// materializer's CPU and memory for free until that check runs.
func TestPacketDecoderEnforcesAdmissionBudgets(t *testing.T) {
	payload := make([]byte, 3200)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	encoder, err := rlnc.NewEncoder(payload, 400)
	if err != nil {
		t.Fatal(err)
	}
	var generation rlnc.GenerationID
	generation[0] = 7

	descriptor := batch.VerifiedDescriptor{Generation: generation}
	descriptor.Descriptor.K = uint16(encoder.K())
	descriptor.Descriptor.SymbolSize = uint16(encoder.SymbolSize())
	descriptor.Descriptor.OriginalSize = uint32(encoder.OriginalSize())

	decoder, err := newPacketDecoder(descriptor)
	if err != nil {
		t.Fatal(err)
	}

	// Distinct non-innovative fragments: every one is the same source symbol
	// re-scaled, so the rank stays 1 while each admission is a fresh
	// fingerprint that must be charged against the budgets.
	limit := rlnc.DefaultLimits(encoder.K(), encoder.SymbolSize()).MaxRankAttempts
	base, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	// Random re-scalings collide (255 distinct exist), and a duplicate is
	// deliberately uncharged, so draw enough times that well over
	// MaxRankAttempts distinct fingerprints are admitted.
	for attempt := 0; attempt < limit*8; attempt++ {
		// A random combination over one symbol is that symbol re-scaled:
		// a fresh fingerprint that cannot raise the rank.
		symbol, err := rlnc.ReEncode([]rlnc.Symbol{base})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(),
			encoder.OriginalSize(), symbol)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := packet.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if lastErr = decoder.Add(wire); lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("unbounded admissions: the decoder accepted rank-attempt work forever")
	}
	if !errors.Is(lastErr, rlnc.ErrBudgetExhausted) {
		t.Fatalf("want ErrBudgetExhausted, got: %v", lastErr)
	}

	// The generation fails closed once a budget is spent.
	fresh, err := encoder.Systematic(1)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := rlnc.NewPacket(generation, encoder.K(), encoder.SymbolSize(),
		encoder.OriginalSize(), fresh)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := decoder.Add(wire); err == nil || !strings.Contains(err.Error(), "budget") {
		t.Fatalf("a failed generation accepted another symbol: %v", err)
	}
}
