package rlnc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"runtime"
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func buildGeneration(t *testing.T, k, symbolSize int) (*Encoder, [][]byte, []byte) {
	t.Helper()
	object := make([]byte, k*symbolSize-7)
	if _, err := rand.Read(object); err != nil {
		t.Fatal(err)
	}
	encoder, err := NewEncoder(object, symbolSize)
	if err != nil {
		t.Fatal(err)
	}
	sources := make([][]byte, encoder.K())
	for index := range sources {
		symbol, err := encoder.Systematic(index)
		if err != nil {
			t.Fatal(err)
		}
		sources[index] = append([]byte(nil), symbol.Data...)
	}
	return encoder, sources, object
}

func TestBoundedDecoderRecoversHonestGeneration(t *testing.T) {
	encoder, sources, object := buildGeneration(t, 8, 64)
	bounded, err := NewBoundedDecoder(encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(),
		DefaultLimits(encoder.K(), encoder.SymbolSize()), CommitSource(sources), testNow)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < encoder.K(); index++ {
		symbol, err := encoder.Systematic(index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bounded.Add(symbol, testNow); err != nil {
			t.Fatal(err)
		}
	}
	decoded, err := bounded.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, object) {
		t.Fatal("honest generation must decode to the original object")
	}
}

// TestPollutedSystematicSymbolRejectedBeforeAdmission is the case a
// commitment can settle: a systematic symbol names exactly one source
// symbol, so a hash comparison refuses it before it can enter the basis.
func TestPollutedSystematicSymbolRejectedBeforeAdmission(t *testing.T) {
	encoder, sources, _ := buildGeneration(t, 8, 64)
	bounded, err := NewBoundedDecoder(encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(),
		DefaultLimits(encoder.K(), encoder.SymbolSize()), CommitSource(sources), testNow)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := encoder.Systematic(3)
	if err != nil {
		t.Fatal(err)
	}
	polluted := Symbol{Coeff: append([]byte(nil), symbol.Coeff...), Data: append([]byte(nil), symbol.Data...)}
	polluted.Data[0] ^= 0xff
	if _, err := bounded.Add(polluted, testNow); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("expected a commitment mismatch, got %v", err)
	}
	if bounded.Rank() != 0 {
		t.Fatal("a polluted systematic symbol must never enter the basis")
	}
	if bounded.Failed() != nil {
		t.Fatal("rejecting one bad symbol must not end the generation")
	}
	// The honest symbol for the same index is still accepted.
	if innovative, err := bounded.Add(symbol, testNow); err != nil || !innovative {
		t.Fatalf("the honest symbol must still be admitted: %v", err)
	}
}

// TestByzantineCampaignStaysBounded is the campaign the production criteria
// require, including the case where every received symbol is malicious. The
// decoder must not consume unbounded CPU or memory; it must terminate.
func TestByzantineCampaignStaysBounded(t *testing.T) {
	const k, symbolSize = 32, 128
	encoder, sources, _ := buildGeneration(t, k, symbolSize)
	commitments := CommitSource(sources)
	limits := DefaultLimits(k, symbolSize)

	for _, campaign := range []struct {
		name             string
		maliciousPercent int
	}{
		{"all malicious", 100},
		{"mostly malicious", 90},
		{"half malicious", 50},
	} {
		t.Run(campaign.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			bounded, err := NewBoundedDecoder(k, symbolSize, encoder.OriginalSize(), limits, commitments, testNow)
			if err != nil {
				t.Fatal(err)
			}
			attempts := 0
			for attempts < 100_000 {
				attempts++
				var symbol Symbol
				if attempts%100 < campaign.maliciousPercent {
					// A malicious innovative symbol: a well-formed random
					// coefficient vector with random data. It raises rank
					// while corrupting the generation, which is exactly the
					// case a hash cannot catch before admission.
					coeff := make([]byte, k)
					data := make([]byte, symbolSize)
					if _, err := rand.Read(coeff); err != nil {
						t.Fatal(err)
					}
					if _, err := rand.Read(data); err != nil {
						t.Fatal(err)
					}
					coeff[attempts%k] |= 1
					symbol = Symbol{Coeff: coeff, Data: data}
				} else {
					honest, err := encoder.Encode()
					if err != nil {
						t.Fatal(err)
					}
					symbol = honest
				}
				if _, err := bounded.Add(symbol, testNow); err != nil {
					if bounded.Failed() != nil {
						break
					}
				}
			}
			if bounded.Failed() == nil && attempts >= 100_000 {
				t.Fatal("the generation must terminate rather than accept work indefinitely")
			}
			stats := bounded.Stats()
			if stats.Symbols > limits.MaxSymbols {
				t.Fatalf("symbol budget exceeded: %d > %d", stats.Symbols, limits.MaxSymbols)
			}
			if stats.Bytes > limits.MaxBytes {
				t.Fatalf("byte budget exceeded: %d > %d", stats.Bytes, limits.MaxBytes)
			}
			if stats.WorkUnits > limits.MaxWorkUnits {
				t.Fatalf("work budget exceeded: %d > %d", stats.WorkUnits, limits.MaxWorkUnits)
			}
			if stats.Attempts > limits.MaxRankAttempts {
				t.Fatalf("rank-attempt budget exceeded: %d > %d", stats.Attempts, limits.MaxRankAttempts)
			}

			runtime.GC()
			runtime.ReadMemStats(&after)
			growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			ceiling := 64 * limits.MaxMemoryBytes
			if growth > ceiling {
				t.Fatalf("heap growth %d exceeded the ceiling %d", growth, ceiling)
			}
			t.Logf("%s: %+v terminal=%v", campaign.name, stats, bounded.Failed())
		})
	}
}

func TestDuplicateSymbolsDrainNoBudget(t *testing.T) {
	encoder, sources, _ := buildGeneration(t, 8, 64)
	bounded, err := NewBoundedDecoder(encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(),
		DefaultLimits(encoder.K(), encoder.SymbolSize()), CommitSource(sources), testNow)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Add(symbol, testNow); err != nil {
		t.Fatal(err)
	}
	baseline := bounded.Stats()
	for replay := 0; replay < 10_000; replay++ {
		if _, err := bounded.Add(symbol, testNow); err != nil {
			t.Fatalf("a replayed symbol must be ignored, not fatal: %v", err)
		}
	}
	after := bounded.Stats()
	if after.Symbols != baseline.Symbols || after.WorkUnits != baseline.WorkUnits || after.Bytes != baseline.Bytes {
		t.Fatal("replaying one symbol must not drain any budget")
	}
	if after.Duplicates < 10_000 {
		t.Fatal("duplicates must be counted")
	}
}

func TestGenerationLifetimeIsBounded(t *testing.T) {
	encoder, sources, _ := buildGeneration(t, 8, 64)
	limits := DefaultLimits(encoder.K(), encoder.SymbolSize())
	bounded, err := NewBoundedDecoder(encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(), limits, CommitSource(sources), testNow)
	if err != nil {
		t.Fatal(err)
	}
	symbol, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	expired := testNow.Add(limits.Lifetime)
	if _, err := bounded.Add(symbol, expired); !errors.Is(err, ErrGenerationExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
	if bounded.Failed() == nil {
		t.Fatal("an expired generation must be terminal")
	}
	if _, err := bounded.Decode(); err == nil {
		t.Fatal("an expired generation must not decode")
	}
}

func TestTerminatedGenerationReleasesMemoryAndStaysFailed(t *testing.T) {
	encoder, sources, _ := buildGeneration(t, 8, 64)
	limits := DefaultLimits(encoder.K(), encoder.SymbolSize())
	limits.MaxSymbols = 2
	bounded, err := NewBoundedDecoder(encoder.K(), encoder.SymbolSize(), encoder.OriginalSize(), limits, CommitSource(sources), testNow)
	if err != nil {
		t.Fatal(err)
	}
	var terminal error
	for index := 0; index < encoder.K(); index++ {
		symbol, err := encoder.Systematic(index)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bounded.Add(symbol, testNow); err != nil {
			terminal = err
			break
		}
	}
	if !errors.Is(terminal, ErrBudgetExhausted) {
		t.Fatalf("expected a budget failure, got %v", terminal)
	}
	if bounded.Stats().MemoryUsed != 0 {
		t.Fatal("a terminated generation must release its basis")
	}
	symbol, err := encoder.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Add(symbol, testNow); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatal("a failed generation must stay failed without doing further work")
	}
}

func TestLimitsMustBePositive(t *testing.T) {
	for name, limits := range map[string]Limits{
		"no symbols": {MaxBytes: 1, MaxRankAttempts: 1, MaxWorkUnits: 1, MaxMemoryBytes: 1, Lifetime: time.Minute},
		"no bytes":   {MaxSymbols: 1, MaxRankAttempts: 1, MaxWorkUnits: 1, MaxMemoryBytes: 1, Lifetime: time.Minute},
		"no work":    {MaxSymbols: 1, MaxBytes: 1, MaxRankAttempts: 1, MaxMemoryBytes: 1, Lifetime: time.Minute},
		"no memory":  {MaxSymbols: 1, MaxBytes: 1, MaxRankAttempts: 1, MaxWorkUnits: 1, Lifetime: time.Minute},
		"no life":    {MaxSymbols: 1, MaxBytes: 1, MaxRankAttempts: 1, MaxWorkUnits: 1, MaxMemoryBytes: 1},
	} {
		if _, err := NewBoundedDecoder(4, 16, 32, limits, nil, testNow); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
}

func TestCommitmentsMustCoverEverySource(t *testing.T) {
	if _, err := NewBoundedDecoder(8, 64, 400, DefaultLimits(8, 64), make(SourceCommitments, 7), testNow); err == nil {
		t.Fatal("a short commitment vector must be rejected")
	}
}

// The commitments the encoder publishes must be exactly what the bounded
// decoder checks admissions against: honest systematic symbols admitted,
// any tampered byte refused before the basis sees it.
func TestSourceCommitmentsBindSystematicSymbols(t *testing.T) {
	data := make([]byte, 1000)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncoder(data, 128)
	if err != nil {
		t.Fatal(err)
	}
	commitments := enc.SourceCommitments()
	if len(commitments) != enc.K() {
		t.Fatalf("want %d commitments, got %d", enc.K(), len(commitments))
	}
	decoder, err := NewBoundedDecoder(enc.K(), enc.SymbolSize(), enc.OriginalSize(),
		DefaultLimits(enc.K(), enc.SymbolSize()), commitments, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	honest, err := enc.Systematic(0)
	if err != nil {
		t.Fatal(err)
	}
	if innovative, err := decoder.Add(honest, time.Now()); err != nil || !innovative {
		t.Fatalf("honest systematic symbol refused: innovative=%v err=%v", innovative, err)
	}
	polluted, err := enc.Systematic(1)
	if err != nil {
		t.Fatal(err)
	}
	polluted.Data[3] ^= 0x40
	if _, err := decoder.Add(polluted, time.Now()); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("polluted systematic symbol not refused: %v", err)
	}
	if decoder.Rank() != 1 {
		t.Fatalf("polluted symbol reached the basis: rank %d", decoder.Rank())
	}
}
