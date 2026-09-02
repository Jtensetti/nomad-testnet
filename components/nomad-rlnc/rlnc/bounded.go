package rlnc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// A malicious peer can send a coded symbol whose coefficient vector is
// well-formed and innovative but whose data is wrong. Such a symbol raises
// the rank and enters the basis, so the corruption is only detected when the
// finished object fails its hash and signature check. Between admission and
// that check an attacker can spend the decoder's CPU and memory.
//
// This file addresses that in two ways.
//
// First, every generation carries explicit, enforced budgets: symbols
// accepted, bytes ingested, rank attempts, elimination work, basis memory
// and wall-clock lifetime. Exceeding any budget ends the generation
// immediately. This converts an unbounded resource attack into a bounded,
// accounted cost, which is what the production criteria require.
//
// Second, where a symbol is systematic it is verified cryptographically
// BEFORE admission, against per-source-symbol commitments carried in the
// signed batch descriptor. A systematic symbol names exactly one source
// symbol, so a plain hash comparison settles it, and polluted systematic
// symbols never reach the basis at all.
//
// What is deliberately NOT claimed: a general coded symbol, one whose
// coefficient vector mixes several sources, cannot be checked this way. A
// hash is not homomorphic over the code's linear structure. The established
// constructions that would allow it either require the code to live in a
// large prime field (homomorphic hashing), a shared secret that a broadcast
// re-encoding network cannot have (homomorphic MACs), or pairings
// (homomorphic signatures). Nomad's code is over GF(2^8) and its symbols are
// re-encoded by relaying peers, so none of them applies without changing the
// coding field, which is a protocol change and not a casual one. Until that
// analysis is done, a polluted coded symbol remains detectable only at final
// object verification, and the guarantee here is that it cannot cost more
// than the generation's budget.

var (
	// ErrBudgetExhausted reports that a generation hit one of its limits.
	ErrBudgetExhausted = errors.New("generation budget exhausted")
	// ErrGenerationExpired reports that a generation outlived its window.
	ErrGenerationExpired = errors.New("generation lifetime expired")
	// ErrCommitmentMismatch reports a systematic symbol whose data does not
	// match the committed source symbol.
	ErrCommitmentMismatch = errors.New("symbol contradicts its source commitment")
)

// Limits are the per-generation budgets. They are public deployment policy
// and never depend on which object a reader wants.
type Limits struct {
	// MaxSymbols bounds symbols accepted for processing, innovative or not.
	MaxSymbols int
	// MaxBytes bounds total ingested symbol bytes.
	MaxBytes int64
	// MaxRankAttempts bounds elimination passes, so repeated non-innovative
	// symbols cannot be replayed for free.
	MaxRankAttempts int
	// MaxWorkUnits bounds GF(2^8) row operations, the decoder's dominant
	// cost. It is a deterministic proxy for CPU: the same input always
	// consumes the same units, so a budget cannot be evaded by timing.
	MaxWorkUnits int64
	// MaxMemoryBytes bounds resident basis memory.
	MaxMemoryBytes int64
	// Lifetime bounds how long a generation may remain open.
	Lifetime time.Duration
}

// DefaultLimits are sized for the v0.1 profile: K source symbols of
// SymbolSize bytes, allowing a generous multiple of K symbols before giving
// up, and bounding elimination work to the cost of a full decode times that
// multiple.
func DefaultLimits(k, symbolSize int) Limits {
	const overheadFactor = 4
	rowWidth := int64(k + symbolSize)
	return Limits{
		MaxSymbols:      overheadFactor * k,
		MaxBytes:        int64(overheadFactor*k) * rowWidth,
		MaxRankAttempts: overheadFactor * k,
		MaxWorkUnits:    int64(overheadFactor) * int64(k) * int64(k) * rowWidth,
		MaxMemoryBytes:  int64(k) * rowWidth,
		Lifetime:        5 * time.Minute,
	}
}

func (limits Limits) validate() error {
	if limits.MaxSymbols <= 0 || limits.MaxBytes <= 0 || limits.MaxRankAttempts <= 0 ||
		limits.MaxWorkUnits <= 0 || limits.MaxMemoryBytes <= 0 || limits.Lifetime <= 0 {
		return errors.New("every generation limit must be positive")
	}
	return nil
}

// SourceCommitments are per-source-symbol hashes, carried in the signed
// batch descriptor. Index i commits to source symbol i.
type SourceCommitments [][32]byte

// CommitSource builds the commitment vector for a generation's source
// symbols. Publishers compute it once; it is covered by the descriptor
// signature, so a peer cannot substitute its own.
func CommitSource(sources [][]byte) SourceCommitments {
	commitments := make(SourceCommitments, len(sources))
	for index, source := range sources {
		commitments[index] = commitSymbol(index, source)
	}
	return commitments
}

func commitSymbol(index int, data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-rlnc-source-commitment-v1"))
	var position [4]byte
	binary.BigEndian.PutUint32(position[:], uint32(index))
	_, _ = h.Write(position[:])
	_, _ = h.Write(data)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// systematicIndex reports the single source index a symbol names, or -1 if
// the symbol is a genuine linear combination.
func systematicIndex(coeff []byte) int {
	found := -1
	for index, value := range coeff {
		if value == 0 {
			continue
		}
		if found >= 0 || value != 1 {
			return -1
		}
		found = index
	}
	return found
}

// BoundedDecoder wraps Decoder with enforced budgets and, where possible,
// pre-admission verification. A generation that exceeds any budget is
// terminated rather than throttled: dropping useful work is preferred to
// letting an attacker set the cost.
type BoundedDecoder struct {
	decoder     *Decoder
	limits      Limits
	commitments SourceCommitments
	deadline    time.Time

	symbols   int
	bytes     int64
	attempts  int
	work      int64
	memory    int64
	seen      map[[32]byte]struct{}
	failed    error
	rejected  int
	duplicate int
}

// NewBoundedDecoder starts a generation. commitments may be nil, in which
// case no symbol can be verified before admission and only the budgets
// apply; pass them whenever the signed descriptor carries them.
func NewBoundedDecoder(k, symbolSize, originalSize int, limits Limits, commitments SourceCommitments, now time.Time) (*BoundedDecoder, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if commitments != nil && len(commitments) != k {
		return nil, errors.New("source commitments must cover every source symbol")
	}
	decoder, err := NewDecoder(k, symbolSize, originalSize)
	if err != nil {
		return nil, err
	}
	return &BoundedDecoder{
		decoder: decoder, limits: limits, commitments: commitments,
		deadline: now.Add(limits.Lifetime),
		seen:     make(map[[32]byte]struct{}, limits.MaxSymbols),
	}, nil
}

// Stats reports accounting for evidence and operator metrics. It contains
// only counts about this generation, never anything about which object a
// reader wanted.
type Stats struct {
	Symbols    int
	Bytes      int64
	Attempts   int
	WorkUnits  int64
	MemoryUsed int64
	Rejected   int
	Duplicates int
	Rank       int
}

func (bounded *BoundedDecoder) Stats() Stats {
	return Stats{
		Symbols: bounded.symbols, Bytes: bounded.bytes, Attempts: bounded.attempts,
		WorkUnits: bounded.work, MemoryUsed: bounded.memory,
		Rejected: bounded.rejected, Duplicates: bounded.duplicate, Rank: bounded.decoder.Rank(),
	}
}

func (bounded *BoundedDecoder) Rank() int   { return bounded.decoder.Rank() }
func (bounded *BoundedDecoder) Ready() bool { return bounded.decoder.Ready() }

// Failed reports the terminal error, if the generation ended.
func (bounded *BoundedDecoder) Failed() error { return bounded.failed }

// Add offers one symbol. It returns true only when the symbol increased the
// rank. Once a generation fails it stays failed: every later call returns
// the same terminal error without doing work.
func (bounded *BoundedDecoder) Add(symbol Symbol, now time.Time) (bool, error) {
	if bounded.failed != nil {
		return false, bounded.failed
	}
	if !now.Before(bounded.deadline) {
		return false, bounded.fail(ErrGenerationExpired)
	}
	if len(symbol.Coeff) != bounded.decoder.k || len(symbol.Data) != bounded.decoder.symbolSize {
		bounded.rejected++
		return false, errors.New("symbol dimensions do not match decoder")
	}

	// Duplicate detection precedes all accounting so that replaying one
	// symbol cannot drain any budget.
	fingerprint := sha256.Sum256(append(append([]byte{}, symbol.Coeff...), symbol.Data...))
	if _, exists := bounded.seen[fingerprint]; exists {
		bounded.duplicate++
		return false, nil
	}

	if bounded.symbols+1 > bounded.limits.MaxSymbols {
		return false, bounded.fail(fmt.Errorf("%w: symbol count", ErrBudgetExhausted))
	}
	symbolBytes := int64(len(symbol.Coeff) + len(symbol.Data))
	if bounded.bytes+symbolBytes > bounded.limits.MaxBytes {
		return false, bounded.fail(fmt.Errorf("%w: byte count", ErrBudgetExhausted))
	}
	if bounded.attempts+1 > bounded.limits.MaxRankAttempts {
		return false, bounded.fail(fmt.Errorf("%w: rank attempts", ErrBudgetExhausted))
	}

	// Pre-admission verification, where the symbol permits it.
	if bounded.commitments != nil {
		if index := systematicIndex(symbol.Coeff); index >= 0 {
			expected := bounded.commitments[index]
			actual := commitSymbol(index, symbol.Data)
			if subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
				bounded.rejected++
				// A polluted systematic symbol is refused before it can
				// enter the basis, and costs one hash rather than an
				// elimination pass.
				return false, ErrCommitmentMismatch
			}
		}
	}

	// Charge the elimination work this admission may cost: one pass over the
	// row per existing pivot, plus the pivot update.
	rowWidth := int64(bounded.decoder.k + bounded.decoder.symbolSize)
	projected := int64(bounded.decoder.Rank()+1) * rowWidth
	if bounded.work+projected > bounded.limits.MaxWorkUnits {
		return false, bounded.fail(fmt.Errorf("%w: elimination work", ErrBudgetExhausted))
	}
	if !bounded.decoder.Ready() {
		if bounded.memory+rowWidth > bounded.limits.MaxMemoryBytes {
			return false, bounded.fail(fmt.Errorf("%w: basis memory", ErrBudgetExhausted))
		}
	}

	bounded.seen[fingerprint] = struct{}{}
	bounded.symbols++
	bounded.bytes += symbolBytes
	bounded.attempts++
	bounded.work += projected

	innovative, err := bounded.decoder.Add(symbol)
	if err != nil {
		bounded.rejected++
		return false, err
	}
	if innovative {
		bounded.memory += rowWidth
	}
	return innovative, nil
}

func (bounded *BoundedDecoder) fail(err error) error {
	if bounded.failed == nil {
		bounded.failed = err
		// Release the basis immediately so a terminated generation stops
		// occupying memory while a caller finishes handling the error.
		bounded.decoder.basis = nil
		bounded.decoder.rank = 0
		bounded.seen = nil
		bounded.memory = 0
	}
	return bounded.failed
}

// Decode returns the object only if the generation is complete and healthy.
func (bounded *BoundedDecoder) Decode() ([]byte, error) {
	if bounded.failed != nil {
		return nil, bounded.failed
	}
	return bounded.decoder.Decode()
}

// SourceCommitments returns the per-source-symbol commitments for this
// encoder's generation, in source order. A signed descriptor carries them so
// a decoder can refuse a polluted systematic symbol before it enters the
// basis, at the cost of one hash, instead of discovering the pollution when
// the finished object fails its envelope check.
func (e *Encoder) SourceCommitments() SourceCommitments {
	return CommitSource(e.source)
}
