package basin

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

const (
	DefaultMaxInputBytes        = 64 << 10
	DefaultMaxEmbeddingDims     = 8192
	DefaultMaxEmbeddingResponse = 8 << 20
	HardMaxInputBytes           = 1 << 20
	HardMaxEmbeddingDims        = 1 << 16
	HardMaxEmbeddingResponse    = 32 << 20
)

type Embedder interface {
	Embed(context.Context, string) ([]float32, error)
}

// LexicalHashEmbedder is a deterministic bag-of-words/character-ngram
// baseline. It is useful for tests and lexical similarity only; it is not a
// semantic model.
type LexicalHashEmbedder struct {
	Dims          int
	MaxInputBytes int
}

func (h LexicalHashEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	if h.Dims <= 0 || h.Dims > HardMaxEmbeddingDims {
		return nil, errors.New("dims are outside the allowed range")
	}
	s := strings.ToLower(strings.TrimSpace(text))
	if s == "" {
		return nil, errors.New("text must not be empty")
	}
	maxInput, err := BoundedInt(h.MaxInputBytes, DefaultMaxInputBytes, HardMaxInputBytes, "maximum input size")
	if err != nil {
		return nil, err
	}
	if len(s) > maxInput {
		return nil, errors.New("text exceeds maximum input size")
	}
	v := make([]float32, h.Dims)
	scanner := bufio.NewScanner(strings.NewReader(s))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		tok := strings.TrimFunc(scanner.Text(), func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSpace(r) })
		if tok == "" {
			continue
		}
		f := fnv.New64a()
		_, _ = f.Write([]byte(tok))
		x := f.Sum64()
		idx := int(x % uint64(h.Dims))
		sign := float32(1)
		if (x>>63)&1 == 1 {
			sign = -1
		}
		v[idx] += sign

		rs := []rune(tok)
		for i := 0; i+2 < len(rs); i++ {
			f.Reset()
			_, _ = f.Write([]byte("3:" + string(rs[i:i+3])))
			y := f.Sum64()
			j := int(y % uint64(h.Dims))
			sg := float32(0.35)
			if (y>>63)&1 == 1 {
				sg = -sg
			}
			v[j] += sg
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !Normalize(v) {
		return nil, errors.New("text produced an empty lexical vector")
	}
	return v, nil
}

// BoundedInt applies the default-or-hard-maximum rule every embedding limit
// uses. It is exported because an embedder outside this package has to reach
// the same numbers: a limit that is enforced differently depending on which
// embedder is configured is not a limit.
func BoundedInt(value, defaultValue, hardMaximum int, name string) (int, error) {
	if value == 0 {
		return defaultValue, nil
	}
	if value < 0 || value > hardMaximum {
		return 0, fmt.Errorf("%s is outside the allowed range", name)
	}
	return value, nil
}

// Normalize scales a vector to unit length, reporting false for a vector that
// cannot be normalized -- non-finite, or all zero. Every Embedder must return
// a normalized vector, so it is exported for the same reason as BoundedInt:
// an embedder in another package must be able to meet the contract rather
// than approximate it.
func Normalize(v []float32) bool {
	var ss float64
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return false
		}
		ss += float64(x) * float64(x)
	}
	if ss == 0 {
		return false
	}
	inv := float32(1 / math.Sqrt(ss))
	for i := range v {
		v[i] *= inv
	}
	return true
}

// Quantizer implements a 64-bit random-hyperplane (SimHash-style) signature.
// Hyperplane coefficients are deterministic standard-normal values derived
// from Seed, bit index and vector dimension. Basin IDs are similarity metadata,
// not secrecy primitives.
type Quantizer struct{ Seed [32]byte }

func (q Quantizer) Basin(v []float32) (uint64, error) {
	if len(v) == 0 {
		return 0, errors.New("empty vector")
	}
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return 0, errors.New("vector contains non-finite value")
		}
	}

	var id uint64
	for bit := 0; bit < 64; bit++ {
		var dot float64
		for i, x := range v {
			dot += gaussianCoefficient(q.Seed, uint64(bit), uint64(i)) * float64(x)
		}
		if dot >= 0 {
			id |= 1 << uint(bit)
		}
	}
	return id, nil
}

func gaussianCoefficient(seed [32]byte, bit, dimension uint64) float64 {
	h := sha256.New()
	_, _ = h.Write([]byte("nomad-basin-hyperplane-v1"))
	_, _ = h.Write(seed[:])
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], bit)
	binary.BigEndian.PutUint64(b[8:], dimension)
	_, _ = h.Write(b[:])
	sum := h.Sum(nil)

	// Convert to open (0,1) intervals before Box-Muller so log(0) is impossible.
	u1 := (float64(binary.BigEndian.Uint64(sum[:8])) + 0.5) / (float64(^uint64(0)) + 1)
	u2 := (float64(binary.BigEndian.Uint64(sum[8:16])) + 0.5) / (float64(^uint64(0)) + 1)
	return math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func HammingDistance(a, b uint64) int {
	x := a ^ b
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}
