package rlnc

import (
	"crypto/rand"
	"errors"
	"fmt"
)

type Symbol struct {
	Coeff []byte
	Data  []byte
}

type Encoder struct {
	source     [][]byte
	original   int
	symbolSize int
}

func NewEncoder(data []byte, symbolSize int) (*Encoder, error) {
	if symbolSize <= 0 {
		return nil, errors.New("symbolSize must be positive")
	}
	if len(data) == 0 {
		return nil, errors.New("data must not be empty")
	}
	k := (len(data) + symbolSize - 1) / symbolSize
	src := make([][]byte, k)
	for i := 0; i < k; i++ {
		src[i] = make([]byte, symbolSize)
		start := i * symbolSize
		end := start + symbolSize
		if end > len(data) {
			end = len(data)
		}
		copy(src[i], data[start:end])
	}
	return &Encoder{source: src, original: len(data), symbolSize: symbolSize}, nil
}

func (e *Encoder) K() int            { return len(e.source) }
func (e *Encoder) OriginalSize() int { return e.original }
func (e *Encoder) SymbolSize() int   { return e.symbolSize }

func (e *Encoder) Encode() (Symbol, error) {
	coeff := make([]byte, e.K())
	for {
		if _, err := rand.Read(coeff); err != nil {
			return Symbol{}, err
		}
		if anyNonZero(coeff) {
			break
		}
	}
	return e.encodeWith(coeff), nil
}

func (e *Encoder) Systematic(i int) (Symbol, error) {
	if i < 0 || i >= e.K() {
		return Symbol{}, fmt.Errorf("index out of range")
	}
	coeff := make([]byte, e.K())
	coeff[i] = 1
	return e.encodeWith(coeff), nil
}

func (e *Encoder) encodeWith(coeff []byte) Symbol {
	out := make([]byte, e.symbolSize)
	for i, c := range coeff {
		if c == 0 {
			continue
		}
		for j := range out {
			out[j] ^= mul(c, e.source[i][j])
		}
	}
	return Symbol{Coeff: append([]byte(nil), coeff...), Data: out}
}

func ReEncode(symbols []Symbol) (Symbol, error) {
	if len(symbols) == 0 {
		return Symbol{}, errors.New("no symbols")
	}
	k := len(symbols[0].Coeff)
	size := len(symbols[0].Data)
	if k == 0 || size == 0 {
		return Symbol{}, errors.New("empty symbol dimensions")
	}
	spanIsNonZero := false
	for _, s := range symbols {
		if len(s.Coeff) != k || len(s.Data) != size {
			return Symbol{}, errors.New("incompatible symbols")
		}
		if anyNonZero(s.Coeff) {
			spanIsNonZero = true
		}
	}
	if !spanIsNonZero {
		return Symbol{}, errors.New("symbols span only the zero vector")
	}

	// A random linear combination can occasionally cancel to the zero
	// coefficient vector. Retry rather than emitting a symbol that can never
	// increase decoder rank.
	for attempt := 0; attempt < 64; attempt++ {
		weights := make([]byte, len(symbols))
		if _, err := rand.Read(weights); err != nil {
			return Symbol{}, err
		}
		if !anyNonZero(weights) {
			continue
		}
		coeff := make([]byte, k)
		data := make([]byte, size)
		for i, s := range symbols {
			w := weights[i]
			if w == 0 {
				continue
			}
			for j := range coeff {
				coeff[j] ^= mul(w, s.Coeff[j])
			}
			for j := range data {
				data[j] ^= mul(w, s.Data[j])
			}
		}
		if anyNonZero(coeff) {
			return Symbol{Coeff: coeff, Data: data}, nil
		}
	}
	return Symbol{}, errors.New("failed to produce a non-zero re-encoded symbol")
}

func anyNonZero(v []byte) bool {
	for _, x := range v {
		if x != 0 {
			return true
		}
	}
	return false
}

func Decode(symbols []Symbol, k, originalSize int) ([]byte, error) {
	if k <= 0 || originalSize <= 0 {
		return nil, errors.New("invalid dimensions")
	}
	if len(symbols) < k {
		return nil, errors.New("insufficient symbols")
	}
	size := len(symbols[0].Data)
	if size == 0 {
		return nil, errors.New("empty symbol data")
	}
	decoder, err := NewDecoder(k, size, originalSize)
	if err != nil {
		return nil, err
	}
	for _, s := range symbols {
		if _, err := decoder.Add(s); err != nil {
			return nil, err
		}
	}
	return decoder.Decode()
}
