package rlnc

import "errors"

var ErrInconsistentSymbol = errors.New("coded symbol contradicts decoder state")

// Decoder incrementally maintains a reduced row-echelon basis. Add returns
// true only when a symbol increases the generation rank.
type Decoder struct {
	k            int
	symbolSize   int
	originalSize int
	basis        [][]byte
	rank         int
}

func NewDecoder(k, symbolSize, originalSize int) (*Decoder, error) {
	if k <= 0 || symbolSize <= 0 || originalSize <= 0 {
		return nil, errors.New("invalid decoder dimensions")
	}
	capacity := uint64(k) * uint64(symbolSize)
	if uint64(originalSize) > capacity {
		return nil, errors.New("original size exceeds decoder capacity")
	}
	return &Decoder{
		k:            k,
		symbolSize:   symbolSize,
		originalSize: originalSize,
		basis:        make([][]byte, k),
	}, nil
}

func (d *Decoder) Rank() int { return d.rank }
func (d *Decoder) Ready() bool { return d.rank == d.k }

func (d *Decoder) Add(symbol Symbol) (bool, error) {
	if len(symbol.Coeff) != d.k || len(symbol.Data) != d.symbolSize {
		return false, errors.New("symbol dimensions do not match decoder")
	}
	if !anyNonZero(symbol.Coeff) {
		return false, errors.New("zero coefficient vector")
	}

	row := make([]byte, d.k+d.symbolSize)
	copy(row, symbol.Coeff)
	copy(row[d.k:], symbol.Data)

	for col := 0; col < d.k; col++ {
		if row[col] == 0 {
			continue
		}
		if d.basis[col] != nil {
			addScaled(row, d.basis[col], row[col])
			continue
		}

		scale(row, inv(row[col]))
		for pivot, existing := range d.basis {
			if existing != nil && existing[col] != 0 {
				addScaled(existing, row, existing[col])
				d.basis[pivot] = existing
			}
		}
		d.basis[col] = row
		d.rank++
		return true, nil
	}

	if anyNonZero(row[d.k:]) {
		return false, ErrInconsistentSymbol
	}
	return false, nil
}

func (d *Decoder) Decode() ([]byte, error) {
	if !d.Ready() {
		return nil, errors.New("decoder is rank deficient")
	}
	out := make([]byte, 0, d.k*d.symbolSize)
	for i, row := range d.basis {
		if row == nil || row[i] != 1 {
			return nil, errors.New("decoder basis is incomplete")
		}
		out = append(out, row[d.k:]...)
	}
	return out[:d.originalSize], nil
}

func addScaled(dst, src []byte, factor byte) {
	for i := range dst {
		dst[i] = add(dst[i], mul(factor, src[i]))
	}
}

func scale(row []byte, factor byte) {
	for i := range row {
		row[i] = mul(row[i], factor)
	}
}
