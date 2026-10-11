package fabric

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// RandomCell fills a cover cell, and cover is what makes an emission carrying
// nothing indistinguishable from one carrying work. A cover cell that came out
// short, zeroed, or the same twice would be distinguishable at a glance, and
// nothing in this module tested it: RandomCell and RandomCellFrom were at zero
// coverage here while live/node calls RandomCell on its production path.

func TestACoverCellIsFullAndDifferentEveryTime(t *testing.T) {
	seen := map[Cell]struct{}{}
	var zero Cell
	for attempt := 0; attempt < 16; attempt++ {
		cell, err := RandomCell()
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if cell == zero {
			t.Fatalf("attempt %d produced an all-zero cover cell", attempt)
		}
		if _, repeated := seen[cell]; repeated {
			t.Fatalf("attempt %d repeated an earlier cover cell", attempt)
		}
		seen[cell] = struct{}{}
	}
}

// A short read must be an error, not a cell that is partly the caller's
// entropy and partly zeros. The tail of such a cell is a constant, which is
// exactly the distinguisher cover exists to avoid.
func TestAnExhaustedEntropySourceIsAnErrorNotAHalfFilledCell(t *testing.T) {
	short := bytes.Repeat([]byte{0xa5}, CellSize-1)
	cell, err := RandomCellFrom(bytes.NewReader(short))
	if err == nil {
		t.Fatal("a source with one byte too few produced a cell")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("refused with %v, want an unexpected EOF", err)
	}
	if bytes.Equal(cell[:len(short)], short) && cell[CellSize-1] == 0 {
		t.Fatal("the half-filled cell was returned alongside the error, so a " +
			"caller ignoring the error emits a cell with a constant tail")
	}
}

func TestANilEntropySourceIsRefused(t *testing.T) {
	_, err := RandomCellFrom(nil)
	if err == nil {
		t.Fatal("a nil random source produced a cell")
	}
	if !strings.Contains(err.Error(), "random source") {
		t.Fatalf("refused for %q rather than the missing source", err)
	}
}

// The whole cell is filled, not a prefix: a reader that stopped early would
// leave a tail every cover cell shares.
func TestTheWholeCellIsFilledFromTheSource(t *testing.T) {
	pattern := bytes.Repeat([]byte{0x3c}, CellSize)
	cell, err := RandomCellFrom(bytes.NewReader(pattern))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cell[:], pattern) {
		for index := range cell {
			if cell[index] != pattern[index] {
				t.Fatalf("byte %d of the cell did not come from the source", index)
			}
		}
	}
}
