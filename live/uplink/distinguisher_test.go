package uplink

import (
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// buildProfileCells reproduces exactly how the live node fills a cell today:
// a work cell carries mix ciphertext plus work metadata, and a cover cell
// carries uniform random bytes plus cover metadata (live/node/node.go).
func buildProfileCells(t *testing.T, count int) (work []fabric.Cell, cover []fabric.Cell) {
	t.Helper()
	public, _, err := mix.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]mix.PlainCell, count)
	for index := range plain {
		copy(plain[index][:], "publication fragment payload")
	}
	batch, err := mix.Encrypt(public, plain)
	if err != nil {
		t.Fatal(err)
	}
	wireCells, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	stream := hop.StreamID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	for ordinal, wireCell := range wireCells {
		var cell fabric.Cell
		copy(cell[:hop.CiphertextSize], wireCell[:hop.CiphertextSize])
		metadata, err := hop.WorkMetadata(stream, uint16(ordinal), uint16(len(wireCells)))
		if err != nil {
			t.Fatal(err)
		}
		if err := hop.SetMetadata(&cell, metadata); err != nil {
			t.Fatal(err)
		}
		work = append(work, cell)
	}
	for index := 0; index < count; index++ {
		cell, err := fabric.RandomCell()
		if err != nil {
			t.Fatal(err)
		}
		if err := hop.SetMetadata(&cell, hop.CoverMetadata()); err != nil {
			t.Fatal(err)
		}
		cover = append(cover, cell)
	}
	return work, cover
}

// classifyByHeaderFlag is the cheapest possible passive attack: read the
// cleartext hop header and report whether the cell claims to carry work.
func classifyByHeaderFlag(cell fabric.Cell) bool {
	metadata, err := hop.MetadataFromCell(cell)
	if err != nil {
		return false
	}
	return hop.IsWork(metadata)
}

// classifyByCiphertextStructure ignores the header entirely and asks only
// whether the payload region parses as compressed group elements. Uniform
// random bytes almost never do. A mix batch requires at least two columns,
// so the cell under test is paired with itself; that does not change what
// the classifier learns about the cell.
func classifyByCiphertextStructure(cell fabric.Cell) bool {
	var wireCell mix.WireCell
	copy(wireCell[:hop.CiphertextSize], cell[:hop.CiphertextSize])
	_, err := mix.ParseWire([]mix.WireCell{wireCell, wireCell})
	return err == nil
}

// TestCurrentProfileWorkCellsAreDistinguishable measures, rather than
// assumes, that the operator-to-operator cell profile in use today lets a
// passive observer separate work from cover with certainty, by two
// independent features.
//
// This does not contradict the reader claim the project already makes:
// operator relay work is driven by public replication policy, so the
// observable is the same whichever object a reader is interested in. It
// does establish that this cell profile cannot carry publisher uplink
// traffic, because there the existence of work is exactly the private fact
// that must not be observable. The uplink profile in this package is the
// response; see docs/PUBLICATION_INGRESS.md.
func TestCurrentProfileWorkCellsAreDistinguishable(t *testing.T) {
	const sampleSize = 16
	work, cover := buildProfileCells(t, sampleSize)

	headerCorrect := 0
	structureCorrect := 0
	for _, cell := range work {
		if classifyByHeaderFlag(cell) {
			headerCorrect++
		}
		if classifyByCiphertextStructure(cell) {
			structureCorrect++
		}
	}
	for _, cell := range cover {
		if !classifyByHeaderFlag(cell) {
			headerCorrect++
		}
		if !classifyByCiphertextStructure(cell) {
			structureCorrect++
		}
	}
	total := len(work) + len(cover)
	if headerCorrect != total {
		t.Fatalf("header-flag classifier: expected perfect separation, got %d/%d", headerCorrect, total)
	}
	if structureCorrect != total {
		t.Fatalf("ciphertext-structure classifier: expected perfect separation, got %d/%d", structureCorrect, total)
	}
	t.Logf("current profile: header-flag %d/%d, ciphertext-structure %d/%d", headerCorrect, total, structureCorrect, total)
}

// TestUplinkCellsResistBothDistinguishers applies the same two classifiers
// to the uplink profile. Both must do no better than a coin flip would be
// expected to, and in fact both must fail outright: every uplink cell is a
// uniform pseudorandom string of the same length, whether it carries a
// publication fragment or cover.
func TestUplinkCellsResistBothDistinguishers(t *testing.T) {
	const sampleSize = 12
	session := testSession(t)
	work := make([]fabric.Cell, 0, sampleSize)
	cover := make([]fabric.Cell, 0, sampleSize)
	for index := 0; index < sampleSize; index++ {
		var payload [PayloadSize]byte
		copy(payload[:], "publication fragment payload")
		workCell, err := session.SealWork(uint64(index)*2+1, payload)
		if err != nil {
			t.Fatal(err)
		}
		work = append(work, workCell)
		coverCell, err := session.SealCover(uint64(index)*2 + 2)
		if err != nil {
			t.Fatal(err)
		}
		cover = append(cover, coverCell)
	}

	for _, cell := range work {
		if classifyByHeaderFlag(cell) {
			t.Fatal("uplink work cell exposes a cleartext work flag")
		}
		if classifyByCiphertextStructure(cell) {
			t.Fatal("uplink work cell is identifiable by payload structure")
		}
	}
	for _, cell := range cover {
		if classifyByHeaderFlag(cell) {
			t.Fatal("uplink cover cell exposes a cleartext work flag")
		}
		if classifyByCiphertextStructure(cell) {
			t.Fatal("uplink cover cell is identifiable by payload structure")
		}
	}
}
