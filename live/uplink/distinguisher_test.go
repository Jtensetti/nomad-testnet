package uplink

import (
	"testing"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-constant-rate-fabric/fabric"
	"github.com/Jtensetti/nomad-testnet/live/hop"
)

// buildProfileCells reproduces exactly how the live node fills a cell today:
// a work cell carries mix ciphertext plus work metadata, and a cover cell
// carries uniform random bytes plus cover metadata (live/node/node.go). The
// cells it returns are unsealed -- what the node holds before Seal, not what
// it puts on the wire.
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

// classifyByHeaderFlag is the cheapest possible passive attack: read the hop
// header and report whether the cell claims to carry work.
func classifyByHeaderFlag(cell fabric.Cell) bool {
	metadata, err := hop.LocalMetadata(cell)
	if err != nil {
		return false
	}
	return hop.IsWork(metadata)
}

// sealForWire puts a cell through the same Seal a node performs before the
// cell reaches a socket, which is the only form a passive observer ever sees.
func sealForWire(t *testing.T, cell fabric.Cell, sequence uint32) fabric.Cell {
	t.Helper()
	metadata, err := hop.LocalMetadata(cell)
	if err != nil {
		t.Fatal(err)
	}
	context := hop.Context{
		NetworkID: "distinguisher-network", Epoch: 3, Receiver: 1,
		TopologyDigest: [32]byte{4, 4, 4},
	}
	if err := hop.Seal(&cell, metadata, 2, sequence, [32]byte{5, 5, 5}, context); err != nil {
		t.Fatal(err)
	}
	return cell
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

// TestRelayProfileIsDistinguishableBeforeItIsSealed keeps the measurement that
// motivated hop header version 2, on the cells as the node holds them.
//
// Both classifiers separate work from cover with certainty here. That is the
// state of a cell in memory, and it is why the sealing step below is not
// optional.
func TestRelayProfileIsDistinguishableBeforeItIsSealed(t *testing.T) {
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
	if headerCorrect != total || structureCorrect != total {
		t.Fatalf("expected perfect separation before sealing, got header %d/%d and "+
			"structure %d/%d", headerCorrect, total, structureCorrect, total)
	}
}

// TestSealedRelayCellsResistBothDistinguishers is the same measurement on the
// bytes that actually go on the wire.
//
// Version 1 of the hop header failed this outright. It authenticated the
// header and sent it in the clear, so the work flag was readable directly; and
// it left the payload alone, so a work cell still parsed as compressed group
// elements while a cover cell did not. Two independent classifiers, both
// perfect. Version 2 encrypts the whole cell under the pairwise link key, and
// both must now do no better than guessing.
func TestSealedRelayCellsResistBothDistinguishers(t *testing.T) {
	const sampleSize = 16
	work, cover := buildProfileCells(t, sampleSize)

	for index, cell := range work {
		sealed := sealForWire(t, cell, uint32(index*2+1))
		if classifyByHeaderFlag(sealed) {
			t.Fatal("a sealed work cell exposes a readable work flag")
		}
		if classifyByCiphertextStructure(sealed) {
			t.Fatal("a sealed work cell is identifiable by payload structure")
		}
	}
	for index, cell := range cover {
		sealed := sealForWire(t, cell, uint32(index*2+2))
		if classifyByHeaderFlag(sealed) {
			t.Fatal("a sealed cover cell exposes a readable work flag")
		}
		if classifyByCiphertextStructure(sealed) {
			t.Fatal("a sealed cover cell is identifiable by payload structure")
		}
	}
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
