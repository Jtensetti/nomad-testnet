package mix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// EncryptCell must be interchangeable with a column of Encrypt's output. That
// is the whole claim, and it has to hold at three levels: the bytes on the
// wire, the batch ParseWire builds from them, and everything the committee
// does to that batch afterwards. A cell that decrypted correctly but sat
// differently under a shuffle proof would be worse than useless.

func TestAnIndividuallyEncryptedCellHasTheSameWireShape(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cells := testCells(2)

	batch, err := Encrypt(pub, cells)
	if err != nil {
		t.Fatal(err)
	}
	fromBatch, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	individual, err := EncryptCell(pub, cells[0])
	if err != nil {
		t.Fatal(err)
	}

	if len(individual) != len(fromBatch[0]) {
		t.Fatalf("individual cell is %d bytes, a batch column is %d",
			len(individual), len(fromBatch[0]))
	}
	// The ciphertext differs because the randomness does; the point is that
	// nothing outside the ciphertext region differs in shape, and that the
	// padding region is not left as zeroes.
	if bytes.Equal(individual[cipherSize:], make([]byte, len(individual)-cipherSize)) {
		t.Fatal("the padding region is all zeroes, so a cell is distinguishable by its tail")
	}
}

// The real test: cells encrypted one at a time, assembled by ParseWire, must
// survive the committee's full pipeline exactly as a batch from Encrypt does.
func TestIndividuallyEncryptedCellsShuffleProveAndDecryptLikeABatch(t *testing.T) {
	committee, secrets, err := GenerateDealerCommittee(testCommitteeID(), 41, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	cells := testCells(4)

	wire := make([]WireCell, len(cells))
	for index, cell := range cells {
		wire[index], err = EncryptCell(committee.PublicKey, cell)
		if err != nil {
			t.Fatal(err)
		}
	}
	batch, err := ParseWire(wire)
	if err != nil {
		t.Fatalf("individually encrypted cells did not assemble into a batch: %v", err)
	}

	// A full signed shuffle round over that batch must verify.
	identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := batch.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ctx := RoundContext{CommitteeID: committee.ID, Epoch: committee.Epoch, BatchID: digest, Round: 0}
	shuffled, proof, receipt, err := ShuffleAndSign(ctx, committee.PublicKey, batch, identityPrivate)
	if err != nil {
		t.Fatalf("a batch of individually encrypted cells could not be shuffled: %v", err)
	}
	if err := VerifySignedRound(committee.PublicKey, batch, shuffled, proof, receipt); err != nil {
		t.Fatalf("the shuffle proof over individually encrypted cells did not verify: %v", err)
	}
	if !bytes.Equal(receipt.MixerPublic[:], identityPublic) {
		t.Fatal("receipt names the wrong mixer")
	}

	// And threshold decryption must return exactly the cells that went in.
	partials := make([]*PartialDecryption, 0, 3)
	for _, secret := range secrets[:3] {
		partial, err := CreatePartialDecryption(committee, secret, shuffled)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPartialDecryption(committee, shuffled, partial); err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	recovered, err := ThresholdDecrypt(committee, shuffled, partials)
	if err != nil {
		t.Fatalf("threshold decryption of individually encrypted cells failed: %v", err)
	}

	want, got := sorted(cells), sorted(recovered)
	if len(want) != len(got) {
		t.Fatalf("recovered %d cells, want %d", len(got), len(want))
	}
	for index := range want {
		if !bytes.Equal(want[index], got[index]) {
			t.Fatalf("cell %d did not survive the pipeline", index)
		}
	}
}

// Mixing the two encryption paths in one batch must also work, because a
// deployment that migrates one publisher at a time will do exactly that.
func TestABatchMayMixIndividuallyAndBatchEncryptedCells(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cells := testCells(4)

	batch, err := Encrypt(pub, cells[:2])
	if err != nil {
		t.Fatal(err)
	}
	fromBatch, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]WireCell(nil), fromBatch...)
	for _, cell := range cells[2:] {
		encrypted, err := EncryptCell(pub, cell)
		if err != nil {
			t.Fatal(err)
		}
		wire = append(wire, encrypted)
	}

	mixed, err := ParseWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Decrypt(priv, mixed)
	if err != nil {
		t.Fatalf("a batch mixing both encryption paths did not decrypt: %v", err)
	}
	want, got := sorted(cells), sorted(recovered)
	for index := range want {
		if !bytes.Equal(want[index], got[index]) {
			t.Fatalf("cell %d did not survive a mixed batch", index)
		}
	}
}

// Two encryptions of one cell must differ, or the ciphertext would identify
// the plaintext to anyone who has seen it before.
func TestEncryptingOneCellTwiceProducesDifferentCiphertext(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cell := testCells(1)[0]

	first, err := EncryptCell(pub, cell)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptCell(pub, cell)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[:cipherSize], second[:cipherSize]) {
		t.Fatal("two encryptions of one cell produced identical ciphertext, so the " +
			"randomness is not per-encryption")
	}

	// Both must still decrypt to the same plaintext.
	batch, err := ParseWire([]WireCell{first, second})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Decrypt(priv, batch)
	if err != nil {
		t.Fatal(err)
	}
	for index, got := range recovered {
		if !bytes.Equal(got[:], cell[:]) {
			t.Fatalf("copy %d decrypted to something else", index)
		}
	}
}

// Encrypt's two-cell minimum must stay: it is a mix property, not an
// implementation limit, and EncryptCell exists precisely so nobody is tempted
// to relax it.
func TestEncryptStillRefusesABatchThatWouldMixNothing(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(pub, testCells(1)); err == nil {
		t.Fatal("Encrypt accepted a one-cell batch, which a shuffle cannot mix")
	}
	if _, err := ParseWire([]WireCell{{}}); err == nil {
		t.Fatal("ParseWire accepted a one-cell batch")
	}
}

// Halving the work is the point, so it is measured rather than assumed.
func BenchmarkEncryptCell(b *testing.B) {
	pub, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	cell := testCells(1)[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncryptCell(pub, cell); err != nil {
			b.Fatal(err)
		}
	}
}

// The path the uplink used before EncryptCell existed: a two-column batch with
// one column discarded.
func BenchmarkEncryptTwoColumnBatchAndDiscardOne(b *testing.B) {
	pub, _, err := GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	cell := testCells(1)[0]
	var companion PlainCell
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch, err := Encrypt(pub, []PlainCell{cell, companion})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := batch.MarshalWire(); err != nil {
			b.Fatal(err)
		}
	}
}
