package mix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"go.dedis.ch/kyber/v4"
)

// EncryptCell must be interchangeable with a column of Encrypt's output. That
// is the whole claim, and it has to hold at three levels: the bytes on the
// wire, the batch ParseWire builds from them, and everything the committee
// does to that batch afterwards. A cell that decrypted correctly but sat
// differently under a shuffle proof would be worse than useless.

// The wire form is the claim, so it is checked structurally rather than by
// comparing two array lengths.
//
// The first version of this test did exactly that: `len(individual) !=
// len(fromBatch[0])` over two [1200]byte values, which the compiler folds to
// 1200 != 1200. It built a whole two-column batch and marshalled it in order to
// read a constant, and asserted nothing about ordering, offsets or structure.
// An evaluator found it; a mutation that swapped x and y, or wrote the
// plaintext into the padding region, sailed past it.
func TestAnIndividuallyEncryptedCellHasTheSameWireShape(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cell := testCells(1)[0]
	wire, err := EncryptCell(pub, cell)
	if err != nil {
		t.Fatal(err)
	}

	suite := newSuite()
	secret, err := privateScalar(suite, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Row r occupies [r*64, r*64+64): x first, then y. Recovering the chunk
	// requires that ordering to be right, so this pins the layout rather than
	// merely the length.
	seen := map[string]struct{}{}
	for row := 0; row < ChunkCount; row++ {
		offset := row * 2 * pointSize
		x := suite.Point()
		if err := x.UnmarshalBinary(wire[offset : offset+pointSize]); err != nil {
			t.Fatalf("row %d: first point does not decode, so x is not first: %v", row, err)
		}
		y := suite.Point()
		if err := y.UnmarshalBinary(wire[offset+pointSize : offset+2*pointSize]); err != nil {
			t.Fatalf("row %d: second point does not decode: %v", row, err)
		}
		recovered, err := suite.Point().Sub(y, suite.Point().Mul(secret, x)).Data()
		if err != nil {
			t.Fatalf("row %d: %v", row, err)
		}
		start := row * ChunkSize
		if !bytes.Equal(recovered, cell[start:start+ChunkSize]) {
			t.Fatalf("row %d did not recover its own chunk, so the layout is not "+
				"x-then-y per row", row)
		}
		// Every row must carry its own ephemeral. One r reused across all
		// eighteen rows still decrypts and still differs between calls, but it
		// makes the cell trivially distinguishable from a genuine Encrypt
		// column, and recovering any single chunk then yields r*h and with it
		// the whole 504-byte fragment.
		encoded, err := x.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if _, repeated := seen[string(encoded)]; repeated {
			t.Fatalf("row %d reuses an ephemeral point from an earlier row", row)
		}
		seen[string(encoded)] = struct{}{}
	}

	if offset := ChunkCount * 2 * pointSize; offset != cipherSize {
		t.Fatalf("the ciphertext region is %d bytes, want %d", offset, cipherSize)
	}
}

// The padding is on the wire wherever MarshalWire's output is, so what is in it
// matters. Asserting only that it is not all-zero let a mutation that copied
// the first 48 bytes of the private fragment into it pass every test in this
// file -- publishing plaintext in cleartext in every cell.
func TestThePaddingIsRandomAndCarriesNoPlaintext(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// A recognisable, low-entropy plaintext, so a copy of it into the padding
	// is unmistakable.
	var cell PlainCell
	for index := range cell {
		cell[index] = byte(index % 7)
	}

	const paddingSize = WireCellSize - cipherSize
	tails := make([][]byte, 0, 8)
	for trial := 0; trial < 8; trial++ {
		wire, err := EncryptCell(pub, cell)
		if err != nil {
			t.Fatal(err)
		}
		tail := append([]byte(nil), wire[cipherSize:]...)
		if len(tail) != paddingSize {
			t.Fatalf("padding is %d bytes, want %d", len(tail), paddingSize)
		}
		if bytes.Contains(cell[:], tail[:16]) {
			t.Fatal("the padding contains bytes of the plaintext")
		}
		if bytes.Equal(tail, make([]byte, paddingSize)) {
			t.Fatal("the padding is all zeroes")
		}
		// A constant filler is as bad as a zero one: it makes every cell's
		// tail identical and so a one-comparison classifier.
		for _, previous := range tails {
			if bytes.Equal(previous, tail) {
				t.Fatal("two encryptions produced identical padding, so it is not random")
			}
		}
		tails = append(tails, tail)
	}
}

// A ciphertext whose randomness comes from a fixed seed is catastrophic here,
// and successive cells still differ under one, so "two encryptions differ" does
// not detect it. What does: two processes must not agree.
//
// The suite draws a fresh seed from crypto/rand on every call and keeps no
// state, so two sequences taken one after another are independent draws rather
// than one continuing stream.
//
// What this catches, precisely: an ephemeral derived deterministically from the
// plaintext, and a fresh fixed-seed stream per call -- both make the second
// sequence replay the first. It does not catch a single long-lived
// deterministic stream shared across calls, because that advances and so still
// yields distinct values within one process; detecting that needs a comparison
// across processes, which a unit test cannot make. In practice such a stream is
// caught by the per-row ephemeral-distinctness check above, but incidentally
// rather than by design, and this comment says so rather than implying the
// property is fully pinned here.
func TestEncryptionRandomnessIsNotReproducible(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cell := testCells(1)[0]

	first := make(map[string]struct{})
	for trial := 0; trial < 16; trial++ {
		wire, err := EncryptCell(pub, cell)
		if err != nil {
			t.Fatal(err)
		}
		first[string(wire[:pointSize])] = struct{}{}
	}
	if len(first) != 16 {
		t.Fatalf("16 encryptions produced %d distinct ephemerals", len(first))
	}

	// The same again, as a separate sequence. Under a deterministic stream the
	// second sequence replays the first; under crypto/rand the two sets are
	// disjoint. This is the property a fixed seed breaks and repetition alone
	// does not test.
	overlap := 0
	for trial := 0; trial < 16; trial++ {
		wire, err := EncryptCell(pub, cell)
		if err != nil {
			t.Fatal(err)
		}
		if _, seen := first[string(wire[:pointSize])]; seen {
			overlap++
		}
	}
	if overlap > 0 {
		t.Fatalf("%d of 16 ephemerals repeated an earlier sequence, so the randomness "+
			"is seeded rather than drawn fresh", overlap)
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

// Encrypting to the identity yields y = m + r*0 = m, which is the plaintext in
// cleartext on the wire. UnmarshalBinary checks that a key is on the curve, not
// that it is in the prime-order subgroup, so nothing stopped it.
//
// validateThresholdCommittee has rejected small-order points since it was
// written, and Encrypt never called it. A caller holding a bare PublicKey that
// never passed committee validation -- uplink.Session holds exactly that -- had
// no protection at all. Found by an evaluator, who recovered a full 504-byte
// fragment off the wire with no key material.
func TestEncryptingToASmallOrderKeyIsRefused(t *testing.T) {
	suite := newSuite()
	cell := testCells(1)[0]

	for name, point := range map[string]kyber.Point{
		"the group identity": suite.Point().Null(),
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := point.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var key PublicKey
			copy(key[:], encoded)

			if _, err := EncryptCell(key, cell); err == nil {
				t.Fatal("EncryptCell accepted a small-order key, so the plaintext is on the wire")
			}
			if _, err := Encrypt(key, testCells(2)); err == nil {
				t.Fatal("Encrypt accepted a small-order key, so the plaintext is on the wire")
			}
		})
	}

	// A genuine key must still work, or the check is just refusing everything.
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptCell(pub, cell); err != nil {
		t.Fatalf("a genuine committee key was refused: %v", err)
	}
}
