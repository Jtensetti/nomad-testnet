package mix

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"testing"
)

func testCells(n int) []PlainCell {
	cells := make([]PlainCell, n)
	for i := range cells {
		seed := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		for j := range cells[i] {
			cells[i][j] = seed[j%len(seed)] ^ byte(j)
		}
	}
	return cells
}

func sorted(cells []PlainCell) [][]byte {
	out := make([][]byte, len(cells))
	for i := range cells {
		out[i] = append([]byte(nil), cells[i][:]...)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func TestPayloadPreservingVerifiableCommitteeShuffle(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := testCells(8)
	encrypted, err := Encrypt(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	before, err := encrypted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	mixed, rounds, err := CommitteeMix(pub, encrypted, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rounds) != 2 {
		t.Fatalf("got %d rounds", len(rounds))
	}
	after, err := mixed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("shuffle retained the input representation")
	}
	decrypted, err := Decrypt(priv, mixed)
	if err != nil {
		t.Fatal(err)
	}
	want := sorted(plain)
	got := sorted(decrypted)
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("payload multiset changed at %d", i)
		}
	}
}

// A wire cell is [WireCellSize]byte, so its length is a compile-time constant
// and asserting it proves nothing. What the wire form has to get right is that
// the ciphertext occupies exactly the first cipherSize bytes and the rest is
// the caller's padding: a cell whose tail were zero, or ciphertext spilling
// past cipherSize, would both still be 1200 bytes long.
func TestTheWireTailIsThePaddingTheCallerSupplied(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := testCells(4)
	batch, err := Encrypt(public, plain)
	if err != nil {
		t.Fatal(err)
	}

	// Distinguishable padding: zeros would be indistinguishable from a tail
	// that was never written.
	const tailSize = WireCellSize - cipherSize
	padding := make([]byte, len(plain)*tailSize)
	for index := range padding {
		padding[index] = byte(index%251 + 1)
	}
	wire, err := batch.MarshalWireWithPadding(bytes.NewReader(padding))
	if err != nil {
		t.Fatal(err)
	}

	if len(wire) != len(plain) {
		t.Fatalf("marshalled %d cells for %d plaintext cells", len(wire), len(plain))
	}
	for index := range wire {
		tail := wire[index][cipherSize:]
		want := padding[index*tailSize : (index+1)*tailSize]
		if !bytes.Equal(tail, want) {
			t.Fatalf("cell %d carries %x in its tail, not the padding %x",
				index, tail, want)
		}
		if bytes.Equal(tail, make([]byte, tailSize)) {
			t.Fatalf("cell %d has a zero tail, so the padding was not written", index)
		}
	}

	parsed, err := ParseWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(private, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for index := range plain {
		if plain[index] != decrypted[index] {
			t.Fatalf("cell %d changed across the wire", index)
		}
	}
}

// Padding that runs out must fail the marshal rather than leave a tail of
// zeros, which is the one thing the cover traffic exists to avoid.
func TestPaddingThatRunsShortFailsTheMarshal(t *testing.T) {
	public, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := Encrypt(public, testCells(4))
	if err != nil {
		t.Fatal(err)
	}
	const tailSize = WireCellSize - cipherSize
	short := make([]byte, 4*tailSize-1)
	if _, err := batch.MarshalWireWithPadding(bytes.NewReader(short)); err == nil {
		t.Fatal("a padding source one byte short was accepted")
	}
	if _, err := batch.MarshalWireWithPadding(nil); err == nil {
		t.Fatal("a nil padding source was accepted")
	}
}

// The padding is not part of the ciphertext, and a reader has to be able to
// tell: two cells differing only in their tails must parse to the same batch.
// If this ever failed, padding would be carrying batch state.
func TestTheTailDoesNotReachTheDecryptedBatch(t *testing.T) {
	public, private, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := testCells(4)
	batch, err := Encrypt(public, plain)
	if err != nil {
		t.Fatal(err)
	}
	const tailSize = WireCellSize - cipherSize
	wire, err := batch.MarshalWireWithPadding(
		bytes.NewReader(make([]byte, len(plain)*tailSize)))
	if err != nil {
		t.Fatal(err)
	}
	for index := range wire {
		for offset := cipherSize; offset < WireCellSize; offset++ {
			wire[index][offset] ^= 0xff
		}
	}
	parsed, err := ParseWire(wire)
	if err != nil {
		t.Fatalf("a cell with a different tail failed to parse: %v", err)
	}
	decrypted, err := Decrypt(private, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for index := range plain {
		if plain[index] != decrypted[index] {
			t.Fatalf("cell %d changed when only its padding did", index)
		}
	}
}

func TestTamperedShuffleIsRejected(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	in, err := Encrypt(pub, testCells(4))
	if err != nil {
		t.Fatal(err)
	}
	out, encodedProof, err := ShuffleAndProve(pub, in)
	if err != nil {
		t.Fatal(err)
	}
	out.x[0][0], out.x[0][1] = out.x[0][1], out.x[0][0]
	if err := VerifyShuffle(pub, in, out, encodedProof); err == nil {
		t.Fatal("accepted a corrupted output batch")
	}
}

func TestBatchThresholdFailsClosed(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(pub, testCells(1)); err == nil {
		t.Fatal("accepted a one-cell batch")
	}
}
