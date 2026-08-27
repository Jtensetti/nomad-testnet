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

func TestWireRoundTripIsExactly1200BytesPerCell(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := testCells(4)
	batch, err := Encrypt(pub, plain)
	if err != nil {
		t.Fatal(err)
	}
	paddingBytes := 4 * (WireCellSize - cipherSize)
	wire, err := batch.MarshalWireWithPadding(bytes.NewReader(make([]byte, paddingBytes)))
	if err != nil {
		t.Fatal(err)
	}
	for i := range wire {
		if len(wire[i]) != WireCellSize {
			t.Fatalf("cell %d has size %d", i, len(wire[i]))
		}
	}
	parsed, err := ParseWire(wire)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(priv, parsed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range plain {
		if plain[i] != decrypted[i] {
			t.Fatalf("cell %d changed", i)
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
