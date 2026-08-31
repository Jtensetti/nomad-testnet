package mix

import (
	"crypto/rand"
	"testing"
)

func benchCommittee(b *testing.B) (ThresholdCommittee, []MemberSecret) {
	b.Helper()
	committee, members, err := GenerateDealerCommittee(CommitteeID{7}, 9, 5, 3)
	if err != nil {
		b.Fatal(err)
	}
	return committee, members
}

func benchCells(b *testing.B, count int) []PlainCell {
	b.Helper()
	cells := make([]PlainCell, count)
	for index := range cells {
		if _, err := rand.Read(cells[index][:]); err != nil {
			b.Fatal(err)
		}
	}
	return cells
}

func BenchmarkHotEncryptBatch8(b *testing.B) {
	committee, _ := benchCommittee(b)
	cells := benchCells(b, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encrypt(committee.PublicKey, cells); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotDigest8(b *testing.B) {
	committee, _ := benchCommittee(b)
	batch, err := Encrypt(committee.PublicKey, benchCells(b, 8))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := batch.Digest(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotShuffleAndProve8(b *testing.B) {
	committee, _ := benchCommittee(b)
	batch, err := Encrypt(committee.PublicKey, benchCells(b, 8))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ShuffleAndProve(committee.PublicKey, batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotPartialDecryption8(b *testing.B) {
	committee, members := benchCommittee(b)
	batch, err := Encrypt(committee.PublicKey, benchCells(b, 8))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CreatePartialDecryption(committee, members[0], batch); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHotThresholdDecryptColumns8(b *testing.B) {
	committee, members := benchCommittee(b)
	batch, err := Encrypt(committee.PublicKey, benchCells(b, 8))
	if err != nil {
		b.Fatal(err)
	}
	partials := make([]*PartialDecryption, 3)
	for index := range partials {
		partials[index], err = CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ThresholdDecryptColumns(committee, batch, partials); err != nil {
			b.Fatal(err)
		}
	}
}
