package mix

import (
	"crypto/rand"
	"testing"
)

// The all-zero encoding is a valid point of order 4, so decoding alone does
// not establish that a committee key is usable: anything encrypted to a
// small-order key is masked with a handful of possible values and recoverable
// with no key material at all.
func TestCommitteeRejectsSmallOrderKeys(t *testing.T) {
	committee, _, err := GenerateDealerCommittee(CommitteeID{5}, 2, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateThresholdCommittee(committee); err != nil {
		t.Fatalf("a freshly generated committee was rejected: %v", err)
	}

	zeroKey := committee
	zeroKey.PublicKey = PublicKey{}
	if err := validateThresholdCommittee(zeroKey); err == nil {
		t.Error("an all-zero committee public key was accepted")
	}

	s := newSuite()
	identity, err := s.Point().Null().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	identityKey := committee
	copy(identityKey.PublicKey[:], identity)
	if err := validateThresholdCommittee(identityKey); err == nil {
		t.Error("the group identity was accepted as a committee public key")
	}

	zeroShare := committee
	zeroShare.Members = append([]PublicMember(nil), committee.Members...)
	zeroShare.Members[1].Share = SharePublicKey{}
	if err := validateThresholdCommittee(zeroShare); err == nil {
		t.Error("an all-zero member share was accepted")
	}
}

func TestValidateCiphertextColumnRejectsUnusablePoints(t *testing.T) {
	committee, _, err := GenerateDealerCommittee(CommitteeID{9}, 2, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	var plain PlainCell
	batch, err := Encrypt(committee.PublicKey, []PlainCell{plain, plain})
	if err != nil {
		t.Fatal(err)
	}
	cells, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCiphertextColumn(cells[0]); err != nil {
		t.Errorf("an honest ciphertext column was rejected: %v", err)
	}
	var zero WireCell
	if err := ValidateCiphertextColumn(zero); err == nil {
		t.Error("an all-zero column was accepted; it parses as identity points")
	}
	rejected := 0
	for attempt := 0; attempt < 20; attempt++ {
		var garbage WireCell
		if _, err := rand.Read(garbage[:]); err != nil {
			t.Fatal(err)
		}
		if err := ValidateCiphertextColumn(garbage); err != nil {
			rejected++
		}
	}
	if rejected == 0 {
		t.Error("no random column was rejected in 20 attempts")
	}
}

// A ciphertext of valid points that is not a real encryption passes every
// shuffle proof and fails only at decryption. All-or-nothing decryption let
// one such column discard every other sender's plaintext.
func TestOnePoisonedColumnDoesNotCensorItsNeighbours(t *testing.T) {
	committee, secrets, err := GenerateDealerCommittee(CommitteeID{6}, 2, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	var first, second PlainCell
	for index := range first {
		first[index] = 0x11
		second[index] = 0x22
	}
	batch, err := Encrypt(committee.PublicKey, []PlainCell{first, second, first})
	if err != nil {
		t.Fatal(err)
	}
	cells, err := batch.MarshalWire()
	if err != nil {
		t.Fatal(err)
	}
	poisoned := append([]WireCell(nil), cells...)
	for row := 0; row < ChunkCount; row++ {
		offset := row*2*pointSize + pointSize
		copy(poisoned[1][offset:offset+pointSize], cells[0][offset:offset+pointSize])
	}
	spliced, err := ParseWire(poisoned)
	if err != nil {
		t.Fatalf("the spliced batch did not parse: %v", err)
	}

	partials := make([]*PartialDecryption, 0, len(secrets))
	for _, secret := range secrets {
		partial, err := CreatePartialDecryption(committee, secret, spliced)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}

	if _, err := ThresholdDecrypt(committee, spliced, partials); err == nil {
		t.Error("the all-or-nothing form accepted a poisoned batch")
	}
	columns, err := ThresholdDecryptColumns(committee, spliced, partials)
	if err != nil {
		t.Fatalf("the per-column form failed the whole batch: %v", err)
	}
	if columns[1].Err == nil {
		t.Error("the poisoned column decrypted successfully")
	}
	for _, index := range []int{0, 2} {
		if columns[index].Err != nil {
			t.Errorf("column %d was censored by its poisoned neighbour: %v",
				index, columns[index].Err)
		}
	}
}
