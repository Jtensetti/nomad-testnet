package mix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

func testCommitteeID() CommitteeID {
	return CommitteeID(sha256.Sum256([]byte("nomad-test-committee-2026-08")))
}

func TestThresholdDecryptionRequiresVerifiedQuorum(t *testing.T) {
	committee, members, err := GenerateDealerCommittee(testCommitteeID(), 7, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	plain := testCells(4)
	batch, err := Encrypt(committee.PublicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*PartialDecryption, 3)
	for index := range partials {
		partials[index], err = CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatalf("member %d partial: %v", index, err)
		}
		if err := VerifyPartialDecryption(committee, batch, partials[index]); err != nil {
			t.Fatalf("member %d proof: %v", index, err)
		}
	}
	if _, err := ThresholdDecrypt(committee, batch, partials[:2]); err == nil {
		t.Fatal("decrypted without the threshold quorum")
	}
	decrypted, err := ThresholdDecrypt(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.Join(sorted(decrypted), nil), bytes.Join(sorted(plain), nil)) {
		t.Fatal("threshold decryption changed the payload multiset")
	}
}

func TestThresholdDecryptionRejectsTamperDuplicateAndWrongEpoch(t *testing.T) {
	committee, members, err := GenerateDealerCommittee(testCommitteeID(), 11, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := Encrypt(committee.PublicKey, testCells(3))
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*PartialDecryption, 3)
	for index := range partials {
		partials[index], err = CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
	}

	tampered := *partials[0]
	tampered.Points = append([][pointSize]byte(nil), partials[0].Points...)
	tampered.Proof = append([]byte(nil), partials[0].Proof...)
	tampered.Points[0][0] ^= 0x80
	if err := VerifyPartialDecryption(committee, batch, &tampered); err == nil {
		t.Fatal("accepted a tampered partial decryption")
	}

	if _, err := ThresholdDecrypt(committee, batch, []*PartialDecryption{partials[0], partials[0], partials[1]}); err == nil {
		t.Fatal("accepted a duplicated decryption member as quorum")
	}

	wrongEpoch := *partials[0]
	wrongEpoch.Epoch++
	if err := VerifyPartialDecryption(committee, batch, &wrongEpoch); err == nil {
		t.Fatal("accepted a partial decryption from another epoch")
	}
}

func TestContextualShuffleReceiptRejectsRetaggingAndReplay(t *testing.T) {
	encryptionKey, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	input, err := Encrypt(encryptionKey, testCells(4))
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, err := input.Digest()
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := RoundContext{
		CommitteeID: testCommitteeID(),
		Epoch:       19,
		BatchID:     inputDigest,
		Round:       2,
	}
	output, encodedProof, receipt, err := ShuffleAndSign(ctx, encryptionKey, input, identityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(receipt.MixerPublic[:], identityPublic) {
		t.Fatal("receipt contains the wrong mixer identity")
	}
	if err := VerifySignedRound(encryptionKey, input, output, encodedProof, receipt); err != nil {
		t.Fatal(err)
	}

	retagged := receipt
	retagged.Context.Epoch++
	if err := VerifySignedRound(encryptionKey, input, output, encodedProof, retagged); err == nil {
		t.Fatal("accepted a round receipt retagged to another epoch")
	}

	tracker, err := NewReceiptTracker(ctx.CommitteeID, ctx.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Accept(receipt); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Accept(receipt); !errors.Is(err, ErrRoundReplay) {
		t.Fatalf("got %v, want replay error", err)
	}
	equivocated := receipt
	equivocated.OutputDigest[0] ^= 1
	if err := tracker.Accept(equivocated); !errors.Is(err, ErrRoundEquivocate) {
		t.Fatalf("got %v, want equivocation error", err)
	}
}
