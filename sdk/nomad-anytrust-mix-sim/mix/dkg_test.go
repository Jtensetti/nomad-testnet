package mix

import (
	"bytes"
	"testing"
)

func TestAuthenticatedDKGFeedsThresholdDecryption(t *testing.T) {
	committee, members, transcript, err := RunAuthenticatedDKG(testCommitteeID(), 23, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if transcript.SessionID == [32]byte{} || transcript.Digest == [32]byte{} {
		t.Fatal("DKG transcript commitment is empty")
	}
	if len(transcript.Identities) != 5 || len(transcript.Qualified) != 5 {
		t.Fatalf("unexpected DKG transcript dimensions: identities=%d qualified=%d", len(transcript.Identities), len(transcript.Qualified))
	}
	for first := range transcript.Identities {
		for second := first + 1; second < len(transcript.Identities); second++ {
			if transcript.Identities[first] == transcript.Identities[second] {
				t.Fatal("DKG accepted duplicate long-term identities")
			}
		}
	}

	plain := testCells(3)
	batch, err := Encrypt(committee.PublicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*PartialDecryption, committee.Threshold)
	for index := range partials {
		partials[index], err = CreatePartialDecryption(committee, members[index], batch)
		if err != nil {
			t.Fatal(err)
		}
	}
	decrypted, err := ThresholdDecrypt(committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.Join(sorted(decrypted), nil), bytes.Join(sorted(plain), nil)) {
		t.Fatal("authenticated DKG threshold key did not preserve payloads")
	}
}
