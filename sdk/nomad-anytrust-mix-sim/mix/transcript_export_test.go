package mix

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// committeeTranscript runs a real committee and exports what it produced, so
// every test below verifies a transcript that a committee could actually have
// published rather than a fixture shaped to pass.
func committeeTranscript(t *testing.T, mixers int) (Transcript, []ed25519.PublicKey, PublicKey) {
	t.Helper()
	encryptionKey, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]PlainCell, 4)
	for index := range plain {
		copy(plain[index][:], "publication fragment")
		plain[index][0] = byte(index + 1)
	}
	batch, err := Encrypt(encryptionKey, plain)
	if err != nil {
		t.Fatal(err)
	}

	context := RoundContext{Epoch: 3}
	copy(context.CommitteeID[:], "conformance-committee")

	var identities []ed25519.PublicKey
	var rounds []Round
	var receipts []RoundReceipt
	current := batch
	for index := 0; index < mixers; index++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// The context's batch identifier is the digest of that round's input:
		// a receipt that named a different batch would authenticate work on
		// something other than what it was handed.
		inputDigest, err := current.Digest()
		if err != nil {
			t.Fatal(err)
		}
		roundContext := context
		roundContext.Round = uint32(index)
		roundContext.BatchID = inputDigest
		output, proof, receipt, err := ShuffleAndSign(roundContext, encryptionKey, current, private)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, public)
		rounds = append(rounds, Round{Input: current, Output: output, Proof: proof})
		receipts = append(receipts, receipt)
		current = output
	}

	transcript, err := ExportTranscript(encryptionKey, context, rounds, receipts)
	if err != nil {
		t.Fatal(err)
	}
	return transcript, identities, encryptionKey
}

// The claim: somebody who is not on the committee, holds no key and reads only
// what was published can check the committee's work.
func TestAPublishedTranscriptVerifiesForAThirdParty(t *testing.T) {
	transcript, mixers, _ := committeeTranscript(t, 3)

	encoded, err := MarshalTranscript(transcript)
	if err != nil {
		t.Fatal(err)
	}
	// Round-tripped through the published bytes, because that is what a third
	// party has -- not the in-memory value this process happens to hold.
	published, err := UnmarshalTranscript(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTranscript(published, mixers); err != nil {
		t.Fatalf("a transcript a committee produced did not verify: %v", err)
	}
	if len(published.Rounds) != 3 {
		t.Fatalf("the transcript carries %d rounds", len(published.Rounds))
	}
}

// A transcript must not be able to name its own signers, or the verdict is
// "this transcript is internally consistent" wearing the clothes of "this
// committee did this work".
func TestATranscriptCannotNameItsOwnSigners(t *testing.T) {
	transcript, mixers, _ := committeeTranscript(t, 3)

	stranger, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	swapped := append([]ed25519.PublicKey(nil), mixers...)
	swapped[1] = stranger
	if err := VerifyTranscript(transcript, swapped); err == nil {
		t.Fatal("a transcript verified against a committee that did not sign it")
	}

	// A caller who names too few or too many keys is refused rather than
	// silently checking a prefix.
	if err := VerifyTranscript(transcript, mixers[:2]); err == nil {
		t.Fatal("a transcript verified against fewer keys than it has rounds")
	}
	if err := VerifyTranscript(transcript, append(append([]ed25519.PublicKey(nil), mixers...),
		stranger)); err == nil {
		t.Fatal("a transcript verified against more keys than it has rounds")
	}
}

// Every way a transcript can be wrong, in one place. A verifier that accepted
// any of these would be a verifier a dishonest committee could satisfy.
func TestVerifyTranscriptFailsClosed(t *testing.T) {
	transcript, mixers, _ := committeeTranscript(t, 3)

	corrupt := func(change func(*Transcript)) Transcript {
		encoded, err := MarshalTranscript(transcript)
		if err != nil {
			t.Fatal(err)
		}
		copied, err := UnmarshalTranscript(encoded)
		if err != nil {
			t.Fatal(err)
		}
		change(&copied)
		return copied
	}

	flipBase64 := func(value string) string {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(raw) == 0 {
			t.Fatalf("cannot flip %q", value)
		}
		raw[0] ^= 0x01
		return base64.StdEncoding.EncodeToString(raw)
	}

	cases := map[string]Transcript{
		"an unrecognised version": corrupt(func(c *Transcript) {
			c.Version = "nomad-mix-transcript-v2"
		}),
		"no rounds": corrupt(func(c *Transcript) { c.Rounds = nil }),
		"a flipped proof byte": corrupt(func(c *Transcript) {
			c.Rounds[1].Proof = flipBase64(c.Rounds[1].Proof)
		}),
		"a flipped signature byte": corrupt(func(c *Transcript) {
			c.Rounds[1].Receipt.Signature = flipBase64(c.Rounds[1].Receipt.Signature)
		}),
		"a flipped output digest": corrupt(func(c *Transcript) {
			c.Rounds[1].Receipt.OutputDigest = flipBase64(c.Rounds[1].Receipt.OutputDigest)
		}),
		"a flipped output cell": corrupt(func(c *Transcript) {
			c.Rounds[1].OutputCells[0] = flipBase64(c.Rounds[1].OutputCells[0])
		}),
		"a broken chain": corrupt(func(c *Transcript) {
			c.Rounds[2].InputCells = c.Rounds[0].InputCells
		}),
		"reordered rounds": corrupt(func(c *Transcript) {
			c.Rounds[0], c.Rounds[1] = c.Rounds[1], c.Rounds[0]
		}),
		// Truncation is detectable only against the committee the caller
		// names. That is the right place for it: the transcript cannot say
		// how many rounds it should have had without being able to lie.
		"a dropped last round": corrupt(func(c *Transcript) {
			c.Rounds = c.Rounds[:2]
		}),
		"a dropped first round": corrupt(func(c *Transcript) {
			c.Rounds = c.Rounds[1:]
		}),
		"another epoch": corrupt(func(c *Transcript) {
			c.Rounds[0].Receipt.Epoch++
		}),
		"another committee": corrupt(func(c *Transcript) {
			c.Rounds[0].Receipt.CommitteeID = flipBase64(c.Rounds[0].Receipt.CommitteeID)
		}),
		"another encryption key": corrupt(func(c *Transcript) {
			c.EncryptionKey = flipBase64(c.EncryptionKey)
		}),
		"a truncated batch": corrupt(func(c *Transcript) {
			c.Rounds[0].OutputCells = c.Rounds[0].OutputCells[:1]
		}),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			// Always the full committee. Trimming the key list to fit a
			// shortened transcript is what a dishonest committee would want a
			// verifier to do: a transcript missing its last round is a valid
			// shorter transcript, and only the caller's knowledge of who is on
			// the committee makes the omission visible.
			if err := VerifyTranscript(candidate, mixers); err == nil {
				t.Fatalf("a transcript with %s verified", name)
			}
		})
	}

	// The positive control: the same transcript, unmodified, verifies. Without
	// it every refusal above could be a verifier that refuses everything.
	if err := VerifyTranscript(transcript, mixers); err != nil {
		t.Fatalf("the unmodified transcript was refused: %v", err)
	}
}

func TestUnmarshalTranscriptRefusesMalformedInput(t *testing.T) {
	transcript, _, _ := committeeTranscript(t, 2)
	encoded, err := MarshalTranscript(transcript)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"an unknown member":    []byte(strings.Replace(string(encoded), `"version"`, `"surprise"`, 1)),
		"trailing content":     append(append([]byte(nil), encoded...), []byte("{}")...),
		"not JSON":             []byte("this is not a transcript"),
		"a truncated document": encoded[:len(encoded)/2],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalTranscript(candidate); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// ExportTranscript must refuse to publish something that establishes nothing,
// rather than emitting it and leaving the verifier to notice.
func TestExportTranscriptRefusesAnEmptyOrMismatchedCommittee(t *testing.T) {
	encryptionKey, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	context := RoundContext{Epoch: 1}
	copy(context.CommitteeID[:], "committee")

	if _, err := ExportTranscript(encryptionKey, context, nil, nil); err == nil {
		t.Error("a transcript with no rounds was exported")
	}
	if _, err := ExportTranscript(encryptionKey, context,
		[]Round{{}}, nil); err == nil {
		t.Error("a transcript with one round and no receipt was exported")
	}
}
