package mix

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func sha256Of(data []byte) [32]byte { return sha256.Sum256(data) }

func signReceipt(t *testing.T, private ed25519.PrivateKey, receipt RoundReceipt,
	encryptionKey PublicKey) [ed25519.SignatureSize]byte {
	t.Helper()
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], ed25519.Sign(private, receiptSigningMessage(receipt, encryptionKey)))
	return signature
}

type blameFixture struct {
	encryptionKey PublicKey
	committee     ThresholdCommittee
	mixers        []ed25519.PublicKey
	privates      []ed25519.PrivateKey
	rounds        []SignedRound
}

// buildChain produces a sound three-round chain, which every case below
// perturbs in exactly one way.
func buildChain(t *testing.T, roundCount int) *blameFixture {
	t.Helper()
	committee, _, err := GenerateDealerCommittee(testCommitteeID(), 23, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &blameFixture{encryptionKey: committee.PublicKey, committee: committee}

	batch, err := Encrypt(committee.PublicKey, testCells(4))
	if err != nil {
		t.Fatal(err)
	}

	current := batch
	for round := 0; round < roundCount; round++ {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixture.mixers = append(fixture.mixers, public)
		fixture.privates = append(fixture.privates, private)

		digest, err := current.Digest()
		if err != nil {
			t.Fatal(err)
		}
		ctx := RoundContext{
			CommitteeID: committee.ID, Epoch: committee.Epoch,
			BatchID: digest, Round: uint32(round),
		}
		output, proof, receipt, err := ShuffleAndSign(ctx, committee.PublicKey, current, private)
		if err != nil {
			t.Fatal(err)
		}
		fixture.rounds = append(fixture.rounds, SignedRound{
			Round:   Round{Input: current, Output: output, Proof: proof},
			Receipt: receipt,
		})
		current = output
	}
	return fixture
}

// Soundness first. Blame that fires on an honest chain is not accountability,
// it is a weapon: anyone could use it to remove a mixer who did nothing.
func TestSoundChainProducesNoBlame(t *testing.T) {
	f := buildChain(t, 3)
	if report := AttributeFault(f.encryptionKey, f.committee, f.mixers, f.rounds); report != nil {
		t.Fatalf("an honest chain was blamed: %v", report)
	}
	// And a report fabricated against it must not verify.
	fabricated := FaultReport{
		Kind: FaultUnsoundRound, Round: 1, Attributable: true,
		Accused: f.mixers[1], Reason: "invented",
	}
	if err := VerifyFaultReport(f.encryptionKey, f.committee, f.mixers, f.rounds, fabricated); err == nil {
		t.Fatal("a fabricated report against an honest chain verified")
	}
}

// A mixer who signs a receipt over a transformation whose proof does not
// verify is attributable, because the signature covers input, output and proof
// digests together.
func TestUnsoundRoundIsAttributedToItsSigner(t *testing.T) {
	f := buildChain(t, 3)
	// Corrupt the proof the middle mixer committed to, then re-sign the
	// receipt so it still matches: this is a mixer who genuinely vouched for
	// an unsound round rather than a tampered transcript.
	broken := append([]byte(nil), f.rounds[1].Proof...)
	broken[len(broken)/2] ^= 0x40
	f.rounds[1].Proof = broken
	f.rounds[1].Receipt.ProofDigest = sha256Of(broken)
	f.rounds[1].Receipt.Signature = signReceipt(t, f.privates[1], f.rounds[1].Receipt, f.encryptionKey)

	report := AttributeFault(f.encryptionKey, f.committee, f.mixers, f.rounds)
	if report == nil {
		t.Fatal("an unsound round was not detected")
	}
	if report.Kind != FaultUnsoundRound || report.Round != 1 || !report.Attributable {
		t.Fatalf("wrong attribution: %+v", report)
	}
	if !bytes.Equal(report.Accused, f.mixers[1]) {
		t.Fatalf("blamed %x, want %x", report.Accused, f.mixers[1])
	}
	if err := VerifyFaultReport(f.encryptionKey, f.committee, f.mixers, f.rounds, *report); err != nil {
		t.Fatalf("a third party could not confirm the fault: %v", err)
	}
	// The report must not transfer to an innocent neighbour.
	moved := *report
	moved.Accused = f.mixers[0]
	if err := VerifyFaultReport(f.encryptionKey, f.committee, f.mixers, f.rounds, moved); err == nil {
		t.Fatal("blame was successfully re-pointed at an innocent mixer")
	}
}

// A receipt that does not verify under the key it names was not produced by
// that mixer. Naming them as the culprit would be exactly backwards.
func TestForgedReceiptDoesNotBlameTheImpersonatedMixer(t *testing.T) {
	f := buildChain(t, 3)
	f.rounds[2].Receipt.Signature[0] ^= 0xFF

	report := AttributeFault(f.encryptionKey, f.committee, f.mixers, f.rounds)
	if report == nil {
		t.Fatal("a forged receipt was not detected")
	}
	if report.Kind != FaultForgedReceipt {
		t.Fatalf("wrong kind: %+v", report)
	}
	if report.Attributable {
		t.Fatal("an impersonated mixer was held responsible for the forgery")
	}
}

// Broken linkage could have been caused by either neighbour, so the protocol
// must not pick one. Attributing it would let a malicious mixer frame the
// mixer after them by handing on the wrong batch.
func TestBrokenLinkageIsNotAttributedToAMixer(t *testing.T) {
	f := buildChain(t, 3)
	other := buildChain(t, 1)
	f.rounds[1].Input = other.rounds[0].Input

	report := AttributeFault(f.encryptionKey, f.committee, f.mixers, f.rounds)
	if report == nil {
		t.Fatal("broken linkage was not detected")
	}
	if report.Kind != FaultBrokenLinkage {
		t.Fatalf("wrong kind: %+v", report)
	}
	if report.Attributable {
		t.Fatal("broken linkage was pinned on one mixer, which lets one frame the next")
	}
}

// A round signed by a key outside the certified committee is a fault whatever
// its proof shows.
func TestRoundFromOutsideTheCommitteeIsBlamed(t *testing.T) {
	f := buildChain(t, 3)
	f.mixers[1] = make([]byte, ed25519.PublicKeySize)

	report := AttributeFault(f.encryptionKey, f.committee, f.mixers, f.rounds)
	if report == nil || report.Kind != FaultWrongCommittee || !report.Attributable {
		t.Fatalf("a non-member round was not blamed: %+v", report)
	}
}

// An empty transcript proves no mixing occurred and must not read as sound.
func TestEmptyTranscriptIsAFault(t *testing.T) {
	f := buildChain(t, 1)
	if report := AttributeFault(f.encryptionKey, f.committee, f.mixers, nil); report == nil {
		t.Fatal("a transcript with no rounds was accepted as sound")
	}
}
