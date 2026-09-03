package mix

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Frozen vectors for the domain-separated bindings.
//
// Every one of this package's thirteen domain separators could be changed and
// nothing failed. That is not a surprise on its own -- every test here is a
// round trip, and a round trip cannot notice a constant that producer and
// verifier both read. What would notice is a frozen output, and there was
// none: nomad-testnet's conformance corpus covers wire vectors (hop cells, an
// object manifest, topologies) and carries nothing from the mix.
//
// What did catch a change was nomad-testnet's compatibility matrix, which
// fails when a version constant it does not document appears in the source --
// so a rename is caught, in the other repository, by name. Nothing anywhere
// pinned what a separator *produces*, and nothing in the repository that
// defines them could fail on them at all. That is the same shape as F-39: the
// module that owns the code has to be able to fail on it.
//
// These vectors pin the bindings step 7 of the plan names -- transcript and
// domain separation, and epoch/batch/round binding -- at the only place they
// are deterministic: the digest preimages. The proofs themselves are
// randomised, which is why the wire corpus has no mix entries and why this is
// the form the pinning can take.
//
// Regenerating: run with -run TestBindingVectors -v and read the logged
// values. Do not regenerate to make a failing test pass. A changed value here
// means the wire format changed, and the question is whether that was
// intended, not how to make the test agree with it.

func vectorContext() RoundContext {
	var committee CommitteeID
	var batch [32]byte
	for index := range committee {
		committee[index] = byte(index + 1)
	}
	for index := range batch {
		batch[index] = byte(0xa0 + index)
	}
	return RoundContext{CommitteeID: committee, Epoch: 7, BatchID: batch, Round: 2}
}

func TestBindingVectorsAreFrozen(t *testing.T) {
	ctx := vectorContext()

	contextDigest := roundContextDigest(ctx)
	t.Logf("roundContextDigest = %x", contextDigest)
	const expectedContext = "d07dda51077f24afe702b1f2511727740eb54c6ea2337ad905b7cb03d8fcd679"
	if hex.EncodeToString(contextDigest[:]) != expectedContext {
		t.Errorf("roundContextDigest changed:\n  got  %x\n  want %s", contextDigest, expectedContext)
	}

	var receipt RoundReceipt
	receipt.Context = ctx
	for index := range receipt.MixerPublic {
		receipt.MixerPublic[index] = byte(index + 0x10)
	}
	for index := range receipt.InputDigest {
		receipt.InputDigest[index] = byte(index + 0x20)
		receipt.OutputDigest[index] = byte(index + 0x30)
		receipt.ProofDigest[index] = byte(index + 0x40)
	}
	for index := range receipt.Signature {
		receipt.Signature[index] = byte(index + 0x50)
	}
	digest := receiptDigest(receipt)
	t.Logf("receiptDigest = %x", digest)
	const expectedReceipt = "0966c4a921956a853f681c206ac46503d3a888dbb1efe0c8f5a1cdd70cf65d16"
	if hex.EncodeToString(digest[:]) != expectedReceipt {
		t.Errorf("receiptDigest changed:\n  got  %x\n  want %s", digest, expectedReceipt)
	}

	var statement NonReceipt
	statement.Context = ctx
	statement.Deadline = 1234567
	for index := range statement.Accused {
		statement.Accused[index] = byte(index + 0x60)
		statement.Observer[index] = byte(index + 0x70)
	}
	message := nonReceiptSigningMessage(statement)
	t.Logf("nonReceiptSigningMessage = %x", message)
	const expectedNonReceipt = "cd2424e303d4d66c52f6dd8160f9ace440d7b4298c2ede67ccdd7e0631771f9e"
	if hex.EncodeToString(message) != expectedNonReceipt {
		t.Errorf("nonReceiptSigningMessage changed:\n  got  %x\n  want %s", message, expectedNonReceipt)
	}
}

// The binding has to be sensitive to every field it claims to bind. A digest
// that ignored the round would let a receipt from round 1 stand for round 2,
// which is the whole point of binding it.
func TestEveryBoundFieldChangesTheDigest(t *testing.T) {
	base := vectorContext()
	baseline := roundContextDigest(base)

	for _, scenario := range []struct {
		name   string
		change func(RoundContext) RoundContext
	}{
		{"committee", func(c RoundContext) RoundContext { c.CommitteeID[0] ^= 0xff; return c }},
		{"epoch", func(c RoundContext) RoundContext { c.Epoch++; return c }},
		{"batch", func(c RoundContext) RoundContext { c.BatchID[0] ^= 0xff; return c }},
		{"round", func(c RoundContext) RoundContext { c.Round++; return c }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if roundContextDigest(scenario.change(base)) == baseline {
				t.Fatalf("the round context digest ignores the %s it claims to bind",
					scenario.name)
			}
		})
	}

	// And the separator itself has to be in the preimage: two different
	// bindings over the same fields must not collide.
	var receipt RoundReceipt
	receipt.Context = base
	collision := receiptDigest(receipt)
	if collision == baseline {
		t.Fatal("the receipt digest and the round context digest collide")
	}
}

// The threshold proof domain binds the committee, the member and the batch. A
// proof that bound none of them would transfer between committees.
func TestTheThresholdProofDomainBindsItsCommitteeMemberAndBatch(t *testing.T) {
	committee := ThresholdCommittee{Threshold: 2, Epoch: 5}
	for index := range committee.ID {
		committee.ID[index] = byte(index)
	}
	for index := range committee.PublicKey {
		committee.PublicKey[index] = byte(index + 1)
	}
	member := PublicMember{Index: 1}
	for index := range member.Share {
		member.Share[index] = byte(index + 2)
	}
	var batchDigest [32]byte
	for index := range batchDigest {
		batchDigest[index] = byte(index + 3)
	}
	baseline := partialProofDomain(committee, member, batchDigest)
	if !strings.HasPrefix(baseline, thresholdProofLabel+":") {
		t.Fatalf("the proof domain lost its label: %q", baseline)
	}
	// Frozen, for the same reason as the digests above: the sensitivity
	// checks below are relative, and a relative check cannot see a changed
	// separator because it moves every value together.
	t.Logf("partialProofDomain = %s", baseline)
	const expectedDomain = "nomad-threshold-decryption-v1:4e73659cd115ffa68f1320579731ceb3bb6a97486c968a970d962537d6960a41"
	if baseline != expectedDomain {
		t.Errorf("partialProofDomain changed:\n  got  %s\n  want %s", baseline, expectedDomain)
	}

	for _, scenario := range []struct {
		name string
		call func() string
	}{
		{"committee identifier", func() string {
			other := committee
			other.ID[0] ^= 0xff
			return partialProofDomain(other, member, batchDigest)
		}},
		{"epoch", func() string {
			other := committee
			other.Epoch++
			return partialProofDomain(other, member, batchDigest)
		}},
		{"threshold", func() string {
			other := committee
			other.Threshold++
			return partialProofDomain(other, member, batchDigest)
		}},
		{"committee key", func() string {
			other := committee
			other.PublicKey[0] ^= 0xff
			return partialProofDomain(other, member, batchDigest)
		}},
		{"member index", func() string {
			other := member
			other.Index++
			return partialProofDomain(committee, other, batchDigest)
		}},
		{"member share", func() string {
			other := member
			other.Share[0] ^= 0xff
			return partialProofDomain(committee, other, batchDigest)
		}},
		{"batch", func() string {
			other := batchDigest
			other[0] ^= 0xff
			return partialProofDomain(committee, member, other)
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if scenario.call() == baseline {
				t.Fatalf("the threshold proof domain ignores the %s it claims to bind",
					scenario.name)
			}
		})
	}
}
