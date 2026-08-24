package epoch

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
)

func TestGenesisAndScheduledTransitionVerify(t *testing.T) {
	_, _, genesis, _, successor := buildTwoEpochChain(t)
	if genesis.Epoch != 1 || successor.Epoch != 2 {
		t.Fatalf("unexpected epochs %d and %d", genesis.Epoch, successor.Epoch)
	}
	if successor.Descriptor.PreviousEpochDigest != hex.EncodeToString(genesis.Digest[:]) {
		t.Fatal("successor does not chain to genesis digest")
	}
	if state := genesis.stateAtIgnoringSuccessors(genesis.ActivateAt.Add(-time.Second)); state != StateReady {
		t.Fatalf("expected READY before activation, got %s", state)
	}
	if state := genesis.stateAtIgnoringSuccessors(genesis.ActivateAt); state != StateActive {
		t.Fatalf("expected ACTIVE at boundary, got %s", state)
	}
	if state := genesis.stateAtIgnoringSuccessors(genesis.RetireAt); state != StateRetired {
		t.Fatalf("expected RETIRED at retirement, got %s", state)
	}
	if !successor.ActivateAt.Equal(genesis.RetireAt) {
		t.Fatal("scheduled successor must activate exactly at genesis retirement")
	}
}

func TestDigestExcludesSignaturesAndPinsContent(t *testing.T) {
	_, _, _, _, successor := buildTwoEpochChain(t)
	unsigned := successor.Descriptor
	unsigned.Approvals = nil
	unsigned.Activations = nil
	unsignedDigest, err := Digest(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if unsignedDigest != successor.Digest {
		t.Fatal("descriptor digest must exclude approvals and activations")
	}
	mutated := unsigned
	mutated.RetireAt = canonicalTime(successor.RetireAt.Add(time.Second))
	mutatedDigest, err := Digest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedDigest == successor.Digest {
		t.Fatal("descriptor digest must change when content changes")
	}
}

func requireVerifyFailure(t *testing.T, encoded []byte, f *fixture, previous *Verified, revoked RevocationSet, fragment string) {
	t.Helper()
	if _, err := Verify(encoded, f.AuthorityPublic, previous, revoked); err == nil {
		t.Fatalf("expected verification failure containing %q", fragment)
	} else if fragment != "" && !strings.Contains(err.Error(), fragment) {
		t.Fatalf("expected error containing %q, got %v", fragment, err)
	}
}

func reencode(t *testing.T, descriptor Descriptor) []byte {
	t.Helper()
	encoded, err := Encode(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestVerifyRejectsInsufficientApprovals(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	descriptor.Approvals = descriptor.Approvals[:ApprovalQuorum(genesis)-1]
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "previous-epoch approvals")
}

func TestVerifyRejectsDuplicateApprovals(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	descriptor.Approvals = []Approval{descriptor.Approvals[0], descriptor.Approvals[0]}
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "duplicate")
}

func TestVerifyRejectsWrongPreviousDigest(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	wrong := sha256.Sum256([]byte("wrong-chain"))
	descriptor.PreviousEpochDigest = hex.EncodeToString(wrong[:])
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "chain")
}

func TestVerifyRejectsEpochSkip(t *testing.T) {
	f := newFixture(t, 3)
	session1 := sha256.Sum256([]byte("skip-session-1"))
	topologyBytes1, network1 := f.buildSignedTopology(t, 1, 2, genesisTimes(), session1, 10)
	certificateBytes1, _ := f.buildCertificate(t, network1)
	_, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	session3 := sha256.Sum256([]byte("skip-session-3"))
	topologyBytes3, network3 := f.buildSignedTopology(t, 3, 2, successorTimes(), session3, 30)
	certificateBytes3, _ := f.buildCertificate(t, network3)
	descriptor, err := New(&genesis, TransitionScheduled, canonicalTime(successorTimes().Activate), canonicalTime(successorTimes().Retire), topologyBytes3, certificateBytes3)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < ApprovalQuorum(genesis); index++ {
		operator, _ := genesis.Topology.Operator(uint16(index))
		approval, err := signApproval(descriptor, genesis, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Approvals = append(descriptor.Approvals, approval)
	}
	for index, operator := range network3.Document.Operators {
		activation, err := signActivation(descriptor, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "increase by exactly one")
}

func TestVerifyRejectsTransplantedActivation(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	// Activation signatures from the genesis descriptor target a different
	// digest; splicing them into the successor must fail even though the
	// signing identities are the same operators.
	descriptor := successor.Descriptor
	descriptor.Activations = genesis.Descriptor.Activations
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "activation")
}

func TestVerifyRejectsTransplantedApproval(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	// Build a second, distinct successor candidate and steal its approvals.
	session := sha256.Sum256([]byte("transplant-session"))
	times := successorTimes()
	times.Retire = times.Retire.Add(time.Hour)
	topologyBytes, network := f.buildSignedTopology(t, 2, 2, times, session, 50)
	certificateBytes, _ := f.buildCertificate(t, network)
	other, err := New(&genesis, TransitionScheduled, canonicalTime(times.Activate), canonicalTime(times.Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := genesis.Topology.Operator(0)
	otherApproval, err := signApproval(other, genesis, operator, f.Operators[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := successor.Descriptor
	descriptor.Approvals = append([]Approval{otherApproval}, descriptor.Approvals[1:]...)
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "approval")
}

func TestVerifyRejectsMissingActivation(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	descriptor.Activations = descriptor.Activations[:len(descriptor.Activations)-1]
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "every configured operator")
}

func TestVerifyRejectsScheduledBoundaryMismatch(t *testing.T) {
	f, _, genesis, _, _ := buildTwoEpochChain(t)
	times := successorTimes()
	times.Activate = times.Activate.Add(time.Minute)
	session := sha256.Sum256([]byte("boundary-session"))
	topologyBytes, network := f.buildSignedTopology(t, 2, 2, times, session, 60)
	certificateBytes, _ := f.buildCertificate(t, network)
	descriptor, err := New(&genesis, TransitionScheduled, canonicalTime(times.Activate), canonicalTime(times.Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < ApprovalQuorum(genesis); index++ {
		operator, _ := genesis.Topology.Operator(uint16(index))
		approval, err := signApproval(descriptor, genesis, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Approvals = append(descriptor.Approvals, approval)
	}
	for index, operator := range network.Document.Operators {
		activation, err := signActivation(descriptor, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "exactly at the previous retirement")
}

func TestVerifyRejectsTamperedEmbeddedTopology(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	raw, err := base64.StdEncoding.DecodeString(descriptor.Topology)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(raw), "nomad-test", "nomad-fake", 1))
	descriptor.Topology = base64.StdEncoding.EncodeToString(tampered)
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "")
}

func TestVerifyRejectsNonCanonicalTime(t *testing.T) {
	_, _, _, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	descriptor.ActivateAt = successor.ActivateAt.In(time.FixedZone("plus1", 3600)).Format(time.RFC3339)
	if _, err := Digest(descriptor); err == nil {
		t.Fatal("non-UTC time must be rejected as non-canonical")
	}
}

func TestVerifyRejectsRevokedApproverAndMember(t *testing.T) {
	f, _, genesis, successorEncoded, _ := buildTwoEpochChain(t)
	revokedApprover := RevocationSet{genesis.Topology.Document.Operators[0].IdentityKey: {}}
	requireVerifyFailure(t, successorEncoded, f, &genesis, revokedApprover, "revoked")
	if _, err := Verify(successorEncoded, f.AuthorityPublic, &genesis, RevocationSet{genesis.Topology.Document.Operators[2].IdentityKey: {}}); err == nil {
		t.Fatal("a revoked identity in the operator set must fail verification")
	}
}

func TestVerifyRejectsNonEmptyUplinkProfile(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	descriptor := successor.Descriptor
	descriptor.UplinkProfile = base64.StdEncoding.EncodeToString([]byte("v0"))
	requireVerifyFailure(t, reencode(t, descriptor), f, &genesis, nil, "uplink")
}

func TestVerifyRejectsActivationBeforeDKGCompletion(t *testing.T) {
	f := newFixture(t, 3)
	times := genesisTimes()
	times.Activate = times.DKGStart.Add(time.Second)
	session := sha256.Sum256([]byte("early-activation"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, times, session, 70)
	certificateBytes, _ := f.buildCertificate(t, network)
	descriptor, err := New(nil, TransitionGenesis, canonicalTime(times.Activate), canonicalTime(times.Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	for index, operator := range network.Document.Operators {
		activation, err := signActivation(descriptor, operator, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	requireVerifyFailure(t, reencode(t, descriptor), f, nil, nil, "DKG schedule")
}

func TestFiveOperatorThresholdProfile(t *testing.T) {
	f := newFixture(t, 5)
	session := sha256.Sum256([]byte("five-operator-session"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 3, genesisTimes(), session, 80)
	certificateBytes, secrets := f.buildCertificate(t, network)
	_, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)
	if got := ApprovalQuorum(genesis); got != 3 {
		t.Fatalf("expected 3-of-5 approval quorum, got %d", got)
	}

	payload := make([]byte, mix.PlainCellSize)
	copy(payload, "five-operator threshold profile probe")
	var cell mix.PlainCell
	copy(cell[:], payload)
	batch, err := mix.Encrypt(genesis.Certificate.Committee.PublicKey, []mix.PlainCell{cell, cell})
	if err != nil {
		t.Fatal(err)
	}
	partials := make([]*mix.PartialDecryption, 0, 3)
	for index := 0; index < 3; index++ {
		partial, err := mix.CreatePartialDecryption(genesis.Certificate.Committee, secrets[index], batch)
		if err != nil {
			t.Fatal(err)
		}
		partials = append(partials, partial)
	}
	if _, err := mix.ThresholdDecrypt(genesis.Certificate.Committee, batch, partials[:2]); err == nil {
		t.Fatal("two partial decryptions must not satisfy a 3-of-5 committee")
	}
	decrypted, err := mix.ThresholdDecrypt(genesis.Certificate.Committee, batch, partials)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted[0][:len("five-operator threshold profile probe")]) != "five-operator threshold profile probe" {
		t.Fatal("threshold decryption did not recover the payload")
	}
}

func TestCrossEpochShareRejected(t *testing.T) {
	f, _, genesis, _, successor := buildTwoEpochChain(t)
	_ = f
	// Recompute genesis-epoch member secrets is impossible from the
	// descriptor alone; instead run a fresh DKG for the genesis topology and
	// try to use its secret against the successor committee.
	_, genesisSecrets := f.buildCertificate(t, genesis.Topology)
	var cell mix.PlainCell
	copy(cell[:], "cross-epoch probe")
	batch, err := mix.Encrypt(successor.Certificate.Committee.PublicKey, []mix.PlainCell{cell, cell})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mix.CreatePartialDecryption(successor.Certificate.Committee, genesisSecrets[0], batch); err == nil {
		t.Fatal("a share from another epoch's committee must be rejected")
	}
}

// TestApprovalQuorumCannotBeForgedByOneOperator is the regression for a
// confirmed exploit: Approval.Index is attacker-chosen and was narrowed to
// uint16 for lookup while being deduplicated on the full uint32, so indices
// i, i+65536, i+131072 all resolved to one operator and were counted as
// three distinct approvers. Because the approval message committed to
// nothing about the approver, a single signature was reusable in every
// slot, letting one previous-epoch operator mint a whole quorum and force a
// membership change alone.
func TestApprovalQuorumCannotBeForgedByOneOperator(t *testing.T) {
	f := newFixture(t, 5)
	session1 := sha256.Sum256([]byte("quorum-forgery-1"))
	topologyBytes1, network1 := f.buildSignedTopology(t, 1, 3, genesisTimes(), session1, 10)
	certificateBytes1, _ := f.buildCertificate(t, network1)
	_, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)
	if got := ApprovalQuorum(genesis); got != 3 {
		t.Fatalf("expected a 3-of-5 quorum, got %d", got)
	}

	session2 := sha256.Sum256([]byte("quorum-forgery-2"))
	topologyBytes2, network2 := f.buildSignedTopology(t, 2, 3, successorTimes(), session2, 30)
	certificateBytes2, _ := f.buildCertificate(t, network2)
	descriptor, err := New(&genesis, TransitionScheduled, canonicalTime(successorTimes().Activate), canonicalTime(successorTimes().Retire), topologyBytes2, certificateBytes2)
	if err != nil {
		t.Fatal(err)
	}
	// One cooperating operator produces its single legitimate approval.
	operator, err := genesis.Topology.Operator(1)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := signApproval(descriptor, genesis, operator, f.Operators[1].Identity)
	if err != nil {
		t.Fatal(err)
	}
	// It is then replayed into aliasing index slots to claim a full quorum.
	descriptor.Approvals = []Approval{
		approval,
		{OperatorID: approval.OperatorID, Index: approval.Index + 1<<16, Signature: approval.Signature},
		{OperatorID: approval.OperatorID, Index: approval.Index + 2<<16, Signature: approval.Signature},
	}
	for index, member := range network2.Document.Operators {
		activation, err := signActivation(descriptor, member, f.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.Activations = append(descriptor.Activations, activation)
	}
	if _, err := Verify(reencode(t, descriptor), f.AuthorityPublic, &genesis, nil); err == nil {
		t.Fatal("a single operator must not be able to satisfy the approval quorum")
	}

	// The same replay without index aliasing must also fail: an approval
	// signature is bound to its approver's identity key.
	stolen := descriptor
	other, err := genesis.Topology.Operator(2)
	if err != nil {
		t.Fatal(err)
	}
	stolen.Approvals = []Approval{
		approval,
		{OperatorID: other.ID, Index: 2, Signature: approval.Signature},
		{OperatorID: network2.Document.Operators[3].ID, Index: 3, Signature: approval.Signature},
	}
	if _, err := Verify(reencode(t, stolen), f.AuthorityPublic, &genesis, nil); err == nil {
		t.Fatal("an approval signature must not verify for a different approver")
	}
}

// TestMembershipTransitionRequiresPreviousCommittee exercises a real
// membership change (A B C D E -> A B C D F) rather than reusing one
// operator set for both epochs, and checks that authority to make it comes
// from the previous committee, not from the incoming one.
func TestMembershipTransitionRequiresPreviousCommittee(t *testing.T) {
	outgoing := newNamedFixture(t, "outgoing", 5)
	session1 := sha256.Sum256([]byte("membership-1"))
	topologyBytes1, network1 := outgoing.buildSignedTopology(t, 1, 3, genesisTimes(), session1, 10)
	certificateBytes1, _ := outgoing.buildCertificate(t, network1)
	_, genesis := outgoing.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	// Epoch 2 keeps four operators and replaces the fifth with a newcomer
	// holding genuinely different keys.
	replacement := newNamedFixture(t, "replacement", 5)
	replacement.Operators[4].ID = "op-f"
	incoming := &fixture{AuthorityPublic: outgoing.AuthorityPublic, AuthorityPrivate: outgoing.AuthorityPrivate}
	incoming.Operators = append(incoming.Operators, outgoing.Operators[:4]...)
	incoming.Operators = append(incoming.Operators, replacement.Operators[4])
	session2 := sha256.Sum256([]byte("membership-2"))
	topologyBytes2, network2 := incoming.buildSignedTopology(t, 2, 3, successorTimes(), session2, 30)
	certificateBytes2, _ := incoming.buildCertificate(t, network2)

	build := func(approvers []int, signWith *fixture) []byte {
		descriptor, err := New(&genesis, TransitionScheduled, canonicalTime(successorTimes().Activate), canonicalTime(successorTimes().Retire), topologyBytes2, certificateBytes2)
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range approvers {
			operator, err := genesis.Topology.Operator(uint16(index))
			if err != nil {
				t.Fatal(err)
			}
			approval, err := signApproval(descriptor, genesis, operator, signWith.Operators[index].Identity)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Approvals = append(descriptor.Approvals, approval)
		}
		for index, member := range network2.Document.Operators {
			activation, err := signActivation(descriptor, member, incoming.Operators[index].Identity)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.Activations = append(descriptor.Activations, activation)
		}
		return reencode(t, descriptor)
	}

	// Two approvals is below the 3-of-5 quorum.
	if _, err := Verify(build([]int{0, 1}, outgoing), outgoing.AuthorityPublic, &genesis, nil); err == nil {
		t.Fatal("a membership change below quorum must be rejected")
	}
	// Three approvals from the outgoing committee authorize the change.
	verified, err := Verify(build([]int{0, 1, 2}, outgoing), outgoing.AuthorityPublic, &genesis, nil)
	if err != nil {
		t.Fatalf("a quorum of the previous committee must authorize the change: %v", err)
	}
	if verified.Topology.Document.Operators[4].IdentityKey == genesis.Topology.Document.Operators[4].IdentityKey {
		t.Fatal("fixture did not actually change membership")
	}
}
