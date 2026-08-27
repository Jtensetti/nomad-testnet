package epoch

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	dkgnet "github.com/Jtensetti/nomad-testnet/live/dkg"
)

// TestRecoveryDrill executes the operator recovery runbook end to end:
// compromise, peer-quorum revocation, replacement through an emergency
// membership transition approved by the previous committee, durable erasure
// acknowledgement of retired material, and refusal to serve the retired epoch.
//
// It is protocol-level. It does not establish independent administration.
func TestRecoveryDrill(t *testing.T) {
	const compromised = 4
	outgoing := newNamedFixture(t, "drill-outgoing", 5)

	// --- Epoch 1: a healthy five-operator, 3-of-5 network. ---
	session1 := sha256.Sum256([]byte("drill-epoch-1"))
	topologyBytes1, network1 := outgoing.buildSignedTopology(t, 1, 3, genesisTimes(), session1, 10)
	certificateBytes1, secrets1 := outgoing.buildCertificate(t, network1)
	genesisEncoded, genesis := outgoing.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	chainRoot := t.TempDir()
	chain, err := OpenChain(chainRoot, "nomad-test", outgoing.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	serving := genesis.ActivateAt.Add(time.Minute)
	if err := chain.ServesEpoch(genesis.Epoch, serving); err != nil {
		t.Fatalf("drill precondition: epoch 1 must serve, got %v", err)
	}
	t.Log("step 1: epoch 1 active and serving")

	// --- Procedure 2: peer-quorum revocation of the compromised operator. ---
	revocation := Revocation{
		Version: RevocationVersion, NetworkID: genesis.NetworkID,
		OperatorID:    genesis.Topology.Document.Operators[compromised].ID,
		IdentityKey:   genesis.Topology.Document.Operators[compromised].IdentityKey,
		EpochObserved: genesis.Epoch, Reason: ReasonCompromise,
	}
	single, err := SignRevocation(revocation, genesis.Topology.Document.Operators[0].ID, outgoing.Operators[0].Identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRevocation(single, genesis); err == nil {
		t.Fatal("drill: one peer must not be able to revoke another operator")
	}
	quorumRevocation := single
	for _, index := range []int{1, 2} {
		quorumRevocation, err = SignRevocation(quorumRevocation, genesis.Topology.Document.Operators[index].ID, outgoing.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyRevocation(quorumRevocation, genesis); err != nil {
		t.Fatalf("drill: peer quorum must authorize revocation: %v", err)
	}
	encodedRevocation, err := EncodeRevocation(quorumRevocation)
	if err != nil {
		t.Fatal(err)
	}
	revocations, err := OpenRevocationStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := revocations.Accept(encodedRevocation, genesis); err != nil {
		t.Fatal(err)
	}
	t.Log("step 2: compromised operator revoked by peer quorum")

	// --- Procedure 3: replacement via emergency membership transition. ---
	replacement := newNamedFixture(t, "drill-replacement", 5)
	replacement.Operators[compromised].ID = "op-f"
	incoming := &fixture{AuthorityPublic: outgoing.AuthorityPublic, AuthorityPrivate: outgoing.AuthorityPrivate}
	incoming.Operators = append(incoming.Operators, outgoing.Operators[:compromised]...)
	incoming.Operators = append(incoming.Operators, replacement.Operators[compromised])

	emergency := epochTimes{
		NotBefore: fixtureBase.Add(20 * time.Minute),
		NotAfter:  fixtureBase.Add(12 * time.Hour),
		DKGStart:  fixtureBase.Add(22 * time.Minute),
		Activate:  fixtureBase.Add(1 * time.Hour),
		Retire:    fixtureBase.Add(6 * time.Hour),
	}
	session2 := sha256.Sum256([]byte("drill-epoch-2"))
	topologyBytes2, network2 := incoming.buildSignedTopology(t, 2, 3, emergency, session2, 30)
	certificateBytes2, _ := incoming.buildCertificate(t, network2)

	successor, err := New(&genesis, TransitionEmergency, canonicalTime(emergency.Activate), canonicalTime(emergency.Retire), topologyBytes2, certificateBytes2)
	if err != nil {
		t.Fatal(err)
	}
	tainted, err := signApproval(successor, genesis, genesis.Topology.Document.Operators[compromised], outgoing.Operators[compromised].Identity)
	if err != nil {
		t.Fatal(err)
	}
	taintedDescriptor := successor
	taintedDescriptor.Approvals = []Approval{tainted}
	for index, member := range network2.Document.Operators {
		activation, err := signActivation(taintedDescriptor, member, incoming.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		taintedDescriptor.Activations = append(taintedDescriptor.Activations, activation)
	}
	if _, err := Verify(reencode(t, taintedDescriptor), outgoing.AuthorityPublic, &genesis, revocations.Set()); err == nil {
		t.Fatal("drill: a revoked operator must not authorize a transition")
	}

	for _, index := range []int{0, 1, 2} {
		approval, err := signApproval(successor, genesis, genesis.Topology.Document.Operators[index], outgoing.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		successor.Approvals = append(successor.Approvals, approval)
	}
	for index, member := range network2.Document.Operators {
		journal, err := OpenJournal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		activation, err := journal.activateWithJournalUnchecked(successor, member, incoming.Operators[index].Identity)
		if err != nil {
			t.Fatal(err)
		}
		successor.Activations = append(successor.Activations, activation)
	}
	successorEncoded := reencode(t, successor)
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatalf("drill: the approved successor must be admitted: %v", err)
	}
	t.Log("step 3: replacement operator activated via emergency transition")

	// --- The retired epoch stops being served at the emergency boundary. ---
	probe := emergency.Activate.Add(time.Minute)
	if err := chain.ServesEpoch(genesis.Epoch, probe); err == nil {
		t.Fatal("drill: the retired epoch must no longer be served")
	}
	if err := chain.ServesEpoch(2, probe); err != nil {
		t.Fatalf("drill: the new epoch must serve: %v", err)
	}
	policy := Policy{PrepareLead: time.Hour, RetryOffsets: []time.Duration{20 * time.Minute}, EscalateAfter: 40 * time.Minute}
	outgoingPlan, err := chain.PlanAtForOperator(probe, policy, genesis.Topology.Document.Operators[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if outgoingPlan.Action != ActionRetire || outgoingPlan.Epoch != genesis.Epoch {
		t.Fatalf("drill: outgoing member must retire epoch 1 material, got %+v", outgoingPlan)
	}
	incomingReplacementID := network2.Document.Operators[compromised].ID
	replacementPlan, err := chain.PlanAtForOperator(probe, policy, incomingReplacementID)
	if err != nil {
		t.Fatal(err)
	}
	if replacementPlan.Action == ActionRetire && replacementPlan.Epoch == genesis.Epoch {
		t.Fatal("drill: replacement was asked to erase an epoch for which it never held material")
	}
	t.Log("step 4: retired epoch refused; only actual epoch-1 members owe retirement acknowledgements")

	// --- Procedure 5: transactionally erase and acknowledge retired material. ---
	directory := t.TempDir()
	sharePaths := make([]string, 0, len(secrets1))
	for index, secret := range secrets1 {
		share := committee.ShareFromSecret(secret, genesis.Topology.Document.Operators[index], genesis.Topology)
		encoded, err := committee.EncodeShare(share)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "share-"+genesis.Topology.Document.Operators[index].ID+".json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		sharePaths = append(sharePaths, path)
	}
	for index, path := range sharePaths {
		operatorID := genesis.Topology.Document.Operators[index].ID
		intent, err := NewErasureIntent(genesis, operatorID, []string{path}, "tmpfs", outgoing.Operators[index].Identity, probe)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := ExecuteErasureIntent(intent, genesis, outgoing.Operators[index].Identity, probe.Add(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyErasureStatement(statement, genesis); err != nil {
			t.Fatalf("drill: erasure statement must verify: %v", err)
		}
		if err := chain.RecordErasureStatement(statement, operatorID); err != nil {
			t.Fatalf("drill: erasure acknowledgement must persist: %v", err)
		}
		if recorded, err := chain.ErasureRecorded(genesis.Epoch, operatorID); err != nil || !recorded {
			t.Fatalf("drill: operator %s retirement ack missing: recorded=%v err=%v", operatorID, recorded, err)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("drill: retired material must not remain, found %d files", len(entries))
	}
	postAckPlan, err := chain.PlanAtForOperator(probe.Add(2*time.Second), policy, genesis.Topology.Document.Operators[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if postAckPlan.Action == ActionRetire && postAckPlan.Epoch == genesis.Epoch {
		t.Fatalf("drill: acknowledged retirement still blocks lifecycle: %+v", postAckPlan)
	}
	t.Log("step 5: retired material erased and durably acknowledged")

	// --- Procedure 1: an interrupted ceremony never resumes. ---
	stateDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(stateDirectory, "RUNNING"), []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := dkgnet.NewStore(stateDirectory, genesis.Topology); err == nil {
		t.Fatal("drill: an interrupted ceremony directory must refuse a fresh session")
	}
	t.Log("step 6: interrupted ceremony refuses to resume")
}
