package epoch

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testRotationPolicy() Policy {
	return Policy{PrepareLead: 30 * time.Minute, RetryOffsets: []time.Duration{10 * time.Minute}, EscalateAfter: 20 * time.Minute}
}

func TestOperatorPlannerCannotSkipScheduledPredecessorRetirement(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, successor := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}
	operatorID := genesis.Topology.Document.Operators[0].ID
	atBoundary := successor.ActivateAt
	plan, err := chain.PlanAtForOperator(atBoundary, testRotationPolicy(), operatorID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != ActionRetire || plan.Epoch != genesis.Epoch || !plan.DueAt.Equal(genesis.RetireAt) {
		t.Fatalf("scheduled successor skipped predecessor retirement: %+v", plan)
	}

	private := filepath.Join(t.TempDir(), "epoch-1-share.json")
	if err := os.WriteFile(private, []byte("private epoch one material"), 0o600); err != nil {
		t.Fatal(err)
	}
	intent, err := NewErasureIntent(genesis, operatorID, []string{private}, "tmpfs", f.Operators[0].Identity, atBoundary)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := ExecuteErasureIntent(intent, genesis, f.Operators[0].Identity, atBoundary)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.RecordErasureStatement(statement, operatorID); err != nil {
		t.Fatal(err)
	}
	plan, err = chain.PlanAtForOperator(atBoundary, testRotationPolicy(), operatorID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action == ActionRetire && plan.Epoch == genesis.Epoch {
		t.Fatalf("durably acknowledged predecessor remained stuck in RETIRE: %+v", plan)
	}
	// Another operator must not inherit operator 0's local acknowledgement.
	otherID := genesis.Topology.Document.Operators[1].ID
	otherPlan, err := chain.PlanAtForOperator(atBoundary, testRotationPolicy(), otherID)
	if err != nil {
		t.Fatal(err)
	}
	if otherPlan.Action != ActionRetire || otherPlan.Epoch != genesis.Epoch {
		t.Fatalf("one operator's acknowledgement satisfied another operator: %+v", otherPlan)
	}
}

func TestOperatorPlannerCannotSkipEmergencyPredecessorRetirement(t *testing.T) {
	f := newFixture(t, 3)
	session1 := sha256.Sum256([]byte("retirement-emergency-one"))
	topologyBytes1, network1 := f.buildSignedTopology(t, 1, 2, genesisTimes(), session1, 10)
	certificateBytes1, _ := f.buildCertificate(t, network1)
	genesisEncoded, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	times := epochTimes{
		NotBefore: fixtureBase.Add(20 * time.Minute),
		NotAfter:  fixtureBase.Add(12 * time.Hour),
		DKGStart:  fixtureBase.Add(22 * time.Minute),
		Activate:  fixtureBase.Add(time.Hour),
		Retire:    fixtureBase.Add(3 * time.Hour),
	}
	session2 := sha256.Sum256([]byte("retirement-emergency-two"))
	topologyBytes2, network2 := f.buildSignedTopology(t, 2, 2, times, session2, 30)
	certificateBytes2, _ := f.buildCertificate(t, network2)
	successorEncoded, successor := f.buildDescriptor(t, &genesis, f, TransitionEmergency, times, network2, topologyBytes2, certificateBytes2)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}
	operatorID := genesis.Topology.Document.Operators[0].ID
	plan, err := chain.PlanAtForOperator(successor.ActivateAt, testRotationPolicy(), operatorID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Action != ActionRetire || plan.Epoch != genesis.Epoch || !plan.DueAt.Equal(successor.ActivateAt) {
		t.Fatalf("emergency activation did not trigger immediate predecessor retirement: %+v", plan)
	}
}

func TestErasureIntentResumesWithOriginalDigestsAfterPartialCrash(t *testing.T) {
	f := newFixture(t, 3)
	_, genesis, _, _ := buildGenesis(t, f, 3, 2, "resumable-erasure")
	directory := t.TempDir()
	first := filepath.Join(directory, "share.json")
	second := filepath.Join(directory, "dkg-journal.json")
	firstBytes := []byte("first private artifact")
	secondBytes := []byte("second private artifact")
	if err := os.WriteFile(first, firstBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, secondBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorID := genesis.Topology.Document.Operators[0].ID
	intent, err := NewErasureIntent(genesis, operatorID, []string{first, second}, "tmpfs", f.Operators[0].Identity, genesis.RetireAt)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a process dying after the first destructive step completed but
	// before a statement was written.
	if _, err := eraseOne(first); err != nil {
		t.Fatal(err)
	}
	statement, err := ExecuteErasureIntent(intent, genesis, f.Operators[0].Identity, genesis.RetireAt.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(second); !os.IsNotExist(err) {
		t.Fatal("resume did not finish erasing the remaining artifact")
	}
	firstDigest := sha256.Sum256(firstBytes)
	secondDigest := sha256.Sum256(secondBytes)
	digests := map[string]string{}
	for _, record := range statement.Files {
		digests[record.Path] = record.Digest
	}
	if digests[first] != hex.EncodeToString(firstDigest[:]) || digests[second] != hex.EncodeToString(secondDigest[:]) {
		t.Fatalf("resume lost the original pre-erasure digests: %#v", digests)
	}
	if err := VerifyErasureStatement(statement, genesis); err != nil {
		t.Fatalf("resumed statement must verify: %v", err)
	}
}

func TestErasureIntentFailsClosedIfRemainingFileChanges(t *testing.T) {
	f := newFixture(t, 3)
	_, genesis, _, _ := buildGenesis(t, f, 3, 2, "tampered-erasure")
	path := filepath.Join(t.TempDir(), "share.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorID := genesis.Topology.Document.Operators[0].ID
	intent, err := NewErasureIntent(genesis, operatorID, []string{path}, "tmpfs", f.Operators[0].Identity, genesis.RetireAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecuteErasureIntent(intent, genesis, f.Operators[0].Identity, genesis.RetireAt.Add(time.Second)); err == nil {
		t.Fatal("changed private material must not be erased under stale prepared metadata")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("fail-closed path unexpectedly removed the changed file")
	}
}
