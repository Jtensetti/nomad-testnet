package epoch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFreshGuardObservesSuccessorWrittenByAnotherProcess(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, successor := buildTwoEpochChain(t)
	root := t.TempDir()

	servingProcess, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := servingProcess.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	guard := FreshGuard{Chain: servingProcess}
	if err := guard.ServesEpoch(genesis.Epoch, genesis.ActivateAt.Add(time.Minute)); err != nil {
		t.Fatalf("genesis should initially serve: %v", err)
	}

	// Model the lifecycle/coordinator as a separate process sharing only the
	// persisted chain directory. It appends the already-verified successor;
	// the long-running share process must observe that without restart.
	lifecycleProcess, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleProcess.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}

	if err := guard.ServesEpoch(genesis.Epoch, successor.ActivateAt); err == nil {
		t.Fatal("a running service must stop serving the predecessor when the successor activates")
	}
	if err := guard.ServesEpoch(successor.Epoch, successor.ActivateAt); err != nil {
		t.Fatalf("the successor should serve at its public activation boundary: %v", err)
	}
}

func TestFreshGuardObservesEmergencyRetirement(t *testing.T) {
	f := newFixture(t, 3)
	session1 := sha256Sum("c2-emergency-1")
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
	session2 := sha256Sum("c2-emergency-2")
	topologyBytes2, network2 := f.buildSignedTopology(t, 2, 2, times, session2, 30)
	certificateBytes2, _ := f.buildCertificate(t, network2)
	successorEncoded, successor := f.buildDescriptor(t, &genesis, f, TransitionEmergency, times, network2, topologyBytes2, certificateBytes2)

	root := t.TempDir()
	first, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	second, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}
	if !successor.ActivateAt.Before(genesis.RetireAt) {
		t.Fatal("fixture must actually exercise early emergency retirement")
	}
	state, err := first.FreshStateOf(genesis.Epoch, successor.ActivateAt)
	if err != nil {
		t.Fatal(err)
	}
	if state != StateRetired {
		t.Fatalf("emergency successor must retire predecessor immediately, got %s", state)
	}
}

func TestDurableErasureRefusesWrongOperatorBeforeDestroyingAnything(t *testing.T) {
	f := newFixture(t, 3)
	_, genesis, _, _ := buildGenesis(t, f, 3, 2, "c2-erasure-identity")
	path := filepath.Join(t.TempDir(), "threshold-share.json")
	original := []byte("private-share-must-survive-a-rejected-erasure")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	operator0 := genesis.Topology.Document.Operators[0]
	_, err := EraseEpochMaterialDurable(
		genesis.NetworkID,
		operator0.ID,
		genesis,
		[]string{path},
		"tmpfs",
		f.Operators[1].Identity, // deliberately the wrong operator
		fixtureBase,
	)
	if err == nil {
		t.Fatal("wrong operator identity must be rejected before any destruction")
	}
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("rejected erasure destroyed the file: %v", readErr)
	}
	if string(contents) != string(original) {
		t.Fatal("rejected erasure changed file contents")
	}
}

func TestFreshEpochPreservesSuccessorChainContext(t *testing.T) {
	f, genesisEncoded, _, successorEncoded, successor := buildTwoEpochChain(t)
	root := t.TempDir()
	chain, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := chain.FreshEpoch(successor.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || loaded.Digest != successor.Digest {
		t.Fatal("operator tooling must retrieve the verified successor rather than reverify it as genesis")
	}
}

func sha256Sum(label string) [32]byte {
	return sha256.Sum256([]byte(label))
}
