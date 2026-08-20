package epoch

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestChainAppendActivateRetireAndReopen(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, successor := buildTwoEpochChain(t)
	root := t.TempDir()
	chain, err := OpenChain(root, f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}

	if _, active := chain.ActiveAt(genesis.ActivateAt.Add(-time.Second)); active {
		t.Fatal("nothing may be active before the genesis boundary")
	}
	if current, active := chain.ActiveAt(genesis.ActivateAt); !active || current.Epoch != 1 {
		t.Fatal("genesis must be active at its boundary")
	}
	if current, active := chain.ActiveAt(successor.ActivateAt); !active || current.Epoch != 2 {
		t.Fatal("successor must take over exactly at the retirement boundary")
	}
	if _, active := chain.ActiveAt(successor.RetireAt); active {
		t.Fatal("nothing may be active after the final retirement without a successor")
	}
	if state, err := chain.StateOf(1, successor.ActivateAt); err != nil || state != StateRetired {
		t.Fatalf("genesis must be RETIRED once the successor activates, got %v %v", state, err)
	}
	if highest := chain.HighestRetired(successor.ActivateAt); highest != 1 {
		t.Fatalf("expected highest retired epoch 1, got %d", highest)
	}

	reopened, err := OpenChain(root, f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tip, ok := reopened.Tip(); !ok || tip.Epoch != 2 {
		t.Fatal("reopened chain lost its tip")
	}

	// Idempotent re-append of stored bytes.
	if verified, err := reopened.Append(genesisEncoded); err != nil || verified.Epoch != 1 {
		t.Fatalf("identical re-append must be idempotent, got %v", err)
	}
}

func TestChainInvalidConflictCannotHalt(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	// A competing genesis whose activation signatures are stripped is not a
	// valid descriptor; it must be rejected without halting the chain.
	forged := genesis.Descriptor
	forged.RetireAt = canonicalTime(genesis.RetireAt.Add(time.Hour))
	forged.Activations = nil
	forgedEncoded, err := Encode(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(forgedEncoded); err == nil {
		t.Fatal("invalid conflicting descriptor must be rejected")
	} else if errors.Is(err, ErrEquivocation) {
		t.Fatal("invalid bytes must not count as equivocation")
	}
	if chain.Halted() {
		t.Fatal("invalid conflicting bytes must not halt the chain")
	}
	if _, active := chain.ActiveAt(genesis.ActivateAt); !active {
		t.Fatal("chain must remain live after rejecting an invalid conflict")
	}
}

func TestChainHaltsOnValidEquivocation(t *testing.T) {
	f := newFixture(t, 3)
	session := sha256.Sum256([]byte("equivocation-session"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, genesisTimes(), session, 10)
	certificateBytes, _ := f.buildCertificate(t, network)
	firstEncoded, first := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)

	// A second fully valid genesis for the same epoch with a different
	// retirement boundary: the authority and all operators equivocated.
	times := genesisTimes()
	times.Retire = times.Retire.Add(time.Hour)
	secondEncoded, second := f.buildDescriptor(t, nil, nil, TransitionGenesis, times, network, topologyBytes, certificateBytes)
	if first.Digest == second.Digest {
		t.Fatal("fixture must produce distinct digests")
	}

	root := t.TempDir()
	chain, err := OpenChain(root, f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(firstEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(secondEncoded); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected equivocation, got %v", err)
	}
	if !chain.Halted() {
		t.Fatal("chain must halt on recorded equivocation")
	}
	if _, err := chain.Append(firstEncoded); !errors.Is(err, ErrHalted) {
		t.Fatal("halted chain must refuse further appends")
	}
	if _, active := chain.ActiveAt(first.ActivateAt); active {
		t.Fatal("halted chain must not report an active epoch")
	}
	reopened, err := OpenChain(root, f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Halted() {
		t.Fatal("halt must survive reopening")
	}
}

func TestChainEmergencyRetiresPredecessor(t *testing.T) {
	f := newFixture(t, 3)
	session1 := sha256.Sum256([]byte("emergency-session-1"))
	topologyBytes1, network1 := f.buildSignedTopology(t, 1, 2, genesisTimes(), session1, 10)
	certificateBytes1, _ := f.buildCertificate(t, network1)
	genesisEncoded, genesis := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network1, topologyBytes1, certificateBytes1)

	times := epochTimes{
		NotBefore: fixtureBase.Add(20 * time.Minute),
		NotAfter:  fixtureBase.Add(12 * time.Hour),
		DKGStart:  fixtureBase.Add(22 * time.Minute),
		Activate:  fixtureBase.Add(1 * time.Hour),
		Retire:    fixtureBase.Add(3 * time.Hour),
	}
	session2 := sha256.Sum256([]byte("emergency-session-2"))
	topologyBytes2, network2 := f.buildSignedTopology(t, 2, 2, times, session2, 30)
	certificateBytes2, _ := f.buildCertificate(t, network2)
	successorEncoded, successor := f.buildDescriptor(t, &genesis, f, TransitionEmergency, times, network2, topologyBytes2, certificateBytes2)
	if !successor.ActivateAt.Before(genesis.RetireAt) {
		t.Fatal("fixture emergency must activate before scheduled retirement")
	}

	chain, err := OpenChain(t.TempDir(), f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); err != nil {
		t.Fatal(err)
	}
	probe := successor.ActivateAt.Add(time.Minute)
	if current, active := chain.ActiveAt(probe); !active || current.Epoch != 2 {
		t.Fatal("emergency successor must be the single active epoch")
	}
	if state, err := chain.StateOf(1, probe); err != nil || state != StateRetired {
		t.Fatalf("predecessor must be RETIRED under an active emergency successor, got %v %v", state, err)
	}
}

func TestJournalRefusesSecondDigest(t *testing.T) {
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := sha256.Sum256([]byte("descriptor-one"))
	second := sha256.Sum256([]byte("descriptor-two"))
	if err := journal.Record("nomad-test", 7, first); err != nil {
		t.Fatal(err)
	}
	if err := journal.Record("nomad-test", 7, first); err != nil {
		t.Fatal("identical record must be idempotent")
	}
	if err := journal.Record("nomad-test", 7, second); !errors.Is(err, ErrConflictingSignature) {
		t.Fatalf("expected conflicting-signature refusal, got %v", err)
	}
	if err := journal.Record("nomad-test", 8, second); err != nil {
		t.Fatal("a different epoch must be recordable")
	}
	if err := journal.Record("other-network", 7, second); err != nil {
		t.Fatal("a different network must be recordable")
	}
}

func TestChainRejectsForeignNetworkGenesisWithoutHalting(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	// A fully valid genesis for a different network signed by the same
	// authority competes for the genesis slot (zero previous digest) but is
	// not equivocation for this network and must not halt the chain.
	foreign := newFixture(t, 3)
	foreign.AuthorityPublic = f.AuthorityPublic
	foreign.AuthorityPrivate = f.AuthorityPrivate
	session := sha256.Sum256([]byte("foreign-network-session"))
	topologyBytes, network := foreign.buildSignedTopologyWithNetwork(t, "nomad-other", 1, 2, genesisTimes(), session, 90)
	certificateBytes, _ := foreign.buildCertificate(t, network)
	foreignEncoded, _ := foreign.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)
	if _, err := chain.Append(foreignEncoded); err == nil {
		t.Fatal("foreign-network genesis must be rejected")
	} else if errors.Is(err, ErrEquivocation) {
		t.Fatal("foreign-network genesis must not count as equivocation")
	}
	if chain.Halted() {
		t.Fatal("foreign-network genesis must not halt the chain")
	}
	if _, active := chain.ActiveAt(genesis.ActivateAt); !active {
		t.Fatal("chain must remain live")
	}
}
