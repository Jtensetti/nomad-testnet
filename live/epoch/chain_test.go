package epoch

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestChainAppendActivateRetireAndReopen(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, successor := buildTwoEpochChain(t)
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

	reopened, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
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
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
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
	chain, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
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
	reopened, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
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
	probe := successor.ActivateAt.Add(time.Minute)
	if current, active := chain.ActiveAt(probe); !active || current.Epoch != 2 {
		t.Fatal("emergency successor must be the single active epoch")
	}
	if state, err := chain.StateOf(1, probe); err != nil || state != StateRetired {
		t.Fatalf("predecessor must be RETIRED under an active emergency successor, got %v %v", state, err)
	}
}

// TestJournalRefusesSecondActivation exercises the enforced signing path.
// An operator that has activated one descriptor for an epoch must refuse to
// activate a second, distinct one: that refusal is the producer-side half of
// the split-brain defense, and because any second valid descriptor halts
// every verifier that sees it, an unjournalled signer is an outage waiting
// to happen.
func TestJournalRefusesSecondActivation(t *testing.T) {
	f := newFixture(t, 3)
	session := sha256.Sum256([]byte("journal-session"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, genesisTimes(), session, 10)
	certificateBytes, _ := f.buildCertificate(t, network)

	first, err := New(nil, TransitionGenesis, canonicalTime(genesisTimes().Activate), canonicalTime(genesisTimes().Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	other := genesisTimes()
	other.Retire = other.Retire.Add(time.Hour)
	second, err := New(nil, TransitionGenesis, canonicalTime(other.Activate), canonicalTime(other.Retire), topologyBytes, certificateBytes)
	if err != nil {
		t.Fatal(err)
	}

	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	operator := network.Document.Operators[0]
	if _, err := journal.activateWithJournalUnchecked(first, operator, f.Operators[0].Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.activateWithJournalUnchecked(first, operator, f.Operators[0].Identity); err != nil {
		t.Fatalf("re-signing the identical descriptor must be idempotent: %v", err)
	}
	if _, err := journal.activateWithJournalUnchecked(second, operator, f.Operators[0].Identity); !errors.Is(err, ErrConflictingSignature) {
		t.Fatalf("expected a refusal to sign a second descriptor for epoch 1, got %v", err)
	}
	// A separate journal directory, i.e. a different operator, is unaffected.
	fresh, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.activateWithJournalUnchecked(second, operator, f.Operators[0].Identity); err != nil {
		t.Fatalf("an independent operator journal must be unaffected: %v", err)
	}
}

func TestJournalRejectsPathTraversalNetworkID(t *testing.T) {
	journal, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("descriptor"))
	for _, networkID := range []string{"../escaped", "a/b", "", "UPPER", "-leading"} {
		if err := journal.record(networkID, 1, roleActivation, digest); err == nil {
			t.Fatalf("network ID %q must be rejected", networkID)
		}
	}
}

func TestChainRejectsForeignNetworkGenesisWithoutHalting(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	// A fully valid genesis for a different network signed by the same
	// authority competes for the genesis slot (zero previous digest) but is
	// not equivocation for this network and must not halt the chain.
	foreign := newNamedFixture(t, "foreign", 3)
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

// TestHaltSurvivesEvidencePersistenceFailure is the regression for a
// confirmed fail-open: the in-memory halt was set only after the marker was
// written, so any persistence error (EEXIST from another instance, ENOSPC,
// read-only mount) left a verifier that had detected equivocation still
// serving epochs.
func TestHaltSurvivesEvidencePersistenceFailure(t *testing.T) {
	f := newFixture(t, 3)
	session := sha256.Sum256([]byte("halt-persistence"))
	topologyBytes, network := f.buildSignedTopology(t, 1, 2, genesisTimes(), session, 10)
	certificateBytes, _ := f.buildCertificate(t, network)
	firstEncoded, first := f.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)
	other := genesisTimes()
	other.Retire = other.Retire.Add(time.Hour)
	secondEncoded, _ := f.buildDescriptor(t, nil, nil, TransitionGenesis, other, network, topologyBytes, certificateBytes)

	root := t.TempDir()
	chain, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(firstEncoded); err != nil {
		t.Fatal(err)
	}
	stored, _ := chain.Tip()
	probe, err := decodeDescriptor(secondEncoded)
	if err != nil {
		t.Fatal(err)
	}
	offeredDigest, err := Digest(probe)
	if err != nil {
		t.Fatal(err)
	}
	// Point the chain at a directory that does not exist, so persisting the
	// evidence must fail the way a full disk or read-only mount would.
	chain.root = filepath.Join(root, "missing")
	persistErr := chain.halt(stored, offeredDigest, secondEncoded)
	if persistErr == nil {
		t.Fatal("this case is only meaningful when persistence actually fails")
	}
	if !chain.Halted() {
		t.Fatal("a detected equivocation must halt the chain even when evidence cannot be written")
	}
	chain.root = root
	if _, active := chain.ActiveAt(first.ActivateAt); active {
		t.Fatal("a halted chain must not report an active epoch")
	}
	if _, err := chain.Append(firstEncoded); !errors.Is(err, ErrHalted) {
		t.Fatal("a halted chain must refuse further appends")
	}
}

// TestPreexistingHaltMarkerStopsAnotherInstance covers the cross-process
// case: a marker written by another instance must halt this one at its next
// mutating operation, not be treated as a write failure.
func TestPreexistingHaltMarkerStopsAnotherInstance(t *testing.T) {
	f, genesisEncoded, _, successorEncoded, _ := buildTwoEpochChain(t)
	root := t.TempDir()
	chain, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "HALTED"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(successorEncoded); !errors.Is(err, ErrHalted) {
		t.Fatalf("expected the chain to observe another instance's halt, got %v", err)
	}
	if !chain.Halted() {
		t.Fatal("chain must adopt a halt recorded by another instance")
	}
}

// TestSecondInstanceAdoptsAppendsFromTheFirst exercises two handles on one
// directory, the ordinary node-plus-CLI deployment.
func TestSecondInstanceAdoptsAppendsFromTheFirst(t *testing.T) {
	f, genesisEncoded, _, successorEncoded, successor := buildTwoEpochChain(t)
	root := t.TempDir()
	first, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	// The second handle knew nothing of that append; adopting it must not
	// look like a conflict.
	if _, err := second.Append(successorEncoded); err != nil {
		t.Fatalf("second instance must adopt the first instance's epoch: %v", err)
	}
	if second.Halted() || first.Halted() {
		t.Fatal("concurrent instances on one directory must not halt each other")
	}
	if tip, ok := second.Tip(); !ok || tip.Epoch != successor.Epoch {
		t.Fatal("second instance should hold the successor tip")
	}
}

// TestAppendNeverReturnsSuccessForUnverifiedBytes covers the idempotence
// path, which previously returned success on a digest match without ever
// verifying the offered bytes: the digest excludes approvals and
// activations, so signature-stripped input matched and was accepted.
func TestAppendNeverReturnsSuccessForUnverifiedBytes(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	stripped := genesis.Descriptor
	stripped.Activations = nil
	strippedEncoded, err := Encode(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(strippedEncoded); err == nil {
		t.Fatal("Append must not report success for bytes Verify rejects")
	}
	if chain.Halted() {
		t.Fatal("unverifiable bytes must not halt the chain")
	}
	// Unknown fields must be rejected by Append's own decoder, not only by Verify.
	garbled := append([]byte(nil), genesisEncoded...)
	garbled = append([]byte(`{"attacker_controlled_field":1,`), garbled[1:]...)
	if _, err := chain.Append(garbled); err == nil {
		t.Fatal("Append must reject unknown fields")
	}
}

// TestBurnedEpochNumberCannotBeReused implements chain rule 2 against a
// persisted high-water mark: deleting a descriptor file must not re-open a
// used epoch number for a different successor.
func TestBurnedEpochNumberCannotBeReused(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, successor := buildTwoEpochChain(t)
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
	// Remove the stored epoch 2 and reopen: the high-water mark survives.
	if err := os.Remove(filepath.Join(root, fmt.Sprintf("%020d.epoch.json", successor.Epoch))); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tip, ok := reopened.Tip(); !ok || tip.Epoch != genesis.Epoch {
		t.Fatal("reopened chain should have fallen back to the genesis tip")
	}
	alternative := successorTimes()
	alternative.Retire = alternative.Retire.Add(2 * time.Hour)
	session := sha256.Sum256([]byte("burned-epoch-alternative"))
	topologyBytes, network := f.buildSignedTopology(t, 2, 2, alternative, session, 40)
	certificateBytes, _ := f.buildCertificate(t, network)
	altEncoded, _ := f.buildDescriptor(t, &genesis, f, TransitionScheduled, alternative, network, topologyBytes, certificateBytes)
	if _, err := reopened.Append(altEncoded); err == nil {
		t.Fatal("a burned epoch number must not accept a different descriptor")
	}
}

// TestLawfulRebootstrapIsNotEquivocation covers a confirmed false positive:
// slots were matched by previous-epoch digest, so a valid genesis for a
// later epoch (the specified recovery from quorum loss) collided with the
// stored genesis and permanently halted every verifier that saw it.
func TestLawfulRebootstrapIsNotEquivocation(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	times := epochTimes{
		NotBefore: fixtureBase.Add(20 * time.Hour),
		NotAfter:  fixtureBase.Add(40 * time.Hour),
		DKGStart:  fixtureBase.Add(21 * time.Hour),
		Activate:  fixtureBase.Add(22 * time.Hour),
		Retire:    fixtureBase.Add(30 * time.Hour),
	}
	session := sha256.Sum256([]byte("rebootstrap-session"))
	topologyBytes, network := f.buildSignedTopology(t, 9, 2, times, session, 50)
	certificateBytes, _ := f.buildCertificate(t, network)
	rebootstrap, _ := f.buildDescriptor(t, nil, nil, TransitionGenesis, times, network, topologyBytes, certificateBytes)

	_, err = chain.Append(rebootstrap)
	if errors.Is(err, ErrEquivocation) {
		t.Fatal("a genesis for a different epoch is not equivocation")
	}
	if chain.Halted() {
		t.Fatal("a lawful re-bootstrap must not halt the chain")
	}
	if _, active := chain.ActiveAt(genesis.ActivateAt); !active {
		t.Fatal("the chain must remain usable")
	}
}

func TestChainPinsItsNetworkOnFirstGenesis(t *testing.T) {
	foreign := newNamedFixture(t, "foreign-network", 3)
	session := sha256.Sum256([]byte("network-pin"))
	topologyBytes, network := foreign.buildSignedTopologyWithNetwork(t, "nomad-other", 1, 2, genesisTimes(), session, 60)
	certificateBytes, _ := foreign.buildCertificate(t, network)
	encoded, _ := foreign.buildDescriptor(t, nil, nil, TransitionGenesis, genesisTimes(), network, topologyBytes, certificateBytes)

	chain, err := OpenChain(t.TempDir(), "nomad-test", foreign.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(encoded); err == nil {
		t.Fatal("an empty store must still reject a genesis for another network")
	}
	if chain.Halted() {
		t.Fatal("a foreign-network genesis must not halt the chain")
	}
}

// TestRevocationDoesNotBrickAnExistingStore covers a confirmed
// self-inflicted denial of service: revocation was applied when
// re-verifying stored history, so declaring a compromise made the chain
// unopenable at exactly the moment the emergency successor was needed.
func TestRevocationDoesNotBrickAnExistingStore(t *testing.T) {
	f, genesisEncoded, genesis, _, _ := buildTwoEpochChain(t)
	root := t.TempDir()
	chain, err := OpenChain(root, "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain.Append(genesisEncoded); err != nil {
		t.Fatal(err)
	}
	revoked := RevocationSet{genesis.Topology.Document.Operators[0].IdentityKey: {}}
	reopened, err := OpenChain(root, "nomad-test", f.AuthorityPublic, revoked)
	if err != nil {
		t.Fatalf("declaring a compromise must not make the store unopenable: %v", err)
	}
	if tip, ok := reopened.Tip(); !ok || tip.Epoch != genesis.Epoch {
		t.Fatal("the accepted history must remain available after a revocation")
	}
}

func TestConcurrentAppendAndReadsAreRaceFree(t *testing.T) {
	f, genesisEncoded, genesis, successorEncoded, _ := buildTwoEpochChain(t)
	chain, err := OpenChain(t.TempDir(), "nomad-test", f.AuthorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			if worker%2 == 0 {
				_, _ = chain.Append(genesisEncoded)
				_, _ = chain.Append(successorEncoded)
				return
			}
			_, _ = chain.ActiveAt(genesis.ActivateAt)
			_, _ = chain.Tip()
			_ = chain.HighestRetired(genesis.RetireAt)
			_ = chain.Halted()
		}(worker)
	}
	group.Wait()
	if chain.Halted() {
		t.Fatal("concurrent appends of the same descriptors must not look like equivocation")
	}
}

// TestServesEpochRefusesEverythingButActive is the chain-backed retirement
// guard used by the share service: a retired epoch's share stays
// cryptographically valid for its own ciphertext, so refusal has to come
// from policy, and that policy must fail closed.
func TestServesEpochRefusesEverythingButActive(t *testing.T) {
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
	if err := chain.ServesEpoch(genesis.Epoch, genesis.ActivateAt); err != nil {
		t.Fatalf("an active epoch must be served: %v", err)
	}
	if err := chain.ServesEpoch(genesis.Epoch, genesis.ActivateAt.Add(-time.Second)); err == nil {
		t.Fatal("a READY epoch must not be served")
	}
	if err := chain.ServesEpoch(genesis.Epoch, successor.ActivateAt); err == nil {
		t.Fatal("a retired epoch must not be served")
	}
	if err := chain.ServesEpoch(9999, genesis.ActivateAt); err == nil {
		t.Fatal("an unknown epoch must not be served")
	}
	if err := chain.ServesEpoch(successor.Epoch, successor.RetireAt); err == nil {
		t.Fatal("an epoch past its retirement must not be served")
	}
}
