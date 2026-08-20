package dkgnet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/ceremony"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

func TestThreeOperatorDistributedDKG(t *testing.T) {
	operatorIDs := []string{"operator-a", "operator-b", "operator-c"}
	listenAddresses := make([]string, len(operatorIDs))
	for index := range listenAddresses {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listenAddresses[index] = listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	private := make(map[string]topology.PrivateKeys, len(operatorIDs))
	secretBytes := make(map[string][]byte, len(operatorIDs))
	enrollments := make([]ceremony.Enrollment, len(operatorIDs))
	for index, id := range operatorIDs {
		secret, err := topology.GenerateSecrets(id)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := topology.EncodeSecrets(secret)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := topology.DecodePrivateKeys(encoded)
		if err != nil {
			t.Fatal(err)
		}
		enrollment, err := ceremony.NewEnrollment(keys, "127.0.0.1:"+[]string{"4211", "4212", "4213"}[index], "http://127.0.0.1:"+[]string{"4311", "4312", "4313"}[index], "http://"+listenAddresses[index])
		if err != nil {
			t.Fatal(err)
		}
		private[id] = keys
		secretBytes[id] = encoded
		enrollments[index] = enrollment
	}
	now := time.Now().UTC().Truncate(time.Second)
	draft, err := ceremony.BuildDraft(enrollments, ceremony.DraftConfig{
		NetworkID: "dkg-test", Epoch: 11, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Traffic:  topology.TrafficClass{CellSize: topology.CellSize, CellIntervalMillis: 50, MaxLatenessMillis: 200, QueueCapacity: 64},
		DKGStart: now.Add(3 * time.Second), DKGPhaseDuration: time.Second, DKGThreshold: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	attested := draft
	for _, operator := range draft.Operators {
		attested, err = topology.Attest(attested, operator.ID, private[operator.ID].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	authorityPublic, authorityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := topology.Finalize(attested, authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encodedTopology, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	network, err := topology.Verify(encodedTopology, authorityPublic, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	type outcome struct {
		index  int
		result RunResult
		err    error
	}
	outcomes := make(chan outcome, len(operatorIDs))
	roots := make([]string, len(operatorIDs))
	for index, operator := range network.Document.Operators {
		root := t.TempDir()
		roots[index] = root
		state := filepath.Join(root, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		verifiedSecrets, err := topology.VerifySecrets(secretBytes[operator.ID], network)
		if err != nil {
			t.Fatal(err)
		}
		go func(index int, verifiedSecrets topology.VerifiedSecrets) {
			result, runErr := Run(ctx, network, verifiedSecrets, RunConfig{
				Listen: listenAddresses[index], StateDirectory: state,
				ShareOutput: filepath.Join(root, "threshold-share.json"), CertificateOutput: filepath.Join(root, "dkg-certificate.json"),
			})
			outcomes <- outcome{index: index, result: result, err: runErr}
		}(index, verifiedSecrets)
	}
	results := make([]RunResult, len(operatorIDs))
	for range operatorIDs {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("operator %d: %v", outcome.index, outcome.err)
		}
		results[outcome.index] = outcome.result
	}
	for index := 1; index < len(results); index++ {
		if results[index].Verified.Digest != results[0].Verified.Digest || results[index].Verified.Committee.PublicKey != results[0].Verified.Committee.PublicKey {
			t.Fatal("operators activated different DKG certificates")
		}
		if results[index].Share.Secret == results[0].Share.Secret {
			t.Fatal("operators received identical private threshold shares")
		}
	}
	for index, root := range roots {
		shareBytes, err := os.ReadFile(filepath.Join(root, "threshold-share.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := committee.VerifyShare(shareBytes, results[index].Verified, network); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(filepath.Join(root, "state"), network); err == nil {
			t.Fatal("completed DKG state directory was reusable")
		}
	}
	expectedManifestDigest, err := committee.ManifestDigest(results[0].Certificate.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	splitManifest := results[0].Certificate.Manifest
	splitManifest.NetworkID = "split-view"
	splitAttestation, err := committee.CreateAttestation(splitManifest, network.Document.Operators[0], private["operator-a"].Identity)
	if err != nil {
		t.Fatal(err)
	}
	splitVote, err := encodeResultVote(splitManifest, splitAttestation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeResultVote(splitVote, network.Document.Operators[0], expectedManifestDigest); err == nil {
		t.Fatal("operator result vote for a split-view DKG manifest was accepted")
	}
}

func TestStoreRejectsSignedEquivocation(t *testing.T) {
	network, secrets := singleTestContext(t)
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, network)
	if err != nil {
		t.Fatal(err)
	}
	first, err := NewEnvelope(network, secrets.Operator, secrets.Identity, ResultPhase, []byte(`{"vote":1}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewEnvelope(network, secrets.Operator, secrets.Identity, ResultPhase, []byte(`{"vote":2}`))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := EncodeEnvelope(first)
	secondBytes, _ := EncodeEnvelope(second)
	if _, _, fresh, err := store.Accept(firstBytes); err != nil || !fresh {
		t.Fatalf("first message fresh=%v err=%v", fresh, err)
	}
	if _, _, fresh, err := store.Accept(firstBytes); err != nil || fresh {
		t.Fatalf("idempotent replay fresh=%v err=%v", fresh, err)
	}
	if _, _, _, err := store.Accept(secondBytes); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("expected equivocation, got %v", err)
	}
}

func TestBoardRejectsMessagesBeforeSignedCeremonyStart(t *testing.T) {
	network, secrets := singleTestContext(t)
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, network)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	board, err := NewBoard(ctx, network, secrets, store)
	if err != nil {
		t.Fatal(err)
	}
	defer board.Wait()
	envelope, err := NewEnvelope(network, secrets.Operator, secrets.Identity, ResultPhase, []byte(`{"vote":1}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := board.deliver(encoded); err == nil {
		t.Fatal("board accepted a DKG message before the signed ceremony start")
	}
}

func TestBoardRefusesIncompleteResultQuorum(t *testing.T) {
	network, secrets := singleTestContext(t)
	network.Document.DKG.StartAt = time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339)
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, network)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	board, err := NewBoard(ctx, network, secrets, store)
	if err != nil {
		t.Fatal(err)
	}
	defer board.Wait()
	if _, err := board.WaitForResults(ctx); err == nil {
		t.Fatal("incomplete all-operator DKG result quorum was accepted")
	}
}

func singleTestContext(t *testing.T) (topology.Verified, topology.VerifiedSecrets) {
	t.Helper()
	// The helper reuses the full three-member topology validator while only
	// returning operator A's local secret context.
	operatorIDs := []string{"operator-a", "operator-b", "operator-c"}
	private := make(map[string]topology.PrivateKeys)
	encodedSecrets := make(map[string][]byte)
	enrollments := make([]ceremony.Enrollment, len(operatorIDs))
	for index, id := range operatorIDs {
		secret, err := topology.GenerateSecrets(id)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := topology.EncodeSecrets(secret)
		keys, _ := topology.DecodePrivateKeys(encoded)
		enrollment, err := ceremony.NewEnrollment(keys, "127.0.0.1:"+[]string{"4251", "4252", "4253"}[index], "http://127.0.0.1:"+[]string{"4351", "4352", "4353"}[index], "http://127.0.0.1:"+[]string{"4451", "4452", "4453"}[index])
		if err != nil {
			t.Fatal(err)
		}
		private[id], encodedSecrets[id], enrollments[index] = keys, encoded, enrollment
	}
	now := time.Now().UTC().Truncate(time.Second)
	draft, err := ceremony.BuildDraft(enrollments, ceremony.DraftConfig{NetworkID: "store-test", Epoch: 2, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), Traffic: topology.TrafficClass{CellSize: topology.CellSize, CellIntervalMillis: 50, MaxLatenessMillis: 200, QueueCapacity: 64}, DKGStart: now.Add(time.Minute), DKGPhaseDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, operator := range draft.Operators {
		draft, err = topology.Attest(draft, operator.ID, private[operator.ID].Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	public, authority, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := topology.Finalize(draft, authority)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := topology.Encode(signed)
	network, err := topology.Verify(encoded, public, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := topology.VerifySecrets(encodedSecrets["operator-a"], network)
	if err != nil {
		t.Fatal(err)
	}
	return network, secrets
}
