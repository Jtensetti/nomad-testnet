package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Jtensetti/nomad-anytrust-mix-sim/mix"
	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type coordinatorOperator struct {
	id              string
	previousSecrets topology.Secrets
	secrets         topology.Secrets
	keys            topology.PrivateKeys
	listener        net.Listener
}

type coordinatorFixture struct {
	authorityPrivate ed25519.PrivateKey
	authorityPublic  ed25519.PublicKey
	operators        []coordinatorOperator
	genesisEncoded   []byte
	genesis          epoch.Verified
	successorBytes   []byte
	successor        topology.Verified
	certificate      []byte
	successorSecrets []mix.MemberSecret
	coordinators     []*Coordinator
	servers          []*http.Server
}

var coordinatorBase = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func newCoordinatorFixture(t *testing.T) *coordinatorFixture {
	t.Helper()
	_, authority, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &coordinatorFixture{
		authorityPrivate: authority,
		authorityPublic:  authority.Public().(ed25519.PublicKey),
		operators:        make([]coordinatorOperator, 3),
	}
	usedPorts := make(map[int]struct{})
	for index := range fixture.operators {
		var listener net.Listener
		for {
			listener, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_, controlConflicts := usedPorts[port]
			_, dkgConflicts := usedPorts[port-1]
			if port > 1 && !controlConflicts && !dkgConflicts {
				usedPorts[port] = struct{}{}
				usedPorts[port-1] = struct{}{}
				break
			}
			_ = listener.Close()
		}
		id := fmt.Sprintf("op-%c", 'a'+index)
		secrets, err := topology.GenerateSecrets(id)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := topology.DecodePrivateKeys(mustEncodeSecrets(t, secrets))
		if err != nil {
			t.Fatal(err)
		}
		fixture.operators[index] = coordinatorOperator{id: id, secrets: secrets, keys: keys, listener: listener}
	}

	genesisTimes := lifecycleTimes{
		notBefore: coordinatorBase.Add(-time.Hour),
		notAfter:  coordinatorBase.Add(3 * time.Hour),
		dkgStart:  coordinatorBase.Add(-50 * time.Minute),
		activate:  coordinatorBase.Add(-30 * time.Minute),
		retire:    coordinatorBase.Add(2 * time.Hour),
	}
	successorTimes := lifecycleTimes{
		notBefore: coordinatorBase,
		notAfter:  coordinatorBase.Add(5 * time.Hour),
		dkgStart:  coordinatorBase.Add(5 * time.Minute),
		activate:  genesisTimes.retire,
		retire:    coordinatorBase.Add(5 * time.Hour),
	}
	genesisTopologyBytes, genesisTopology := fixture.buildTopology(t, 1, genesisTimes, "genesis")
	genesisCertificate, _ := fixture.buildCertificate(t, genesisTopology)
	fixture.genesisEncoded, fixture.genesis = fixture.buildGenesis(t, genesisTimes, genesisTopologyBytes, genesisCertificate)
	for index := range fixture.operators {
		operator := &fixture.operators[index]
		operator.previousSecrets = operator.secrets
		rotated, err := topology.RotateEpochSecrets(operator.keys)
		if err != nil {
			t.Fatal(err)
		}
		keys, err := topology.DecodePrivateKeys(mustEncodeSecrets(t, rotated))
		if err != nil {
			t.Fatal(err)
		}
		operator.secrets = rotated
		operator.keys = keys
	}
	fixture.successorBytes, fixture.successor = fixture.buildTopology(t, 2, successorTimes, "successor")
	fixture.certificate, fixture.successorSecrets = fixture.buildCertificate(t, fixture.successor)
	fixture.installOperators(t)
	return fixture
}

type lifecycleTimes struct {
	notBefore time.Time
	notAfter  time.Time
	dkgStart  time.Time
	activate  time.Time
	retire    time.Time
}

func mustEncodeSecrets(t *testing.T, secrets topology.Secrets) []byte {
	t.Helper()
	encoded, err := topology.EncodeSecrets(secrets)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func canonicalLifecycleTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func (fixture *coordinatorFixture) buildTopology(t *testing.T, number uint64, times lifecycleTimes, sessionLabel string) ([]byte, topology.Verified) {
	t.Helper()
	session := sha256.Sum256([]byte("coordinator-test-" + sessionLabel))
	document := topology.Document{
		Version: topology.Version, NetworkID: "nomad-test", Epoch: number,
		NotBefore: canonicalLifecycleTime(times.notBefore), NotAfter: canonicalLifecycleTime(times.notAfter),
		Traffic: topology.TrafficClass{
			CellSize: topology.CellSize, CellIntervalMillis: 50,
			MaxLatenessMillis: 500, QueueCapacity: 64,
		},
		DKG: topology.DKGProfile{
			Threshold: 2, SessionID: base64.StdEncoding.EncodeToString(session[:]),
			StartAt: canonicalLifecycleTime(times.dkgStart), PhaseDurationMillis: 1_000,
		},
		Operators: make([]topology.Operator, len(fixture.operators)),
	}
	identities := make(map[string]ed25519.PrivateKey, len(fixture.operators))
	occupied := make(map[int]struct{}, 2*len(fixture.operators))
	for _, operator := range fixture.operators {
		port := operator.listener.Addr().(*net.TCPAddr).Port
		occupied[port] = struct{}{}
		occupied[port-1] = struct{}{}
	}
	partialPort := 20_000
	for index, operator := range fixture.operators {
		for {
			if _, exists := occupied[partialPort]; !exists {
				occupied[partialPort] = struct{}{}
				break
			}
			partialPort++
		}
		dkgPublic, err := mix.DKGPublicFromPrivate(operator.keys.DKG)
		if err != nil {
			t.Fatal(err)
		}
		controlPort := operator.listener.Addr().(*net.TCPAddr).Port
		document.Operators[index] = topology.Operator{
			ID: operator.id, Index: uint16(index),
			Endpoint:        fmt.Sprintf("127.0.0.1:%d", 4200+index),
			PartialEndpoint: fmt.Sprintf("http://127.0.0.1:%d", partialPort),
			DKGEndpoint:     fmt.Sprintf("http://127.0.0.1:%d", controlPort-1),
			IdentityKey:     base64.StdEncoding.EncodeToString(operator.keys.Identity.Public().(ed25519.PublicKey)),
			KEXKey:          base64.StdEncoding.EncodeToString(operator.keys.KEX.PublicKey().Bytes()),
			DKGIdentityKey:  base64.StdEncoding.EncodeToString(dkgPublic[:]),
			PeerPlan:        []uint16{uint16((index + 1) % len(fixture.operators))},
		}
		identities[operator.id] = operator.keys.Identity
		partialPort++
	}
	signed, err := topology.Sign(document, fixture.authorityPrivate, identities)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := topology.Verify(encoded, fixture.authorityPublic, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := topology.ValidateEpochControlEndpoints(verified); err != nil {
		t.Fatal(err)
	}
	return encoded, verified
}

func (fixture *coordinatorFixture) buildCertificate(t *testing.T, network topology.Verified) ([]byte, []mix.MemberSecret) {
	t.Helper()
	committeeID, err := committee.IDForTopology(network)
	if err != nil {
		t.Fatal(err)
	}
	session, err := base64.StdEncoding.Strict().DecodeString(network.Document.DKG.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	identities := make([]mix.DKGPrivateIdentity, len(fixture.operators))
	for index, operator := range fixture.operators {
		identities[index] = operator.keys.DKG
	}
	public, secrets, transcript, err := mix.RunAuthenticatedDKGWithIdentities(
		committeeID, network.Document.Epoch, identities, network.Document.DKG.Threshold, session,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := committee.NewManifest(network, public, transcript)
	if err != nil {
		t.Fatal(err)
	}
	attestations := make([]committee.Attestation, len(fixture.operators))
	for index, operator := range fixture.operators {
		attestations[index], err = committee.CreateAttestation(manifest, network.Document.Operators[index], operator.keys.Identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := committee.Assemble(manifest, attestations, network)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := committee.Encode(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, secrets
}

func (fixture *coordinatorFixture) buildGenesis(t *testing.T, times lifecycleTimes, topologyBytes, certificateBytes []byte) ([]byte, epoch.Verified) {
	t.Helper()
	draft, err := epoch.New(
		nil, epoch.TransitionGenesis,
		canonicalLifecycleTime(times.activate), canonicalLifecycleTime(times.retire),
		topologyBytes, certificateBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make([]epoch.SignatureArtifact, len(fixture.operators))
	for index, operator := range fixture.operators {
		journal, err := epoch.OpenJournal(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		artifacts[index], err = journal.CreateActivationArtifact(
			draft, fixture.authorityPublic, nil, nil, operator.id, operator.keys.Identity,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, verified, err := epoch.Assemble(draft, artifacts, fixture.authorityPublic, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, verified
}

func (fixture *coordinatorFixture) installOperators(t *testing.T) {
	t.Helper()
	fixture.coordinators = make([]*Coordinator, len(fixture.operators))
	fixture.servers = make([]*http.Server, len(fixture.operators))
	for index, operator := range fixture.operators {
		root := t.TempDir()
		controller := Config{
			OperatorID: operator.id, Authority: fixture.authorityPublic, NetworkID: "nomad-test",
			TopologyDir: filepath.Join(root, "topologies"), SecretsRoot: filepath.Join(root, "secrets"),
			Listen: operator.listener.Addr().String(), StateRoot: filepath.Join(root, "state"),
			ShareRoot: filepath.Join(root, "shares"), CertRoot: filepath.Join(root, "certificates"),
		}
		for _, directory := range []string{controller.StateRoot, controller.ShareRoot, controller.CertRoot, controller.SecretsRoot} {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Dir(controller.attemptTopologyPath(2, 1)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(controller.attemptTopologyPath(2, 1), fixture.successorBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		previousPath, err := controller.epochSecretsPath(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(previousPath, mustEncodeSecrets(t, operator.previousSecrets), 0o600); err != nil {
			t.Fatal(err)
		}
		incomingPath, err := controller.epochSecretsPath(2)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(incomingPath, mustEncodeSecrets(t, operator.secrets), 0o600); err != nil {
			t.Fatal(err)
		}
		chainRoot := filepath.Join(root, "chain")
		chain, err := epoch.OpenChain(chainRoot, "nomad-test", fixture.authorityPublic, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := chain.Append(fixture.genesisEncoded); err != nil {
			t.Fatal(err)
		}
		coordinator, err := NewCoordinator(CoordinatorConfig{
			Controller: controller, ChainRoot: chainRoot, RevocationRoot: filepath.Join(root, "revocations"),
			ExchangeRoot: filepath.Join(root, "exchange"), JournalRoot: filepath.Join(root, "journal"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.exchange.Publish(2, artifactCertificate, "", fixture.certificate); err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: coordinator.Handler(), ReadHeaderTimeout: time.Second}
		fixture.coordinators[index] = coordinator
		fixture.servers[index] = server
		go func(listener net.Listener, server *http.Server) {
			_ = server.Serve(listener)
		}(operator.listener, server)
	}
	t.Cleanup(func() {
		for _, server := range fixture.servers {
			shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = server.Shutdown(shutdown)
			cancel()
		}
	})
}

type corruptingArtifactTransport struct {
	base   http.RoundTripper
	suffix string
}

type boundaryBlockingTransport struct{}

func (boundaryBlockingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	<-request.Context().Done()
	return nil, request.Context().Err()
}

func (transport corruptingArtifactTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, transport.suffix) {
		return &http.Response{
			StatusCode: http.StatusOK, Status: "200 OK",
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   io.NopCloser(strings.NewReader("{\"invalid\":true}")), Request: request,
		}, nil
	}
	return transport.base.RoundTrip(request)
}

func TestAutomaticCoordinatorReachesReadyAcrossIndependentMailboxes(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	now := coordinatorBase.Add(10 * time.Minute)

	first, err := fixture.coordinators[0].Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusCollecting || first.Approvals != 1 || first.Activations != 1 {
		t.Fatalf("first operator outcome = %+v", first)
	}
	second, err := fixture.coordinators[1].Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusCollecting || second.Approvals != 2 || second.Activations != 2 {
		t.Fatalf("second operator outcome = %+v", second)
	}

	// Approval quorum alone is insufficient: all incoming operators must
	// activate the exact draft before any verifier imports it as READY.
	missingActivation, err := fixture.coordinators[0].Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if missingActivation.Status != StatusCollecting || missingActivation.Approvals < missingActivation.ApprovalQuorum || missingActivation.Activations != 2 {
		t.Fatalf("missing activation did not fail closed: %+v", missingActivation)
	}

	third, err := fixture.coordinators[2].Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if third.Status != StatusReady {
		t.Fatalf("last signer did not reach READY: %+v", third)
	}

	// Reopen operator A from the same durable roots. Re-signing the identical
	// draft must recover idempotently from its anti-equivocation journal.
	restarted, err := NewCoordinator(fixture.coordinators[0].config)
	if err != nil {
		t.Fatal(err)
	}
	productionClient := restarted.exchange.client
	restarted.exchange.client = &http.Client{
		Transport: corruptingArtifactTransport{
			base: productionClient.Transport, suffix: "/approval/op-c",
		},
		Timeout: productionClient.Timeout, CheckRedirect: productionClient.CheckRedirect,
	}
	fixture.coordinators[0] = restarted
	afterRestart, err := restarted.Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if afterRestart.Status != StatusReady || afterRestart.Approvals != 2 || afterRestart.Activations != 3 {
		t.Fatalf("restart or malicious nonessential approval blocked READY: %+v", afterRestart)
	}
	final, err := fixture.coordinators[1].Advance(ctx, now, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != StatusReady {
		t.Fatalf("remaining verifier did not reach READY: %+v", final)
	}

	var digest string
	for index, coordinator := range fixture.coordinators {
		chain, err := epoch.OpenChain(coordinator.config.ChainRoot, "nomad-test", fixture.authorityPublic, nil)
		if err != nil {
			t.Fatal(err)
		}
		tip, exists := chain.Tip()
		if !exists || tip.Epoch != 2 {
			t.Fatalf("operator %d did not import successor", index)
		}
		current := fmt.Sprintf("%x", tip.Digest)
		if digest == "" {
			digest = current
		} else if current != digest {
			t.Fatalf("operator %d imported digest %s, want %s", index, current, digest)
		}
		state, err := chain.StateOf(2, fixture.genesis.RetireAt.Add(-time.Second))
		if err != nil || state != epoch.StateReady {
			t.Fatalf("operator %d pre-boundary state = %s, %v", index, state, err)
		}
		active, exists := chain.ActiveAt(fixture.genesis.RetireAt)
		if !exists || active.Epoch != 2 {
			t.Fatalf("operator %d did not activate successor at signed boundary", index)
		}
	}
}

func TestCoordinatorRequiresBothEpochScopedSecretsForContinuingOperator(t *testing.T) {
	for _, test := range []struct {
		name  string
		epoch uint64
		want  string
	}{
		{"predecessor approval", 1, "predecessor epoch keys"},
		{"incoming activation", 2, "incoming epoch keys"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCoordinatorFixture(t)
			coordinator := fixture.coordinators[0]
			path, err := coordinator.config.Controller.epochSecretsPath(test.epoch)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			_, err = coordinator.Advance(context.Background(), coordinatorBase.Add(10*time.Minute), 2, 1)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("missing %s secret did not fail closed: %v", test.name, err)
			}
		})
	}
}

func TestCoordinatorWaitsWithoutCertificateAndDoesNotInventFallback(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	for _, coordinator := range fixture.coordinators {
		path, err := coordinator.exchange.path(2, artifactCertificate, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	outcome, err := fixture.coordinators[0].Advance(ctx, coordinatorBase.Add(10*time.Minute), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != StatusAwaitCertificate {
		t.Fatalf("missing public certificate produced %+v", outcome)
	}
	entries, err := os.ReadDir(fixture.coordinators[0].config.JournalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("coordinator signed a descriptor without a certified DKG result")
	}
}

func TestCoordinatorPublishesOnlyReverifiedLocalDKGCompletion(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	for _, coordinator := range fixture.coordinators {
		path, err := coordinator.exchange.path(2, artifactCertificate, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	coordinator := fixture.coordinators[0]
	config := coordinator.config.Controller
	certificate, certified, err := committee.Decode(fixture.certificate, fixture.successor)
	if err != nil {
		t.Fatal(err)
	}
	_ = certificate
	share := committee.ShareFromSecret(fixture.successorSecrets[0], fixture.successor.Document.Operators[0], fixture.successor)
	shareBytes, err := committee.EncodeShare(share)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.certificatePath(2, 1), fixture.certificate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.sharePath(2, 1), shareBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(config.attemptRoot(2, 1), 0o700); err != nil {
		t.Fatal(err)
	}
	complete := []byte(fmt.Sprintf(
		"network=%s\nepoch=%d\ntopology=%x\ncertificate=%x\n",
		fixture.successor.Document.NetworkID, fixture.successor.Document.Epoch,
		fixture.successor.Digest, certified.Digest,
	))
	if err := os.WriteFile(filepath.Join(config.attemptRoot(2, 1), "COMPLETE"), complete, 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := coordinator.Advance(context.Background(), coordinatorBase.Add(10*time.Minute), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != StatusCollecting || outcome.Approvals != 1 || outcome.Activations != 1 {
		t.Fatalf("recovered local completion outcome = %+v", outcome)
	}
	publishedPath, err := coordinator.exchange.path(2, artifactCertificate, "")
	if err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(publishedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(published) != string(fixture.certificate) {
		t.Fatal("coordinator published bytes other than its reverified local DKG certificate")
	}
}

func TestCoordinatorNeverImportsAfterSignedActivationBoundary(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	coordinator := fixture.coordinators[0]
	outcome, err := coordinator.Advance(context.Background(), fixture.genesis.RetireAt, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != StatusMissedActivation {
		t.Fatalf("late coordination outcome = %+v", outcome)
	}
	chain, err := epoch.OpenChain(coordinator.config.ChainRoot, "nomad-test", fixture.authorityPublic, nil)
	if err != nil {
		t.Fatal(err)
	}
	tip, exists := chain.Tip()
	if !exists || tip.Epoch != 1 {
		t.Fatal("late scheduled successor was imported as catch-up activation")
	}
	entries, err := os.ReadDir(coordinator.config.JournalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("late coordination burned a signature-journal slot")
	}
	draftPath, err := coordinator.exchange.path(2, artifactDraft, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(draftPath); !os.IsNotExist(err) {
		t.Fatal("late coordination published a catch-up draft")
	}
}

func TestCoordinatorRejectsControlTLSModeOutsideSignedTopology(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	config := fixture.coordinators[0].config
	config.Controller.TLSCert = "unexpected.crt"
	config.Controller.TLSKey = "unexpected.key"
	coordinator, err := NewCoordinator(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), coordinatorBase.Add(10*time.Minute), 2, 1); err == nil || !strings.Contains(err.Error(), "TLS mode") {
		t.Fatalf("unsigned lifecycle transport change was accepted: %v", err)
	}
	entries, err := os.ReadDir(config.JournalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("transport mismatch burned a signature-journal slot")
	}
}

func TestCoordinatorStopsAnInFlightRoundAtActivationBoundary(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	coordinator := fixture.coordinators[0]
	for _, peer := range fixture.coordinators {
		path, err := peer.exchange.path(2, artifactCertificate, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	coordinator.exchange.client = &http.Client{Transport: boundaryBlockingTransport{}}
	started := time.Now()
	outcome, err := coordinator.Advance(context.Background(), fixture.genesis.RetireAt.Add(-25*time.Millisecond), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != StatusMissedActivation {
		t.Fatalf("boundary-crossing control round = %+v", outcome)
	}
	if elapsed := time.Since(started); elapsed < 20*time.Millisecond || elapsed > time.Second {
		t.Fatalf("boundary cancellation took %s", elapsed)
	}
	entries, err := os.ReadDir(coordinator.config.JournalRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("boundary-crossing round signed after its public deadline")
	}
}

func TestControlEndpointPortMatchesSignedTopology(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	for index, operator := range fixture.successor.Document.Operators {
		endpoint, err := ControlEndpoint(operator.DKGEndpoint)
		if err != nil {
			t.Fatal(err)
		}
		_, portText, err := net.SplitHostPort(strings.TrimPrefix(endpoint, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		port, _ := strconv.Atoi(portText)
		if port != fixture.operators[index].listener.Addr().(*net.TCPAddr).Port {
			t.Fatalf("operator %d control port = %d", index, port)
		}
	}
}

func TestRetryLadderChangesOnlyFreshSessionAndPublicStart(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	config := fixture.coordinators[0].config.Controller
	retryTimes := lifecycleTimes{
		notBefore: coordinatorBase,
		notAfter:  coordinatorBase.Add(5 * time.Hour),
		dkgStart:  coordinatorBase.Add(15 * time.Minute),
		activate:  fixture.genesis.RetireAt,
		retire:    coordinatorBase.Add(5 * time.Hour),
	}
	retryBytes, retry := fixture.buildTopology(t, 2, retryTimes, "successor-retry-2")
	retryPath := config.attemptTopologyPath(2, 2)
	if err := os.MkdirAll(filepath.Dir(retryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retryPath, retryBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := config.validateRetryLadder(2, 2, retry); err != nil {
		t.Fatalf("valid fresh-session retry was rejected: %v", err)
	}

	changed := retry
	changed.Document.Operators = append([]topology.Operator(nil), retry.Document.Operators...)
	changed.Document.Operators[0].Endpoint = "127.0.0.1:9999"
	if err := config.validateRetryLadder(2, 2, changed); err == nil || !strings.Contains(err.Error(), "invariant") {
		t.Fatalf("retry membership/endpoint mutation was accepted: %v", err)
	}

	reused := retry
	reused.Document.DKG.SessionID = fixture.successor.Document.DKG.SessionID
	if err := config.validateRetryLadder(2, 2, reused); err == nil || !strings.Contains(err.Error(), "reused") {
		t.Fatalf("retry session reuse was accepted: %v", err)
	}

	nonIncreasing := retry
	nonIncreasing.Document.DKG.StartAt = fixture.successor.Document.DKG.StartAt
	if err := config.validateRetryLadder(2, 2, nonIncreasing); err == nil || !strings.Contains(err.Error(), "increase") {
		t.Fatalf("non-increasing retry schedule was accepted: %v", err)
	}
}
