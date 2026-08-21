package rotation

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	dkgnet "github.com/Jtensetti/nomad-testnet/live/dkg"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

type fixedPlanner struct{ plan epoch.Plan }

func (planner fixedPlanner) PlanAtForOperator(time.Time, epoch.Policy, string) (epoch.Plan, error) {
	return planner.plan, nil
}

func baseConfig(t *testing.T, planned epoch.Plan) Config {
	t.Helper()
	root := t.TempDir()
	_, authority, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	shares := filepath.Join(root, "shares")
	certs := filepath.Join(root, "certs")
	for _, directory := range []string{state, shares, certs} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return Config{
		Planner: fixedPlanner{plan: planned}, Policy: epoch.DefaultPolicy(), OperatorID: "operator-a",
		Authority: authority, NetworkID: "nomad-test", TopologyDir: filepath.Join(root, "topologies"),
		SecretsPath: filepath.Join(root, "operator.json"), Listen: "127.0.0.1:0",
		StateRoot: state, ShareRoot: shares, CertRoot: certs,
	}
}

func TestInterruptedAttemptNeverRestartsSamePublicAttempt(t *testing.T) {
	planned := epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 1, DueAt: time.Unix(100, 0).UTC()}
	config := baseConfig(t, planned)
	attempt := filepath.Join(config.StateRoot, "epoch-00000000000000000002-attempt-01")
	if err := os.Mkdir(attempt, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	config.RunDKG = func(context.Context, topology.Verified, topology.VerifiedSecrets, dkgnet.RunConfig) (dkgnet.RunResult, error) {
		called = true
		return dkgnet.RunResult{}, nil
	}
	outcome, err := config.Step(context.Background(), time.Unix(200, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("interrupted DKG attempt was restarted inside the same public attempt")
	}
	if outcome.Status != StatusAwaitRetry {
		t.Fatalf("status = %s, want %s", outcome.Status, StatusAwaitRetry)
	}
}

func TestCompletedDKGDoesNotRunAgainAtLaterRetryTick(t *testing.T) {
	planned := epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 2, DueAt: time.Unix(200, 0).UTC()}
	config := baseConfig(t, planned)
	certificate := filepath.Join(config.CertRoot, "epoch-00000000000000000002.certificate.json")
	share := filepath.Join(config.ShareRoot, "epoch-00000000000000000002.share.json")
	if err := os.WriteFile(certificate, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(share, []byte("share"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificateDigest, err := digestFile(certificate)
	if err != nil {
		t.Fatal(err)
	}
	shareDigest, err := digestFile(share)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(config.StateRoot, "epoch-00000000000000000002-result.json")
	if err := writeMarker(markerPath, resultMarker{
		Version: 1, NetworkID: config.NetworkID, Epoch: 2, Attempt: 1,
		CertificateSHA256: certificateDigest, ShareSHA256: shareDigest,
		TopologyDigest: "public-topology-digest", CompletedAt: time.Unix(150, 0).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	config.RunDKG = func(context.Context, topology.Verified, topology.VerifiedSecrets, dkgnet.RunConfig) (dkgnet.RunResult, error) {
		called = true
		return dkgnet.RunResult{}, nil
	}
	outcome, err := config.Step(context.Background(), time.Unix(250, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("completed DKG was run again when the public retry tick advanced")
	}
	if outcome.Status != StatusDKGComplete {
		t.Fatalf("status = %s, want %s", outcome.Status, StatusDKGComplete)
	}
}

func TestTamperedCompletedOutputFailsClosed(t *testing.T) {
	planned := epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 1}
	config := baseConfig(t, planned)
	certificate := filepath.Join(config.CertRoot, "epoch-00000000000000000002.certificate.json")
	share := filepath.Join(config.ShareRoot, "epoch-00000000000000000002.share.json")
	if err := os.WriteFile(certificate, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(share, []byte("share"), 0o600); err != nil {
		t.Fatal(err)
	}
	certificateDigest, _ := digestFile(certificate)
	shareDigest, _ := digestFile(share)
	markerPath := filepath.Join(config.StateRoot, "epoch-00000000000000000002-result.json")
	if err := writeMarker(markerPath, resultMarker{Version: 1, NetworkID: config.NetworkID, Epoch: 2, Attempt: 1, CertificateSHA256: certificateDigest, ShareSHA256: shareDigest}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(share, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Step(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("tampered completed DKG output was accepted")
	}
}

func TestNonDKGActionsNeverInvokeRunner(t *testing.T) {
	actions := []struct {
		action epoch.Action
		status string
	}{
		{epoch.ActionIdle, StatusIdle},
		{epoch.ActionAwaitActivation, StatusAwaitActivation},
		{epoch.ActionRetire, StatusRetire},
		{epoch.ActionEscalate, StatusEscalate},
		{epoch.ActionHalted, StatusHalted},
	}
	for _, test := range actions {
		t.Run(test.action.String(), func(t *testing.T) {
			config := baseConfig(t, epoch.Plan{Action: test.action, Epoch: 2})
			called := false
			config.RunDKG = func(context.Context, topology.Verified, topology.VerifiedSecrets, dkgnet.RunConfig) (dkgnet.RunResult, error) {
				called = true
				return dkgnet.RunResult{}, nil
			}
			outcome, err := config.Step(context.Background(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if called {
				t.Fatal("non-DKG public lifecycle action invoked DKG")
			}
			if outcome.Status != test.status {
				t.Fatalf("status = %s, want %s", outcome.Status, test.status)
			}
		})
	}
}
