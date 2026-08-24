package rotation

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
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
	topologies := filepath.Join(root, "topologies")
	for _, directory := range []string{state, shares, certs, topologies} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	generated, err := topology.GenerateSecrets("operator-a")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := topology.EncodeSecrets(generated)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(root, "operator.json")
	if err := os.WriteFile(secretPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{
		Planner: fixedPlanner{plan: planned}, Policy: epoch.DefaultPolicy(), OperatorID: "operator-a",
		Authority: authority, NetworkID: "nomad-test", TopologyDir: topologies,
		SecretsPath: secretPath, Listen: "127.0.0.1:0",
		StateRoot: state, ShareRoot: shares, CertRoot: certs,
	}
}

func TestInterruptedAttemptNeverRestartsSamePublicAttempt(t *testing.T) {
	planned := epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 1, DueAt: time.Unix(100, 0).UTC()}
	config := baseConfig(t, planned)
	attempt := config.attemptRoot(2, 1)
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

func TestResultMarkerAloneNeverEstablishesCompletion(t *testing.T) {
	planned := epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 1}
	config := baseConfig(t, planned)
	digest := strings.Repeat("ab", 32)
	if err := writeMarker(config.resultMarkerPath(2), resultMarker{
		Version: 1, NetworkID: config.NetworkID, Epoch: 2, Attempt: 1,
		TopologyDigest: digest, CommitteeDigest: digest, CertificateSHA256: digest, ShareSHA256: digest,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Step(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("unbacked result marker was accepted as a completed DKG")
	}
}

func TestAttemptOutputsCannotCollideAcrossRetries(t *testing.T) {
	config := baseConfig(t, epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 1})
	if config.sharePath(2, 1) == config.sharePath(2, 2) {
		t.Fatal("private share output path is shared across retries")
	}
	if config.certificatePath(2, 1) == config.certificatePath(2, 2) {
		t.Fatal("certificate output path is shared across retries")
	}
	if config.discardPath(2, 1) == config.discardPath(2, 2) {
		t.Fatal("discard evidence path is shared across retries")
	}
}

func TestCompletedAttemptScanAllowsDiscardEvidence(t *testing.T) {
	config := baseConfig(t, epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 2})
	if err := os.Mkdir(config.attemptRoot(2, 1), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.discardPath(2, 1), []byte("durable signed discard evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, completed, err := config.recoverCompletedAttempt(2); err != nil {
		t.Fatalf("discard evidence blocked retry-state scan: %v", err)
	} else if completed {
		t.Fatal("failed DKG attempt was confused with a completed attempt")
	}
}

func TestCompletedAttemptScanRejectsMalformedDiscardEvidenceName(t *testing.T) {
	config := baseConfig(t, epoch.Plan{Action: epoch.ActionPrepareNext, Epoch: 2, Attempt: 2})
	path := filepath.Join(config.StateRoot, "epoch-00000000000000000002-attempt-1.discard.json")
	if err := os.WriteFile(path, []byte("malformed evidence name"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := config.recoverCompletedAttempt(2); err == nil {
		t.Fatal("non-canonical discard evidence filename was ignored")
	}
}

func TestResultMarkerDistinguishesCommitteeAndCertificateDigests(t *testing.T) {
	base := resultMarker{
		Version: 1, NetworkID: "nomad-test", Epoch: 2, Attempt: 1,
		TopologyDigest: strings.Repeat("01", 32), CommitteeDigest: strings.Repeat("02", 32),
		CertificateSHA256: strings.Repeat("03", 32), ShareSHA256: strings.Repeat("04", 32),
	}
	other := base
	other.CommitteeDigest = strings.Repeat("05", 32)
	if sameResultMarker(base, other) {
		t.Fatal("committee digest change was confused with certificate file hash")
	}
	other = base
	other.CertificateSHA256 = strings.Repeat("06", 32)
	if sameResultMarker(base, other) {
		t.Fatal("certificate file hash change was ignored")
	}
}

func TestLoadMarkerRejectsNonCanonicalDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	marker := resultMarker{
		Version: 1, NetworkID: "nomad-test", Epoch: 2, Attempt: 1,
		TopologyDigest: strings.Repeat("AA", 32), CommitteeDigest: strings.Repeat("02", 32),
		CertificateSHA256: strings.Repeat("03", 32), ShareSHA256: strings.Repeat("04", 32),
	}
	encoded := []byte(`{"version":1,"network_id":"nomad-test","epoch":2,"attempt":1,"topology_digest":"` + marker.TopologyDigest + `","committee_digest":"` + marker.CommitteeDigest + `","certificate_sha256":"` + marker.CertificateSHA256 + `","share_sha256":"` + marker.ShareSHA256 + `","completed_at":""}`)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMarker(path); err == nil {
		t.Fatal("non-canonical uppercase digest was accepted")
	}
}

func TestLoadMarkerRejectsDuplicateJSONKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadMarker(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate result-marker key was not rejected: %v", err)
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
