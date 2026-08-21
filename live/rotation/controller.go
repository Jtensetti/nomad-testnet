package rotation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	dkgnet "github.com/Jtensetti/nomad-testnet/live/dkg"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	StatusIdle            = "IDLE"
	StatusAwaitActivation = "AWAIT_ACTIVATION"
	StatusDKGComplete     = "DKG_COMPLETE"
	StatusAwaitRetry      = "AWAIT_RETRY"
	StatusRetire          = "RETIRE_REQUIRED"
	StatusEscalate        = "ESCALATION_REQUIRED"
	StatusHalted          = "HALTED"
)

// Planner is deliberately tiny: controller decisions depend only on the
// public lifecycle state machine, never on private publication or reader state.
type Planner interface {
	PlanAtForOperator(time.Time, epoch.Policy, string) (epoch.Plan, error)
}

// RunDKG is injected in tests. Production uses dkgnet.Run directly.
type RunDKG func(context.Context, topology.Verified, topology.VerifiedSecrets, dkgnet.RunConfig) (dkgnet.RunResult, error)

type Config struct {
	Planner     Planner
	Policy      epoch.Policy
	OperatorID  string
	Authority   ed25519.PublicKey
	NetworkID   string
	TopologyDir string
	SecretsPath string
	Listen      string
	StateRoot   string
	ShareRoot   string
	CertRoot    string
	TLSCert     string
	TLSKey      string
	RunDKG      RunDKG
}

type Outcome struct {
	Status            string    `json:"status"`
	Action            string    `json:"action"`
	Epoch             uint64    `json:"epoch"`
	Attempt           int       `json:"attempt,omitempty"`
	DueAt             time.Time `json:"due_at,omitempty"`
	CertificateDigest string    `json:"certificate_digest,omitempty"`
	Reason            string    `json:"reason"`
}

type resultMarker struct {
	Version           int    `json:"version"`
	NetworkID         string `json:"network_id"`
	Epoch             uint64 `json:"epoch"`
	Attempt           int    `json:"attempt"`
	TopologyDigest    string `json:"topology_digest"`
	CertificateSHA256 string `json:"certificate_sha256"`
	ShareSHA256       string `json:"share_sha256"`
	CompletedAt       string `json:"completed_at"`
}

// Step performs at most one public lifecycle action. It never derives work
// from publication, reader, cache or queue state. A DKG run is started only
// when PlanAtForOperator says PREPARE_NEXT on the public schedule.
func (config Config) Step(ctx context.Context, now time.Time) (Outcome, error) {
	if ctx == nil || config.Planner == nil || config.OperatorID == "" || config.NetworkID == "" ||
		config.TopologyDir == "" || config.SecretsPath == "" || config.Listen == "" ||
		config.StateRoot == "" || config.ShareRoot == "" || config.CertRoot == "" {
		return Outcome{}, errors.New("complete rotation controller configuration is required")
	}
	if len(config.Authority) != ed25519.PublicKeySize {
		return Outcome{}, errors.New("authority key is required")
	}
	planned, err := config.Planner.PlanAtForOperator(now.UTC(), config.Policy, config.OperatorID)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Action: planned.Action.String(), Epoch: planned.Epoch, Attempt: planned.Attempt, DueAt: planned.DueAt, Reason: planned.Reason}
	switch planned.Action {
	case epoch.ActionIdle:
		out.Status = StatusIdle
		return out, nil
	case epoch.ActionAwaitActivation:
		out.Status = StatusAwaitActivation
		return out, nil
	case epoch.ActionRetire:
		out.Status = StatusRetire
		return out, nil
	case epoch.ActionEscalate:
		out.Status = StatusEscalate
		return out, nil
	case epoch.ActionHalted:
		out.Status = StatusHalted
		return out, nil
	case epoch.ActionPrepareNext:
		return config.prepare(ctx, now.UTC(), planned, out)
	default:
		return Outcome{}, fmt.Errorf("unsupported lifecycle action %s", planned.Action.String())
	}
}

func (config Config) prepare(ctx context.Context, now time.Time, planned epoch.Plan, out Outcome) (Outcome, error) {
	markerPath := filepath.Join(config.StateRoot, fmt.Sprintf("epoch-%020d-result.json", planned.Epoch))
	if marker, err := loadMarker(markerPath); err == nil {
		if marker.NetworkID != config.NetworkID || marker.Epoch != planned.Epoch {
			return Outcome{}, errors.New("stored DKG result marker belongs to another network or epoch")
		}
		if err := config.verifyMarkerFiles(marker); err != nil {
			return Outcome{}, err
		}
		out.Status = StatusDKGComplete
		out.CertificateDigest = marker.CertificateSHA256
		out.Reason = "successor DKG already completed; waiting for the signed epoch descriptor"
		return out, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Outcome{}, err
	}

	attemptRoot := filepath.Join(config.StateRoot, fmt.Sprintf("epoch-%020d-attempt-%02d", planned.Epoch, planned.Attempt))
	if _, err := os.Lstat(attemptRoot); err == nil {
		out.Status = StatusAwaitRetry
		out.Reason = "this public DKG attempt already started and did not complete; unsafe resume is forbidden"
		return out, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Outcome{}, err
	}

	// Every retry is a distinct, authority-signed DKG session. Reusing the
	// topology from attempt 1 after its signed start time would either violate
	// dkg.Run's anti-resume rule or silently turn a retry into the same session.
	topologyPath := filepath.Join(config.TopologyDir, fmt.Sprintf("epoch-%020d", planned.Epoch), fmt.Sprintf("attempt-%02d", planned.Attempt), "topology.json")
	network, err := topology.Load(topologyPath, config.Authority, now)
	if err != nil {
		return Outcome{}, fmt.Errorf("load successor topology for attempt %d: %w", planned.Attempt, err)
	}
	if network.Document.NetworkID != config.NetworkID || network.Document.Epoch != planned.Epoch {
		return Outcome{}, errors.New("successor topology does not match planned network and epoch")
	}
	secrets, err := topology.LoadSecrets(config.SecretsPath, network)
	if err != nil {
		return Outcome{}, fmt.Errorf("load successor operator secrets: %w", err)
	}
	if secrets.Operator.ID != config.OperatorID {
		return Outcome{}, errors.New("successor topology does not contain the configured local operator identity")
	}

	if err := ensureRealDirectory(config.StateRoot); err != nil {
		return Outcome{}, err
	}
	if err := ensureRealDirectory(config.ShareRoot); err != nil {
		return Outcome{}, err
	}
	if err := ensureRealDirectory(config.CertRoot); err != nil {
		return Outcome{}, err
	}
	shareOut := filepath.Join(config.ShareRoot, fmt.Sprintf("epoch-%020d.share.json", planned.Epoch))
	certOut := filepath.Join(config.CertRoot, fmt.Sprintf("epoch-%020d.certificate.json", planned.Epoch))
	if exists(shareOut) || exists(certOut) {
		return Outcome{}, errors.New("successor DKG outputs exist without a durable result marker; refusing ambiguous restart")
	}

	runner := config.RunDKG
	if runner == nil {
		runner = dkgnet.Run
	}
	result, err := runner(ctx, network, secrets, dkgnet.RunConfig{
		Listen: config.Listen, StateDirectory: attemptRoot, ShareOutput: shareOut,
		CertificateOutput: certOut, TLSCertificate: config.TLSCert, TLSPrivateKey: config.TLSKey,
	})
	if err != nil {
		return Outcome{}, err
	}
	certificateDigest, err := digestFile(certOut)
	if err != nil {
		return Outcome{}, err
	}
	shareDigest, err := digestFile(shareOut)
	if err != nil {
		return Outcome{}, err
	}
	completedAt := time.Now().UTC()
	marker := resultMarker{
		Version: 1, NetworkID: config.NetworkID, Epoch: planned.Epoch, Attempt: planned.Attempt,
		TopologyDigest: fmt.Sprintf("%x", network.Digest), CertificateSHA256: certificateDigest,
		ShareSHA256: shareDigest, CompletedAt: completedAt.Format(time.RFC3339),
	}
	if err := writeMarker(markerPath, marker); err != nil {
		return Outcome{}, err
	}
	out.Status = StatusDKGComplete
	out.CertificateDigest = fmt.Sprintf("%x", result.Verified.Digest)
	out.Reason = "successor DKG completed on the public rotation schedule; waiting for signed descriptor assembly"
	return out, nil
}

func (config Config) verifyMarkerFiles(marker resultMarker) error {
	certificate := filepath.Join(config.CertRoot, fmt.Sprintf("epoch-%020d.certificate.json", marker.Epoch))
	share := filepath.Join(config.ShareRoot, fmt.Sprintf("epoch-%020d.share.json", marker.Epoch))
	certDigest, err := digestFile(certificate)
	if err != nil {
		return fmt.Errorf("verify completed certificate: %w", err)
	}
	shareDigest, err := digestFile(share)
	if err != nil {
		return fmt.Errorf("verify completed share: %w", err)
	}
	if certDigest != marker.CertificateSHA256 || shareDigest != marker.ShareSHA256 {
		return errors.New("completed DKG output digest does not match durable result marker")
	}
	return nil
}

func loadMarker(path string) (resultMarker, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return resultMarker{}, err
	}
	if len(encoded) == 0 || len(encoded) > 16<<10 {
		return resultMarker{}, errors.New("invalid DKG result marker size")
	}
	var marker resultMarker
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return resultMarker{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return resultMarker{}, errors.New("trailing DKG result marker data")
	}
	if marker.Version != 1 || marker.NetworkID == "" || marker.Epoch == 0 || marker.Attempt < 1 || marker.CertificateSHA256 == "" || marker.ShareSHA256 == "" {
		return resultMarker{}, errors.New("incomplete DKG result marker")
	}
	return marker, nil
}

func writeMarker(path string, marker resultMarker) error {
	encoded, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if err := ensureRealDirectory(parent); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func digestFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 8<<20 {
		return "", errors.New("DKG output must be a non-empty bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

func ensureRealDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("rotation controller state path must be a real directory")
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
