package rotation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	dkgnet "github.com/Jtensetti/nomad-testnet/live/dkg"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	StatusIdle            = "IDLE"
	StatusAwaitActivation = "AWAIT_ACTIVATION"
	StatusDKGComplete     = "DKG_COMPLETE"
	StatusAwaitRetry      = "AWAIT_RETRY"
	StatusNotParticipant  = "NOT_PARTICIPANT"
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
	CommitteeDigest   string    `json:"committee_digest,omitempty"`
	CertificateSHA256 string    `json:"certificate_sha256,omitempty"`
	Reason            string    `json:"reason"`
}

type resultMarker struct {
	Version           int    `json:"version"`
	NetworkID         string `json:"network_id"`
	Epoch             uint64 `json:"epoch"`
	Attempt           int    `json:"attempt"`
	TopologyDigest    string `json:"topology_digest"`
	CommitteeDigest   string `json:"committee_digest"`
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
	for _, directory := range []string{config.StateRoot, config.ShareRoot, config.CertRoot} {
		if err := ensureRealDirectory(directory); err != nil {
			return Outcome{}, err
		}
	}

	// Completion is reconstructed from the signed topology, DKG COMPLETE
	// marker, all-operator certificate and private share. The local result JSON
	// is only a cached summary and is never a trust root.
	verifiedCompletion, completed, err := config.recoverCompletedAttempt(planned.Epoch)
	if err != nil {
		return Outcome{}, err
	}
	markerPath := config.resultMarkerPath(planned.Epoch)
	marker, markerErr := loadMarker(markerPath)
	switch {
	case markerErr == nil:
		if !completed {
			return Outcome{}, errors.New("DKG result marker exists without one cryptographically completed attempt")
		}
		if !sameResultMarker(marker, verifiedCompletion) {
			return Outcome{}, errors.New("stored DKG result marker conflicts with verified DKG artifacts")
		}
		return completionOutcome(out, marker, "successor DKG already completed; waiting for the signed epoch descriptor"), nil
	case !errors.Is(markerErr, os.ErrNotExist):
		return Outcome{}, markerErr
	case completed:
		if err := writeMarker(markerPath, verifiedCompletion); err != nil {
			return Outcome{}, err
		}
		return completionOutcome(out, verifiedCompletion, "recovered a durably completed successor DKG after controller restart"), nil
	}

	private, err := topology.LoadPrivateKeys(config.SecretsPath)
	if err != nil {
		return Outcome{}, fmt.Errorf("load local operator identity: %w", err)
	}
	if private.OperatorID != config.OperatorID {
		return Outcome{}, errors.New("configured operator ID does not match local private material")
	}
	// At the public boundary for retry N, discard only private share output
	// left by earlier failed attempts. Journals and public certificates remain
	// untouched as evidence. The discard itself is local and creates no wire
	// event.
	if err := config.discardEarlierFailedShares(planned.Epoch, planned.Attempt, private.Identity, now); err != nil {
		return Outcome{}, err
	}

	attemptRoot := config.attemptRoot(planned.Epoch, planned.Attempt)
	if exists, err := pathExists(attemptRoot); err != nil {
		return Outcome{}, err
	} else if exists {
		out.Status = StatusAwaitRetry
		out.Reason = "this public DKG attempt already started and did not complete; unsafe resume is forbidden"
		return out, nil
	}

	// Every retry is a distinct, authority-signed DKG session. Reusing the
	// topology from attempt 1 after its signed start time would either violate
	// dkg.Run's anti-resume rule or silently turn a retry into the same session.
	topologyPath := config.attemptTopologyPath(planned.Epoch, planned.Attempt)
	network, err := topology.Load(topologyPath, config.Authority, now)
	if err != nil {
		return Outcome{}, fmt.Errorf("load successor topology for attempt %d: %w", planned.Attempt, err)
	}
	if network.Document.NetworkID != config.NetworkID || network.Document.Epoch != planned.Epoch {
		return Outcome{}, errors.New("successor topology does not match planned network and epoch")
	}
	if _, err := network.OperatorByID(config.OperatorID); err != nil {
		out.Status = StatusNotParticipant
		out.Reason = "local operator is not a member of the public successor topology and does not participate in its DKG"
		return out, nil
	}
	secrets, err := topology.LoadSecrets(config.SecretsPath, network)
	if err != nil {
		return Outcome{}, fmt.Errorf("local keys do not match successor membership: %w", err)
	}

	shareOut := config.sharePath(planned.Epoch, planned.Attempt)
	certOut := config.certificatePath(planned.Epoch, planned.Attempt)
	for _, path := range []string{shareOut, certOut} {
		if exists, err := pathExists(path); err != nil {
			return Outcome{}, err
		} else if exists {
			return Outcome{}, fmt.Errorf("attempt output %s exists before its DKG state directory; refusing ambiguous restart", filepath.Base(path))
		}
	}
	// NewStore intentionally requires a pre-existing empty directory. Creating
	// it here is also the durable fact that prevents this same public attempt
	// from being restarted after a crash.
	if err := os.Mkdir(attemptRoot, 0o700); err != nil {
		return Outcome{}, fmt.Errorf("create fresh DKG attempt state: %w", err)
	}
	if err := syncDirectory(config.StateRoot); err != nil {
		return Outcome{}, err
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
	verified, err := config.verifyAttemptCompletion(planned.Epoch, planned.Attempt)
	if err != nil {
		return Outcome{}, fmt.Errorf("verify DKG completion before recording result: %w", err)
	}
	if verified.CommitteeDigest != hex.EncodeToString(result.Verified.Digest[:]) {
		return Outcome{}, errors.New("DKG runner result disagrees with independently reverified certificate")
	}
	if err := writeMarker(markerPath, verified); err != nil {
		return Outcome{}, err
	}
	return completionOutcome(out, verified, "successor DKG completed on the public rotation schedule; waiting for signed descriptor assembly"), nil
}

func completionOutcome(out Outcome, marker resultMarker, reason string) Outcome {
	out.Status = StatusDKGComplete
	out.Attempt = marker.Attempt
	out.CommitteeDigest = marker.CommitteeDigest
	out.CertificateSHA256 = marker.CertificateSHA256
	out.Reason = reason
	return out
}

func sameResultMarker(left, right resultMarker) bool {
	return left.Version == right.Version && left.NetworkID == right.NetworkID && left.Epoch == right.Epoch &&
		left.Attempt == right.Attempt && left.TopologyDigest == right.TopologyDigest && left.CommitteeDigest == right.CommitteeDigest &&
		left.CertificateSHA256 == right.CertificateSHA256 && left.ShareSHA256 == right.ShareSHA256
}

func (config Config) discardEarlierFailedShares(epochNumber uint64, currentAttempt int, identity ed25519.PrivateKey, now time.Time) error {
	for attempt := 1; attempt < currentAttempt; attempt++ {
		root := config.attemptRoot(epochNumber, attempt)
		exists, err := pathExists(root)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if complete, err := pathExists(filepath.Join(root, "COMPLETE")); err != nil {
			return err
		} else if complete {
			return fmt.Errorf("attempt %d is COMPLETE but no epoch result was recovered", attempt)
		}
		share := config.sharePath(epochNumber, attempt)
		statement := config.discardPath(epochNumber, attempt)
		shareExists, err := pathExists(share)
		if err != nil {
			return err
		}
		finalExists, err := regularFileExists(statement)
		if err != nil {
			return err
		}
		pendingExists, err := regularFileExists(statement + ".pending")
		if err != nil {
			return err
		}
		if !shareExists && !finalExists && !pendingExists {
			continue
		}
		topologyBytes, err := readBoundedRegular(config.attemptTopologyPath(epochNumber, attempt), topology.MaximumFileBytes)
		if err != nil {
			return fmt.Errorf("read failed-attempt topology %d: %w", attempt, err)
		}
		network, err := topology.Verify(topologyBytes, config.Authority, time.Time{})
		if err != nil {
			return fmt.Errorf("verify failed-attempt topology %d: %w", attempt, err)
		}
		if network.Document.NetworkID != config.NetworkID || network.Document.Epoch != epochNumber {
			return errors.New("failed-attempt topology belongs to another network or epoch")
		}
		if _, err := topology.VerifySecrets(mustReadSecretFile(config.SecretsPath), network); err != nil {
			return fmt.Errorf("failed-attempt private material does not match its signed topology: %w", err)
		}
		if _, err := DiscardFailedShare(config.NetworkID, epochNumber, attempt, fmt.Sprintf("%x", network.Digest), config.OperatorID, share, statement, identity, now); err != nil {
			return fmt.Errorf("discard failed DKG share for attempt %d: %w", attempt, err)
		}
	}
	return nil
}

func mustReadSecretFile(path string) []byte {
	// The caller already loaded this file through LoadPrivateKeys, including
	// permission and canonical-key checks. This second bounded read exists only
	// to bind the same private material to an older signed attempt topology.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

func (config Config) recoverCompletedAttempt(epochNumber uint64) (resultMarker, bool, error) {
	entries, err := os.ReadDir(config.StateRoot)
	if err != nil {
		return resultMarker{}, false, err
	}
	prefix := fmt.Sprintf("epoch-%020d-attempt-", epochNumber)
	completed := make([]int, 0, 1)
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		suffix := strings.TrimPrefix(entry.Name(), prefix)
		attempt, err := strconv.Atoi(suffix)
		if err != nil || attempt < 1 || attempt > 99 || fmt.Sprintf("%02d", attempt) != suffix {
			return resultMarker{}, false, fmt.Errorf("unexpected DKG attempt state directory %q", entry.Name())
		}
		root := filepath.Join(config.StateRoot, entry.Name())
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return resultMarker{}, false, fmt.Errorf("DKG attempt state %q is not a real directory", entry.Name())
		}
		complete := filepath.Join(root, "COMPLETE")
		completeInfo, err := os.Lstat(complete)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !completeInfo.Mode().IsRegular() {
			return resultMarker{}, false, fmt.Errorf("DKG completion marker for attempt %d is invalid", attempt)
		}
		completed = append(completed, attempt)
	}
	if len(completed) == 0 {
		return resultMarker{}, false, nil
	}
	if len(completed) != 1 {
		return resultMarker{}, false, errors.New("multiple completed DKG attempts exist for one epoch")
	}
	marker, err := config.verifyAttemptCompletion(epochNumber, completed[0])
	return marker, err == nil, err
}

func (config Config) verifyAttemptCompletion(epochNumber uint64, attempt int) (resultMarker, error) {
	topologyBytes, err := readBoundedRegular(config.attemptTopologyPath(epochNumber, attempt), topology.MaximumFileBytes)
	if err != nil {
		return resultMarker{}, err
	}
	network, err := topology.Verify(topologyBytes, config.Authority, time.Time{})
	if err != nil {
		return resultMarker{}, fmt.Errorf("verify attempt topology: %w", err)
	}
	if network.Document.NetworkID != config.NetworkID || network.Document.Epoch != epochNumber {
		return resultMarker{}, errors.New("completed attempt topology belongs to another network or epoch")
	}
	certificateBytes, err := readBoundedRegular(config.certificatePath(epochNumber, attempt), committee.MaximumFileBytes)
	if err != nil {
		return resultMarker{}, err
	}
	_, certified, err := committee.Decode(certificateBytes, network)
	if err != nil {
		return resultMarker{}, fmt.Errorf("verify completed DKG certificate: %w", err)
	}
	if _, err := committee.LoadShare(config.sharePath(epochNumber, attempt), certified, network); err != nil {
		return resultMarker{}, fmt.Errorf("verify completed DKG share: %w", err)
	}
	completePath := filepath.Join(config.attemptRoot(epochNumber, attempt), "COMPLETE")
	complete, err := readBoundedRegular(completePath, 8<<10)
	if err != nil {
		return resultMarker{}, err
	}
	expected := []byte(fmt.Sprintf("network=%s\nepoch=%d\ntopology=%x\ncertificate=%x\n", network.Document.NetworkID, network.Document.Epoch, network.Digest, certified.Digest))
	if !bytes.Equal(complete, expected) {
		return resultMarker{}, errors.New("DKG COMPLETE marker does not match verified topology and certificate")
	}
	certificateDigest, err := digestFile(config.certificatePath(epochNumber, attempt))
	if err != nil {
		return resultMarker{}, err
	}
	shareDigest, err := digestFile(config.sharePath(epochNumber, attempt))
	if err != nil {
		return resultMarker{}, err
	}
	completeInfo, err := os.Lstat(completePath)
	if err != nil {
		return resultMarker{}, err
	}
	return resultMarker{
		Version: 1, NetworkID: config.NetworkID, Epoch: epochNumber, Attempt: attempt,
		TopologyDigest: fmt.Sprintf("%x", network.Digest), CommitteeDigest: hex.EncodeToString(certified.Digest[:]),
		CertificateSHA256: certificateDigest, ShareSHA256: shareDigest,
		CompletedAt: completeInfo.ModTime().UTC().Truncate(time.Second).Format(time.RFC3339),
	}, nil
}

func (config Config) attemptRoot(epochNumber uint64, attempt int) string {
	return filepath.Join(config.StateRoot, fmt.Sprintf("epoch-%020d-attempt-%02d", epochNumber, attempt))
}

func (config Config) attemptTopologyPath(epochNumber uint64, attempt int) string {
	return filepath.Join(config.TopologyDir, fmt.Sprintf("epoch-%020d", epochNumber), fmt.Sprintf("attempt-%02d", attempt), "topology.json")
}

func (config Config) sharePath(epochNumber uint64, attempt int) string {
	return filepath.Join(config.ShareRoot, fmt.Sprintf("epoch-%020d-attempt-%02d.share.json", epochNumber, attempt))
}

func (config Config) certificatePath(epochNumber uint64, attempt int) string {
	return filepath.Join(config.CertRoot, fmt.Sprintf("epoch-%020d-attempt-%02d.certificate.json", epochNumber, attempt))
}

func (config Config) discardPath(epochNumber uint64, attempt int) string {
	return filepath.Join(config.StateRoot, fmt.Sprintf("epoch-%020d-attempt-%02d.discard.json", epochNumber, attempt))
}

func (config Config) resultMarkerPath(epochNumber uint64) string {
	return filepath.Join(config.StateRoot, fmt.Sprintf("epoch-%020d-result.json", epochNumber))
}

func loadMarker(path string) (resultMarker, error) {
	encoded, err := readBoundedRegular(path, 16<<10)
	if err != nil {
		return resultMarker{}, err
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
	for name, digest := range map[string]string{"topology": marker.TopologyDigest, "committee": marker.CommitteeDigest, "certificate": marker.CertificateSHA256, "share": marker.ShareSHA256} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
			return resultMarker{}, fmt.Errorf("invalid %s digest in DKG result marker", name)
		}
	}
	if marker.Version != 1 || marker.NetworkID == "" || marker.Epoch == 0 || marker.Attempt < 1 {
		return resultMarker{}, errors.New("incomplete DKG result marker")
	}
	return marker, nil
}

func writeMarker(path string, marker resultMarker) error {
	encoded, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(path, encoded, 0o600)
}

func digestFile(path string) (string, error) {
	data, err := readBoundedRegular(path, 8<<20)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("artifact must be a non-empty bounded regular file")
	}
	return os.ReadFile(path)
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

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
