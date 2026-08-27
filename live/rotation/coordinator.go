package rotation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/epoch"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	StatusAwaitCertificate = "AWAIT_CERTIFICATE"
	StatusCollecting       = "COLLECTING_SIGNATURES"
	StatusReady            = "READY"
	StatusMissedActivation = "MISSED_ACTIVATION"
)

// CoordinatorConfig joins the public DKG result to the descriptor chain. The
// embedded Controller config is the exact rotation path that produced (or, for
// an outgoing non-participant, observed) the public successor attempt.
type CoordinatorConfig struct {
	Controller     Config
	ChainRoot      string
	RevocationRoot string
	ExchangeRoot   string
	JournalRoot    string
}

type Coordinator struct {
	config   CoordinatorConfig
	exchange *Exchange
}

type CoordinationOutcome struct {
	Status           string `json:"status"`
	Epoch            uint64 `json:"epoch"`
	Attempt          int    `json:"attempt,omitempty"`
	DescriptorDigest string `json:"descriptor_digest,omitempty"`
	Approvals        int    `json:"approvals"`
	ApprovalQuorum   int    `json:"approval_quorum"`
	Activations      int    `json:"activations"`
	ActivationTotal  int    `json:"activation_total"`
	Reason           string `json:"reason"`
}

func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	controller := config.Controller
	if controller.OperatorID == "" || controller.NetworkID == "" || len(controller.Authority) != ed25519.PublicKeySize ||
		controller.TopologyDir == "" || controller.SecretsRoot == "" || controller.StateRoot == "" || controller.CertRoot == "" ||
		config.ChainRoot == "" || config.RevocationRoot == "" || config.ExchangeRoot == "" || config.JournalRoot == "" {
		return nil, errors.New("complete epoch coordinator configuration is required")
	}
	if err := controller.validateSecretsRoot(); err != nil {
		return nil, err
	}
	for _, directory := range []string{config.ExchangeRoot, config.JournalRoot} {
		if err := ensureRealDirectory(directory); err != nil {
			return nil, err
		}
	}
	exchange, err := OpenExchange(config.ExchangeRoot)
	if err != nil {
		return nil, err
	}
	return &Coordinator{config: config, exchange: exchange}, nil
}

func (coordinator *Coordinator) Handler() http.Handler {
	return coordinator.exchange.Handler()
}

// Advance performs one bounded public control-plane round. Every remote
// artifact is requested at most once in this call. A missing or invalid peer
// response waits for the next aligned controller tick; it never triggers an
// immediate retry, faster schedule, alternate peer or fallback network.
func (coordinator *Coordinator) Advance(ctx context.Context, now time.Time, targetEpoch uint64, attempt int) (CoordinationOutcome, error) {
	if coordinator == nil || ctx == nil || now.IsZero() || targetEpoch == 0 || attempt < 1 || attempt > 99 {
		return CoordinationOutcome{}, errors.New("complete epoch coordination round is required")
	}
	roundStarted := time.Now()
	previous, revoked, chain, err := coordinator.context(targetEpoch)
	if err != nil {
		return CoordinationOutcome{}, err
	}
	if tip, exists := chain.Tip(); exists && tip.Epoch >= targetEpoch {
		return CoordinationOutcome{
			Status: StatusReady, Epoch: tip.Epoch, DescriptorDigest: hex.EncodeToString(tip.Digest[:]),
			Reason: "successor descriptor is already imported and follows its signed public lifecycle",
		}, nil
	}
	if previous == nil || previous.Epoch+1 != targetEpoch {
		return CoordinationOutcome{}, errors.New("epoch coordinator target is not the direct successor of the verified chain tip")
	}
	remaining := previous.RetireAt.Sub(now)
	if remaining <= 0 {
		return CoordinationOutcome{
			Status: StatusMissedActivation, Epoch: targetEpoch, Attempt: attempt,
			Reason: "the signed scheduled activation boundary passed before a successor was READY; late catch-up import is forbidden",
		}, nil
	}
	roundContext, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	candidate, err := coordinator.candidateTopology(targetEpoch, attempt)
	if err != nil {
		return CoordinationOutcome{}, err
	}
	if err := coordinator.validateLocalControlTransport(*previous, candidate.network); err != nil {
		return CoordinationOutcome{}, err
	}
	certifiedCandidate, err := coordinator.obtainCertificate(roundContext, targetEpoch, candidate)
	if err != nil {
		return CoordinationOutcome{}, err
	}
	if certifiedCandidate == nil {
		outcome := CoordinationOutcome{
			Status: StatusAwaitCertificate, Epoch: targetEpoch, Attempt: attempt,
			Reason: "no all-operator-certified successor DKG result was available in this public control round",
		}
		if time.Since(roundStarted) >= remaining {
			outcome.Status = StatusMissedActivation
			outcome.Reason = "the signed scheduled activation boundary passed while waiting for a certificate; late catch-up is forbidden"
		}
		return outcome, nil
	}
	candidate = *certifiedCandidate

	draft, verifiedDraft, encodedDraft, err := buildScheduledDraft(*previous, candidate.network, candidate.topologyBytes, candidate.certificateBytes, coordinator.config.Controller.Authority, revoked)
	if err != nil {
		return CoordinationOutcome{}, err
	}
	if time.Since(roundStarted) >= remaining {
		return CoordinationOutcome{
			Status: StatusMissedActivation, Epoch: targetEpoch, Attempt: attempt,
			DescriptorDigest: hex.EncodeToString(verifiedDraft.Digest[:]),
			Reason:           "the signed scheduled activation boundary passed before local signing; late catch-up is forbidden",
		}, nil
	}
	if err := coordinator.exchange.Publish(targetEpoch, artifactDraft, "", encodedDraft); err != nil {
		return CoordinationOutcome{}, err
	}
	if time.Since(roundStarted) >= remaining {
		return CoordinationOutcome{
			Status: StatusMissedActivation, Epoch: targetEpoch, Attempt: attempt,
			DescriptorDigest: hex.EncodeToString(verifiedDraft.Digest[:]),
			Reason:           "the signed scheduled activation boundary passed before local signing; late catch-up is forbidden",
		}, nil
	}
	localArtifacts, err := coordinator.publishLocalArtifacts(draft, verifiedDraft, previous, revoked)
	if err != nil {
		return CoordinationOutcome{}, err
	}

	artifacts, approvals, activations := coordinator.collectArtifacts(roundContext, draft, verifiedDraft, *previous, revoked, candidate.network, localArtifacts)
	outcome := CoordinationOutcome{
		Status: StatusCollecting, Epoch: targetEpoch, Attempt: candidate.attempt,
		DescriptorDigest: hex.EncodeToString(verifiedDraft.Digest[:]),
		Approvals:        approvals, ApprovalQuorum: epoch.ApprovalQuorum(*previous),
		Activations: activations, ActivationTotal: len(candidate.network.Document.Operators),
		Reason: "waiting for the remaining independently signed public epoch artifacts",
	}
	if approvals < outcome.ApprovalQuorum || activations != outcome.ActivationTotal {
		if time.Since(roundStarted) >= remaining {
			outcome.Status = StatusMissedActivation
			outcome.Reason = "the signed scheduled activation boundary passed before a successor was READY; late catch-up import is forbidden"
		}
		return outcome, nil
	}
	encoded, verified, err := epoch.Assemble(draft, artifacts, coordinator.config.Controller.Authority, previous, revoked)
	if err != nil {
		return CoordinationOutcome{}, fmt.Errorf("assemble successor descriptor: %w", err)
	}
	if time.Since(roundStarted) >= remaining {
		outcome.Status = StatusMissedActivation
		outcome.Reason = "the signed scheduled activation boundary passed before import; late catch-up activation is forbidden"
		return outcome, nil
	}
	if err := coordinator.exchange.Publish(targetEpoch, artifactDescriptor, "", encoded); err != nil {
		return CoordinationOutcome{}, err
	}
	imported, err := chain.Append(encoded)
	if err != nil {
		return CoordinationOutcome{}, fmt.Errorf("import assembled successor descriptor: %w", err)
	}
	if imported.Digest != verified.Digest {
		return CoordinationOutcome{}, errors.New("imported successor digest disagrees with assembled descriptor")
	}
	outcome.Status = StatusReady
	outcome.DescriptorDigest = hex.EncodeToString(imported.Digest[:])
	outcome.Reason = "all public artifacts verified; successor imported in READY state until its signed activation boundary"
	return outcome, nil
}

func (coordinator *Coordinator) context(targetEpoch uint64) (*epoch.Verified, epoch.RevocationSet, *epoch.Chain, error) {
	controller := coordinator.config.Controller
	historical, err := epoch.OpenChain(coordinator.config.ChainRoot, controller.NetworkID, controller.Authority, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if historical.Halted() {
		return nil, nil, nil, epoch.ErrHalted
	}
	revocations, err := epoch.OpenRevocationStore(coordinator.config.RevocationRoot)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := revocations.Revalidate(historical); err != nil {
		return nil, nil, nil, fmt.Errorf("revalidate persisted revocations: %w", err)
	}
	revoked, err := revocations.ScopedSet(targetEpoch)
	if err != nil {
		return nil, nil, nil, err
	}
	chain, err := epoch.OpenChain(coordinator.config.ChainRoot, controller.NetworkID, controller.Authority, revoked)
	if err != nil {
		return nil, nil, nil, err
	}
	previous, exists := chain.Tip()
	if !exists {
		return nil, nil, nil, errors.New("automatic epoch coordination requires an imported predecessor")
	}
	if err := topology.ValidateEpochControlEndpoints(previous.Topology); err != nil {
		return nil, nil, nil, fmt.Errorf("predecessor lifecycle endpoints: %w", err)
	}
	return &previous, revoked, chain, nil
}

type certificateCandidate struct {
	attempt          int
	network          topology.Verified
	topologyBytes    []byte
	certificateBytes []byte
}

func (coordinator *Coordinator) validateLocalControlTransport(previous epoch.Verified, incoming topology.Verified) error {
	operator, err := incoming.OperatorByID(coordinator.config.Controller.OperatorID)
	if err != nil {
		operator, err = previous.Topology.OperatorByID(coordinator.config.Controller.OperatorID)
		if err != nil {
			return errors.New("local operator belongs to neither side of the public epoch transition")
		}
	}
	endpoint, err := url.Parse(operator.DKGEndpoint)
	if err != nil {
		return errors.New("local signed DKG endpoint is invalid")
	}
	expectsTLS := endpoint.Scheme == "https"
	configuredTLS := coordinator.config.Controller.TLSCert != "" && coordinator.config.Controller.TLSKey != ""
	if expectsTLS != configuredTLS {
		return errors.New("lifecycle control TLS mode does not match the local signed DKG endpoint")
	}
	return nil
}

func (coordinator *Coordinator) obtainCertificate(ctx context.Context, targetEpoch uint64, candidate certificateCandidate) (*certificateCandidate, error) {
	controller := coordinator.config.Controller

	// A participating operator first re-verifies the exact artifacts its DKG
	// wrote. Publishing is idempotent, so restart recovers without inventing a
	// new certificate or changing the public network schedule.
	marker, completed, err := controller.recoverCompletedAttempt(targetEpoch)
	if err != nil {
		return nil, err
	}
	if completed {
		if marker.Attempt != candidate.attempt {
			return nil, errors.New("completed DKG attempt disagrees with the public controller attempt")
		}
		encoded, err := readBoundedRegular(controller.certificatePath(targetEpoch, marker.Attempt), committee.MaximumFileBytes)
		if err != nil {
			return nil, err
		}
		_, certified, err := committee.Decode(encoded, candidate.network)
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(certified.Digest[:]) != marker.CommitteeDigest {
			return nil, errors.New("completed DKG marker conflicts with reverified certificate")
		}
		candidate.certificateBytes = encoded
		if err := coordinator.exchange.Publish(targetEpoch, artifactCertificate, "", encoded); err != nil {
			return nil, err
		}
		return &candidate, nil
	}

	type fetched struct {
		bytes []byte
	}
	requests := len(candidate.network.Document.Operators)
	results := make(chan fetched, requests)
	for _, operator := range candidate.network.Document.Operators {
		operator := operator
		go func() {
			encoded, err := coordinator.exchange.Fetch(ctx, operator, targetEpoch, artifactCertificate, "")
			if err != nil {
				results <- fetched{}
				return
			}
			if _, _, err := committee.Decode(encoded, candidate.network); err != nil {
				results <- fetched{}
				return
			}
			results <- fetched{bytes: encoded}
		}()
	}
	valid := make(map[string]certificateCandidate)
	for range requests {
		result := <-results
		if len(result.bytes) == 0 {
			continue
		}
		_, certified, err := committee.Decode(result.bytes, candidate.network)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%x:%x", candidate.network.Digest, certified.Digest)
		if existing, exists := valid[key]; exists && !bytes.Equal(existing.certificateBytes, result.bytes) {
			return nil, errors.New("two encodings claim one certified successor committee")
		}
		candidate.certificateBytes = result.bytes
		valid[key] = candidate
	}
	if len(valid) == 0 {
		return nil, nil
	}
	if len(valid) != 1 {
		return nil, errors.New("multiple distinct all-operator-certified successor attempts were observed")
	}
	for _, candidate := range valid {
		return &candidate, nil
	}
	return nil, nil
}

func (coordinator *Coordinator) candidateTopology(targetEpoch uint64, attempt int) (certificateCandidate, error) {
	controller := coordinator.config.Controller
	path := controller.attemptTopologyPath(targetEpoch, attempt)
	encoded, err := readBoundedRegular(path, topology.MaximumFileBytes)
	if err != nil {
		return certificateCandidate{}, err
	}
	network, err := topology.Verify(encoded, controller.Authority, time.Time{})
	if err != nil {
		return certificateCandidate{}, fmt.Errorf("verify successor attempt %d topology: %w", attempt, err)
	}
	if network.Document.NetworkID != controller.NetworkID || network.Document.Epoch != targetEpoch {
		return certificateCandidate{}, errors.New("successor attempt topology belongs to another network or epoch")
	}
	if err := topology.ValidateEpochControlEndpoints(network); err != nil {
		return certificateCandidate{}, fmt.Errorf("successor attempt %d lifecycle endpoints: %w", attempt, err)
	}
	if err := controller.validateRetryLadder(targetEpoch, attempt, network); err != nil {
		return certificateCandidate{}, err
	}
	return certificateCandidate{attempt: attempt, network: network, topologyBytes: encoded}, nil
}

func buildScheduledDraft(previous epoch.Verified, network topology.Verified, topologyBytes, certificateBytes []byte, authority ed25519.PublicKey, revoked epoch.RevocationSet) (epoch.Descriptor, epoch.Verified, []byte, error) {
	descriptor, err := epoch.New(
		&previous, epoch.TransitionScheduled,
		previous.RetireAt.UTC().Format(time.RFC3339), network.Document.NotAfter,
		topologyBytes, certificateBytes,
	)
	if err != nil {
		return epoch.Descriptor{}, epoch.Verified{}, nil, err
	}
	verified, err := epoch.ValidateUnsignedDraft(descriptor, authority, &previous, revoked)
	if err != nil {
		return epoch.Descriptor{}, epoch.Verified{}, nil, err
	}
	encoded, err := epoch.Encode(descriptor)
	if err != nil {
		return epoch.Descriptor{}, epoch.Verified{}, nil, err
	}
	return descriptor, verified, encoded, nil
}

func (coordinator *Coordinator) publishLocalArtifacts(draft epoch.Descriptor, verified epoch.Verified, previous *epoch.Verified, revoked epoch.RevocationSet) (map[string]epoch.SignatureArtifact, error) {
	controller := coordinator.config.Controller
	journal, err := epoch.OpenJournal(filepath.Join(coordinator.config.JournalRoot, fmt.Sprintf("epoch-%020d", verified.Epoch)))
	if err != nil {
		return nil, err
	}
	local := make(map[string]epoch.SignatureArtifact, 2)
	if _, err := previous.Topology.OperatorByID(controller.OperatorID); err == nil {
		secretPath, pathErr := controller.epochSecretsPath(previous.Epoch)
		if pathErr != nil {
			return nil, pathErr
		}
		secrets, loadErr := topology.LoadSecrets(secretPath, previous.Topology)
		if loadErr != nil {
			return nil, fmt.Errorf("load predecessor epoch keys for approval: %w", loadErr)
		}
		if secrets.Operator.ID != controller.OperatorID {
			return nil, errors.New("coordinator operator ID does not match predecessor private material")
		}
		artifact, err := journal.CreateApprovalArtifact(draft, controller.Authority, previous, revoked, controller.OperatorID, secrets.Identity)
		if err != nil {
			return nil, err
		}
		if err := coordinator.publishArtifact(artifact); err != nil {
			return nil, err
		}
		local[artifact.Role+":"+artifact.OperatorID] = artifact
	}
	if _, err := verified.Topology.OperatorByID(controller.OperatorID); err == nil {
		secretPath, pathErr := controller.epochSecretsPath(verified.Epoch)
		if pathErr != nil {
			return nil, pathErr
		}
		secrets, loadErr := topology.LoadSecrets(secretPath, verified.Topology)
		if loadErr != nil {
			return nil, fmt.Errorf("load incoming epoch keys for activation: %w", loadErr)
		}
		if secrets.Operator.ID != controller.OperatorID {
			return nil, errors.New("coordinator operator ID does not match incoming private material")
		}
		artifact, err := journal.CreateActivationArtifact(draft, controller.Authority, previous, revoked, controller.OperatorID, secrets.Identity)
		if err != nil {
			return nil, err
		}
		if err := coordinator.publishArtifact(artifact); err != nil {
			return nil, err
		}
		local[artifact.Role+":"+artifact.OperatorID] = artifact
	}
	if len(local) == 0 {
		return nil, errors.New("local operator belongs to neither side of the public epoch transition")
	}
	return local, nil
}

func (coordinator *Coordinator) publishArtifact(artifact epoch.SignatureArtifact) error {
	encoded, err := epoch.EncodeSignatureArtifact(artifact)
	if err != nil {
		return err
	}
	return coordinator.exchange.Publish(artifact.Epoch, artifact.Role, artifact.OperatorID, encoded)
}

type artifactRequest struct {
	role     string
	operator topology.Operator
}

func (coordinator *Coordinator) collectArtifacts(ctx context.Context, draft epoch.Descriptor, verified epoch.Verified, previous epoch.Verified, revoked epoch.RevocationSet, incoming topology.Verified, local map[string]epoch.SignatureArtifact) ([]epoch.SignatureArtifact, int, int) {
	requests := make([]artifactRequest, 0, len(previous.Topology.Document.Operators)+len(incoming.Document.Operators))
	incomingByID := make(map[string]topology.Operator, len(incoming.Document.Operators))
	for _, operator := range incoming.Document.Operators {
		incomingByID[operator.ID] = operator
	}
	for _, operator := range previous.Topology.Document.Operators {
		if _, isRevoked := revoked[operator.IdentityKey]; isRevoked {
			continue
		}
		endpointOperator := operator
		if successor, exists := incomingByID[operator.ID]; exists {
			endpointOperator = successor
		}
		requests = append(requests, artifactRequest{role: artifactApproval, operator: endpointOperator})
	}
	for _, operator := range incoming.Document.Operators {
		requests = append(requests, artifactRequest{role: artifactActivation, operator: operator})
	}

	type fetched struct {
		artifact epoch.SignatureArtifact
		valid    bool
	}
	results := make(chan fetched, len(requests))
	for _, request := range requests {
		request := request
		key := request.role + ":" + request.operator.ID
		if artifact, exists := local[key]; exists {
			results <- fetched{artifact: artifact, valid: true}
			continue
		}
		go func() {
			encoded, err := coordinator.exchange.Fetch(ctx, request.operator, verified.Epoch, request.role, request.operator.ID)
			if err != nil {
				results <- fetched{}
				return
			}
			artifact, err := epoch.DecodeSignatureArtifact(encoded)
			if err != nil || artifact.Role != request.role || artifact.OperatorID != request.operator.ID ||
				epoch.VerifySignatureArtifact(draft, artifact, coordinator.config.Controller.Authority, &previous, revoked) != nil {
				results <- fetched{}
				return
			}
			results <- fetched{artifact: artifact, valid: true}
		}()
	}

	byKey := make(map[string]epoch.SignatureArtifact, len(requests))
	for range requests {
		result := <-results
		if !result.valid {
			continue
		}
		key := result.artifact.Role + ":" + result.artifact.OperatorID
		byKey[key] = result.artifact
	}
	artifacts := make([]epoch.SignatureArtifact, 0, len(byKey))
	approvals, activations := 0, 0
	for _, artifact := range byKey {
		artifacts = append(artifacts, artifact)
		if artifact.Role == artifactApproval {
			approvals++
		} else if artifact.Role == artifactActivation {
			activations++
		}
	}
	sort.Slice(artifacts, func(i, j int) bool {
		if artifacts[i].Role != artifacts[j].Role {
			return artifacts[i].Role < artifacts[j].Role
		}
		return artifacts[i].Index < artifacts[j].Index
	})
	return artifacts, approvals, activations
}
