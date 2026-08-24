package epoch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Jtensetti/nomad-testnet/live/committee"
	"github.com/Jtensetti/nomad-testnet/live/strictjson"
	"github.com/Jtensetti/nomad-testnet/live/topology"
)

const (
	Version          = "nomad-epoch-descriptor-v1"
	MaximumFileBytes = 1 << 20

	digestDomain     = "nomad-epoch-descriptor-digest-v1"
	activationDomain = "nomad-epoch-activation-v1"
	approvalDomain   = "nomad-epoch-approval-v1"

	TransitionGenesis   = "genesis"
	TransitionScheduled = "scheduled"
	TransitionEmergency = "emergency"
)

// Descriptor is the storage/transport form of one epoch's activation object.
// The embedded signed topology and DKG certificate are carried as base64 of
// their exact bytes so that no JSON re-encoding can disturb the digests they
// already carry or the digest computed here.
type Descriptor struct {
	Version             string       `json:"version"`
	PreviousEpochDigest string       `json:"previous_epoch_digest"`
	Transition          string       `json:"transition"`
	ActivateAt          string       `json:"activate_at"`
	RetireAt            string       `json:"retire_at"`
	Topology            string       `json:"topology"`
	DKGCertificate      string       `json:"dkg_certificate"`
	UplinkProfile       string       `json:"uplink_profile"`
	Approvals           []Approval   `json:"approvals"`
	Activations         []Activation `json:"activations"`
}

// Approval is a cross-epoch approval by one previous-epoch operator.
type Approval struct {
	OperatorID string `json:"operator_id"`
	Index      uint32 `json:"index"`
	Signature  string `json:"signature"`
}

// Activation is an activation signature by one of the epoch's own operators.
type Activation struct {
	OperatorID string `json:"operator_id"`
	Index      uint32 `json:"index"`
	Signature  string `json:"signature"`
}

// Verified is a fully validated descriptor plus its derived public state.
type Verified struct {
	Descriptor  Descriptor
	Digest      [32]byte
	Topology    topology.Verified
	Certificate committee.Verified
	Epoch       uint64
	NetworkID   string
	ActivateAt  time.Time
	RetireAt    time.Time
}

// RevocationSet lists revoked operator identity keys (base64 Ed25519 public
// keys, exactly as they appear in topology documents).
type RevocationSet map[string]struct{}

var zeroDigestHex = hex.EncodeToString(make([]byte, 32))

// New assembles an unsigned descriptor. topologyBytes and certificateBytes
// must be the exact encoded signed topology and DKG certificate.
func New(previous *Verified, transition, activateAt, retireAt string, topologyBytes, certificateBytes []byte) (Descriptor, error) {
	previousDigest := zeroDigestHex
	if previous != nil {
		previousDigest = hex.EncodeToString(previous.Digest[:])
	}
	descriptor := Descriptor{
		Version:             Version,
		PreviousEpochDigest: previousDigest,
		Transition:          transition,
		ActivateAt:          activateAt,
		RetireAt:            retireAt,
		Topology:            base64.StdEncoding.EncodeToString(topologyBytes),
		DKGCertificate:      base64.StdEncoding.EncodeToString(certificateBytes),
	}
	if _, err := Digest(descriptor); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

// Digest computes the canonical descriptor digest. Approvals and activations
// are excluded so independently produced signatures bind identical bytes.
func Digest(descriptor Descriptor) ([32]byte, error) {
	canonical, err := CanonicalBytes(descriptor)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(digestDomain))
	_, _ = h.Write(canonical)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func activationMessage(digest [32]byte) []byte {
	message := make([]byte, 0, len(activationDomain)+32)
	message = append(message, activationDomain...)
	message = append(message, digest[:]...)
	return message
}

// approvalMessage binds the approving operator's own identity key in
// addition to the transition it approves. Without that binding every
// approver signs identical bytes, so one signature is verbatim reusable in
// every quorum slot and a single operator can mint a whole quorum.
func approvalMessage(previousDigest, digest [32]byte, approver ed25519.PublicKey) []byte {
	message := make([]byte, 0, len(approvalDomain)+64+ed25519.PublicKeySize)
	message = append(message, approvalDomain...)
	message = append(message, previousDigest[:]...)
	message = append(message, digest[:]...)
	message = append(message, approver...)
	return message
}

// signActivation is the primitive Ed25519 operation. Production callers use
// Journal.CreateActivationArtifact so authority, chain, membership,
// revocation and anti-equivocation checks happen before this function runs.
func signActivation(descriptor Descriptor, operator topology.Operator, identity ed25519.PrivateKey) (Activation, error) {
	if err := requireMatchingIdentity(operator, identity); err != nil {
		return Activation{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Activation{}, err
	}
	signature := ed25519.Sign(identity, activationMessage(digest))
	return Activation{OperatorID: operator.ID, Index: uint32(operator.Index), Signature: base64.StdEncoding.EncodeToString(signature)}, nil
}

// signApproval is the corresponding internal primitive for an outgoing
// committee approval. It is intentionally not exported.
func signApproval(descriptor Descriptor, previous Verified, operator topology.Operator, identity ed25519.PrivateKey) (Approval, error) {
	if err := requireMatchingIdentity(operator, identity); err != nil {
		return Approval{}, err
	}
	digest, err := Digest(descriptor)
	if err != nil {
		return Approval{}, err
	}
	signature := ed25519.Sign(identity, approvalMessage(previous.Digest, digest, identity.Public().(ed25519.PublicKey)))
	return Approval{OperatorID: operator.ID, Index: uint32(operator.Index), Signature: base64.StdEncoding.EncodeToString(signature)}, nil
}

func requireMatchingIdentity(operator topology.Operator, identity ed25519.PrivateKey) error {
	if len(identity) != ed25519.PrivateKeySize {
		return errors.New("operator identity private key is required")
	}
	configured, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
	if err != nil || !bytes.Equal(configured, identity.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("identity private key does not match operator %s", operator.ID)
	}
	return nil
}

// ApprovalQuorum is the number of distinct previous-epoch operator approvals
// a non-genesis descriptor requires.
func ApprovalQuorum(previous Verified) int {
	members := len(previous.Topology.Document.Operators)
	majority := members/2 + 1
	threshold := int(previous.Topology.Document.DKG.Threshold)
	if threshold > majority {
		return threshold
	}
	return majority
}

func Encode(descriptor Descriptor) ([]byte, error) {
	if _, err := Digest(descriptor); err != nil {
		return nil, err
	}
	return json.MarshalIndent(descriptor, "", "  ")
}

// Verify validates one descriptor completely. previous must be nil exactly
// for a genesis descriptor. revoked may be nil.
func Verify(encoded []byte, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet) (Verified, error) {
	if len(encoded) == 0 || len(encoded) > MaximumFileBytes {
		return Verified{}, errors.New("epoch descriptor is empty or too large")
	}
	if err := strictjson.RejectDuplicateKeys(encoded); err != nil {
		return Verified{}, fmt.Errorf("epoch descriptor is ambiguous: %w", err)
	}
	var descriptor Descriptor
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&descriptor); err != nil {
		return Verified{}, fmt.Errorf("decode epoch descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verified{}, errors.New("trailing epoch descriptor data")
	}
	verified, err := ValidateDraft(descriptor, authority, previous, revoked)
	if err != nil {
		return Verified{}, err
	}
	if err := verifyApprovals(descriptor, verified.Digest, previous, revoked); err != nil {
		return Verified{}, err
	}
	if err := verifyActivations(descriptor, verified.Digest, verified.Topology); err != nil {
		return Verified{}, err
	}
	return verified, nil
}

// ValidateDraft verifies every signed public input, lifecycle boundary and
// chain rule that defines a descriptor digest, but deliberately does not
// require the approval or activation signature sets to be complete. Operator
// tooling must call this before signing a draft; final admission still calls
// Verify, which requires the complete sets.
func ValidateDraft(descriptor Descriptor, authority ed25519.PublicKey, previous *Verified, revoked RevocationSet) (Verified, error) {
	digest, err := Digest(descriptor)
	if err != nil {
		return Verified{}, err
	}
	if len(descriptor.UplinkProfile) != 0 {
		return Verified{}, errors.New("uplink profile versions are not yet specified; field must be empty")
	}

	topologyBytes, _ := decodeBounded(descriptor.Topology)
	network, err := topology.Verify(topologyBytes, authority, time.Time{})
	if err != nil {
		return Verified{}, fmt.Errorf("embedded topology: %w", err)
	}
	certificateBytes, _ := decodeBounded(descriptor.DKGCertificate)
	_, certified, err := committee.Decode(certificateBytes, network)
	if err != nil {
		return Verified{}, fmt.Errorf("embedded DKG certificate: %w", err)
	}

	activateAt, _ := time.Parse(time.RFC3339, descriptor.ActivateAt)
	retireAt, _ := time.Parse(time.RFC3339, descriptor.RetireAt)
	notBefore, _ := time.Parse(time.RFC3339, network.Document.NotBefore)
	notAfter, _ := time.Parse(time.RFC3339, network.Document.NotAfter)
	dkgStart, _ := time.Parse(time.RFC3339, network.Document.DKG.StartAt)
	dkgEnd := dkgStart.Add(4 * time.Duration(network.Document.DKG.PhaseDurationMillis) * time.Millisecond)
	if !activateAt.Before(retireAt) {
		return Verified{}, errors.New("activation boundary must precede retirement boundary")
	}
	if activateAt.Before(dkgEnd) {
		return Verified{}, errors.New("epoch cannot activate before its DKG schedule completes")
	}
	if activateAt.Before(notBefore) || retireAt.After(notAfter) {
		return Verified{}, errors.New("active window must sit inside the topology validity envelope")
	}

	for _, operator := range network.Document.Operators {
		if revokedIdentity(revoked, operator.IdentityKey) {
			return Verified{}, fmt.Errorf("operator %s uses a revoked identity", operator.ID)
		}
	}

	if err := verifyChainLink(descriptor, network, previous, activateAt); err != nil {
		return Verified{}, err
	}

	return Verified{
		Descriptor: descriptor, Digest: digest, Topology: network, Certificate: certified,
		Epoch: network.Document.Epoch, NetworkID: network.Document.NetworkID,
		ActivateAt: activateAt, RetireAt: retireAt,
	}, nil
}

func verifyChainLink(descriptor Descriptor, network topology.Verified, previous *Verified, activateAt time.Time) error {
	if descriptor.Transition == TransitionGenesis {
		if previous != nil {
			return errors.New("genesis descriptor cannot follow an existing epoch")
		}
		if descriptor.PreviousEpochDigest != zeroDigestHex {
			return errors.New("genesis descriptor must carry the zero previous digest")
		}
		if len(descriptor.Approvals) != 0 {
			return errors.New("genesis descriptor cannot carry approvals")
		}
		return nil
	}
	if previous == nil {
		return errors.New("non-genesis descriptor requires the previous verified epoch")
	}
	if descriptor.PreviousEpochDigest != hex.EncodeToString(previous.Digest[:]) {
		return errors.New("descriptor does not chain to the previous epoch digest")
	}
	if network.Document.NetworkID != previous.NetworkID {
		return errors.New("descriptor changes network identity across epochs")
	}
	if network.Document.Epoch != previous.Epoch+1 {
		return errors.New("epoch numbers must increase by exactly one")
	}
	switch descriptor.Transition {
	case TransitionScheduled:
		if !activateAt.Equal(previous.RetireAt) {
			return errors.New("scheduled transition must activate exactly at the previous retirement boundary")
		}
	case TransitionEmergency:
		if !activateAt.Before(previous.RetireAt) {
			return errors.New("emergency transition must activate before the previous retirement boundary")
		}
		if !activateAt.After(previous.ActivateAt) {
			return errors.New("emergency transition must activate after the previous activation boundary")
		}
	default:
		// A transition kind accepted by the canonical encoder but not
		// constrained here would otherwise get no window rules at all.
		return errors.New("unsupported transition kind for a chained epoch")
	}
	return nil
}

func verifyApprovals(descriptor Descriptor, digest [32]byte, previous *Verified, revoked RevocationSet) error {
	return verifyApprovalSet(descriptor, digest, previous, revoked, true)
}

func verifyApprovalSet(descriptor Descriptor, digest [32]byte, previous *Verified, revoked RevocationSet, requireQuorum bool) error {
	if descriptor.Transition == TransitionGenesis {
		return nil
	}
	if previous == nil {
		return errors.New("non-genesis approval set requires the previous verified epoch")
	}
	quorum := ApprovalQuorum(*previous)
	if requireQuorum && len(descriptor.Approvals) < quorum {
		return fmt.Errorf("transition requires at least %d previous-epoch approvals", quorum)
	}
	members := len(previous.Topology.Document.Operators)
	// Deduplication keys on the resolved operator, never on the wire value:
	// an index that is out of range, or that aliases another index under any
	// narrowing conversion, must not be able to occupy two quorum slots.
	seen := make(map[string]struct{}, len(descriptor.Approvals))
	for _, approval := range descriptor.Approvals {
		if approval.Index >= uint32(members) {
			return errors.New("approval index is outside previous-epoch membership")
		}
		operator, err := previous.Topology.Operator(uint16(approval.Index))
		if err != nil || operator.ID != approval.OperatorID {
			return errors.New("approval does not match previous-epoch membership")
		}
		if _, exists := seen[operator.ID]; exists {
			return errors.New("duplicate transition approval")
		}
		seen[operator.ID] = struct{}{}
		if revokedIdentity(revoked, operator.IdentityKey) {
			return fmt.Errorf("approval from revoked operator %s", operator.ID)
		}
		public, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid previous-epoch operator identity")
		}
		signature, err := decodeBase64(approval.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(public), approvalMessage(previous.Digest, digest, public), signature) {
			return fmt.Errorf("invalid transition approval from %s", approval.OperatorID)
		}
	}
	if requireQuorum && len(seen) < quorum {
		return fmt.Errorf("transition requires at least %d distinct previous-epoch approvals", quorum)
	}
	return nil
}

func verifyActivations(descriptor Descriptor, digest [32]byte, network topology.Verified) error {
	return verifyActivationSet(descriptor, digest, network, true)
}

func verifyActivationSet(descriptor Descriptor, digest [32]byte, network topology.Verified, requireAll bool) error {
	members := len(network.Document.Operators)
	if requireAll && len(descriptor.Activations) != members {
		return errors.New("epoch activation requires one signature from every configured operator")
	}
	message := activationMessage(digest)
	seen := make(map[string]struct{}, len(descriptor.Activations))
	for _, activation := range descriptor.Activations {
		if activation.Index >= uint32(members) {
			return errors.New("activation index is outside epoch membership")
		}
		operator, err := network.Operator(uint16(activation.Index))
		if err != nil || activation.OperatorID != operator.ID {
			return errors.New("activation signature does not match epoch membership")
		}
		if _, exists := seen[operator.ID]; exists {
			return errors.New("duplicate epoch activation")
		}
		seen[operator.ID] = struct{}{}
		public, err := decodeBase64(operator.IdentityKey, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("invalid operator identity key")
		}
		signature, err := decodeBase64(activation.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(public), message, signature) {
			return fmt.Errorf("invalid epoch activation from %s", activation.OperatorID)
		}
	}
	if requireAll && len(seen) != members {
		return errors.New("epoch activation requires one signature from every configured operator")
	}
	return nil
}

func revokedIdentity(revoked RevocationSet, identityKey string) bool {
	if revoked == nil {
		return false
	}
	_, exists := revoked[identityKey]
	return exists
}

// State is one epoch's lifecycle position relative to a clock.
type State int

const (
	StateReady State = iota
	StateActive
	StateRetired
)

func (s State) String() string {
	switch s {
	case StateReady:
		return "READY"
	case StateActive:
		return "ACTIVE"
	case StateRetired:
		return "RETIRED"
	default:
		return "UNKNOWN"
	}
}

// stateAtIgnoringSuccessors reports this descriptor's own window position.
// It is deliberately unexported: it cannot see an emergency successor that
// has already retired this epoch, so a caller using it to decide whether to
// serve an epoch could serve two committees at once. Chain.StateOf and
// Chain.ActiveAt are the only correct ways to ask.
func (v Verified) stateAtIgnoringSuccessors(now time.Time) State {
	if now.Before(v.ActivateAt) {
		return StateReady
	}
	if now.Before(v.RetireAt) {
		return StateActive
	}
	return StateRetired
}

func validateCanonicalTime(encoded string) error {
	parsed, err := time.Parse(time.RFC3339, encoded)
	if err != nil {
		return errors.New("invalid RFC3339 time")
	}
	if parsed.UTC().Format(time.RFC3339) != encoded {
		return errors.New("time is not in canonical UTC RFC3339 form")
	}
	return nil
}

func decodeBounded(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if err := validCanonicalLength(len(decoded)); err != nil {
		return nil, err
	}
	return decoded, nil
}

func decodeBase64(encoded string, size int) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid base64 or length")
	}
	return decoded, nil
}

func decodeHex(encoded string, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || encoded != hex.EncodeToString(decoded) {
		return nil, errors.New("invalid canonical hex or length")
	}
	return decoded, nil
}
